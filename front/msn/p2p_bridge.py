from typing import Any, Dict, List, Optional
import struct

from .misc import encode_payload

# Largest P2P payload official clients put in one switchboard `MSG` (which is capped at 1664 bytes)
SB_P2P_DATA_SIZE = 1202

# The most a switchboard `MSG` payload (MIME headers and P2P packet) may be; clients enforce it on what they send, so what
# the server sends them stays under it too
SB_MSG_MAX = 1664

SDG_DATA = '''Routing: 1.0
To: 1:{to_email}
From: 1:{from_email}
Options: 0
Service-Channel: PE

Reliability: 1.0

Messaging: 2.0
Message-Type: Data
Content-Type: application/x-msnmsgrp2p
Content-Transfer-Encoding: binary
Content-Length: {cl}
Pipe: {pipe}
Bridging-Offsets: {offsets}

'''


SLP_DIRECT_CONTENT_TYPES = frozenset({
	'application/x-msnmsgr-transreqbody', 'application/x-msnmsgr-transrespbody',
	'application/x-msnmsgr-transdestaddrupdate', 'application/x-msnmsgr-transudpswitch',
})
SLP_TRANSREQ = 'application/x-msnmsgr-transreqbody'
SLP_TRANSRESP = 'application/x-msnmsgr-transrespbody'


SLP_BRIDGES = 'TCPv1 SBBridge'
SLP_NULL_NONCE = '{00000000-0000-0000-0000-000000000000}'

_SLP_SESSION_HEADERS = ('SessionID', 'SChannelState', 'Capabilities-Flags')

_SLP_PAD_HEADER = 'X-Padding'

def split_sdg_p2p(body: bytes, offsets: str) -> List[bytes]:
	starts = [int(offset) for offset in offsets.split(',') if offset.strip()] or [0]
	ends = starts[1:] + [len(body)]
	return [body[start:end] for start, end in zip(starts, ends) if end > start]

def detect_p2p_version(packet: bytes) -> Optional[bool]:
	v1 = len(packet) >= 52 and len(packet) == 48 + struct.unpack('<I', packet[24:28])[0] + 4
	v2 = False
	if len(packet) >= 8:
		(hl, _, payload_size) = struct.unpack('>BBH', packet[:4])
		v2 = hl >= 8 and hl % 4 == 0 and len(packet) in (hl + payload_size + 4, hl + payload_size)
	if v1 == v2: return None
	return v2

def get_p2p_state(front_data: Dict[str, Any], sender_uuid: str, receiver_uuid: str) -> Dict[str, Any]:
	return front_data.setdefault('msn_p2p', {}).setdefault((sender_uuid, receiver_uuid), { 'shift': 0, 'acks': {}, 'pipe': 1 })

def build_sdg_data(to_email: str, from_email: str, packets: List[bytes], pipe: int) -> bytes:
	offsets = [] # type: List[str]
	body = b''
	for packet in packets:
		offsets.append(str(len(body)))
		body += packet
	return encode_payload(SDG_DATA,
		to_email = to_email, from_email = from_email, cl = len(body), pipe = pipe, offsets = ','.join(offsets),
	) + body

def build_sb_p2p_headers(dest: str, src: Optional[str]) -> bytes:
	headers = 'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: {}\r\n'.format(dest)
	if src is not None:
		headers += 'P2P-Src: {}\r\n'.format(src)
	return (headers + '\r\n').encode('utf-8')

def sb_p2p_data_size(headers: bytes, p2pv2: bool) -> int:
	if p2pv2:
		overhead = 24 + 20 + 4
	else:
		overhead = 48 + 4
	return max(256, SB_MSG_MAX - len(headers) - overhead)

def chunk_p2p(packet: bytes, p2pv2: bool, state: Dict[str, Any], max_data: int = SB_P2P_DATA_SIZE) -> List[bytes]:
	if p2pv2:
		return _chunk_p2pv2(packet, state, max_data)
	return _chunk_p2pv1(packet, min(max_data, SB_P2P_DATA_SIZE))

def translate_p2pv2_ack(packet: bytes, state: Dict[str, Any]) -> bytes:
	if len(packet) < 8: return packet
	hl = packet[0]
	tlvs = bytearray(packet[8:hl])
	i = 0
	while i + 2 <= len(tlvs) and tlvs[i]:
		t, l = tlvs[i], tlvs[i + 1]
		if t in (0x02, 0x03) and l == 4:
			value = struct.unpack('>I', tlvs[i + 2:i + 6])[0]
			tlvs[i + 2:i + 6] = struct.pack('>I', state['acks'].get(value, value))
		i += 2 + l
	return packet[:8] + bytes(tlvs) + packet[hl:]

def _chunk_p2pv1(packet: bytes, max_data: int = SB_P2P_DATA_SIZE) -> List[bytes]:
	data = packet[48:-4]
	if len(data) <= max_data:
		return [packet]
	(session_id, identifier, offset, total_size, _, flags, ack_session_id, ack_unique_id, ack_data_size) = struct.unpack('<IIQQIIIIQ', packet[:48])
	return [
		struct.pack(
			'<IIQQIIIIQ', session_id, identifier, offset + i, total_size, len(data[i:i + max_data]),
			flags, ack_session_id, ack_unique_id, ack_data_size,
		) + data[i:i + max_data] + packet[-4:]
		for i in range(0, len(data), max_data)
	]

def _chunk_p2pv2(packet: bytes, state: Dict[str, Any], max_data: int = SB_P2P_DATA_SIZE) -> List[bytes]:
	(hl, op, payload_size, identifier) = struct.unpack('>BBHI', packet[:8])
	payload = packet[hl:hl + payload_size]
	footer = packet[hl + payload_size:]
	next_identifier = (identifier + payload_size) & 0xFFFFFFFF
	shift = state['shift']

	if payload_size == 0 or payload_size - payload[0] <= max_data:
		if shift:
			state['acks'][(next_identifier + shift) & 0xFFFFFFFF] = next_identifier
			packet = packet[:4] + struct.pack('>I', (identifier + shift) & 0xFFFFFFFF) + packet[8:]
		return [packet]

	(dhl, tf, package_number, session_id) = struct.unpack('>BBHI', payload[:8])
	data = payload[dhl:]
	data_remaining = _get_data_remaining(payload[8:dhl])
	chunks = []
	chunk_identifier = identifier + shift
	for i in range(0, len(data), max_data):
		chunk_data = data[i:i + max_data]
		first = (i == 0)
		last = (i + len(chunk_data) >= len(data))
		left = data_remaining + len(data) - i - len(chunk_data)
		data_tlvs = (struct.pack('>BBQ', 0x01, 8, left) + b'\x00\x00' if left else b'')
		chunk_payload = struct.pack('>BBHI', 8 + len(data_tlvs), (tf if first else tf & ~0x01), package_number, session_id) + data_tlvs + chunk_data
		tlvs = (packet[8:hl] if first else b'')
		chunk_op = (op & 0x01 if first else 0) | (op & 0x02 if last else 0)
		chunks.append(struct.pack('>BBHI', 8 + len(tlvs), chunk_op, len(chunk_payload), chunk_identifier & 0xFFFFFFFF) + tlvs + chunk_payload + footer)
		chunk_identifier += len(chunk_payload)
	state['shift'] = chunk_identifier - (identifier + payload_size)
	state['acks'][chunk_identifier & 0xFFFFFFFF] = next_identifier
	return chunks

def _get_data_remaining(tlvs: bytes) -> int:
	i = 0
	while i + 2 <= len(tlvs) and tlvs[i]:
		t, l = tlvs[i], tlvs[i + 1]
		if t == 0x01 and l == 8:
			return struct.unpack('>Q', tlvs[i + 2:i + 10])[0]
		i += 2 + l
	return 0

class SLPMessage:
	__slots__ = ('start_line', 'headers', 'body')

	start_line: str
	headers: list[tuple[str, str]]
	body: bytes

	def __init__(self, start_line: str, headers: list[tuple[str, str]], body: bytes) -> None:
		self.start_line = start_line
		self.headers = headers
		self.body = body

	def get(self, name: str) -> str | None:
		for key, value in self.headers:
			if key.lower() == name.lower(): return value
		return None

	@property
	def content_type(self) -> str:
		return (self.get('Content-Type') or '').split(';', 1)[0].strip().lower()

	@property
	def is_request(self) -> bool:
		return not self.start_line.startswith('MSNSLP/')

	@property
	def method(self) -> str:
		return self.start_line.split(' ', 1)[0]

	def body_values(self) -> list[tuple[str, str]]:
		return _parse_slp_lines(self.body.rstrip(b'\x00').decode('utf-8', 'replace'))

def parse_slp(data: bytes) -> SLPMessage | None:
	if not (data.startswith(b'MSNSLP/') or data[:12].split(b' ', 1)[0] in _SLP_METHODS):
		return None
	try:
		end = data.index(b'\r\n\r\n')
		head = data[:end].decode('utf-8')
	except (ValueError, UnicodeDecodeError):
		return None
	lines = head.split('\r\n')
	headers = []
	for line in lines[1:]:
		if ':' not in line: continue
		key, value = line.split(':', 1)
		headers.append((key.strip(), value.strip()))
	slp = SLPMessage(lines[0], headers, b'')
	try:
		length = int(slp.get('Content-Length') or '0')
	except ValueError:
		return None
	slp.body = data[end + 4:end + 4 + length]
	return slp

def is_direct_connection_slp(data: bytes) -> bool:
	slp = parse_slp(data)
	return slp is not None and slp.content_type in SLP_DIRECT_CONTENT_TYPES

def rewrite_direct_slp(data: bytes, *, preserve_length: bool) -> bytes | None:
	slp = parse_slp(data)
	if slp is None or slp.content_type not in SLP_DIRECT_CONTENT_TYPES:
		return None
	values = slp.body_values()
	content_type = slp.content_type
	if content_type == SLP_TRANSREQ:
		nonce = _nonce_line(values, keep = True)
		required = [('Bridges', SLP_BRIDGES), ('NetID', '0'), ('Conn-Type', 'Firewall'), ('TCP-Conn-Type', 'Firewall'), ('UPnPNat', 'false'), ('ICF', 'true')] + nonce
		optional = [(key, value) for key, value in values if key in _SLP_SESSION_HEADERS or key == 'Nat-Trav-Msg-Type']
	elif content_type == SLP_TRANSRESP:
		required = [('Bridge', 'SBBridge'), ('Listening', 'false')] + _nonce_line(values, keep = False)
		optional = [(key, value) for key, value in values if key in _SLP_SESSION_HEADERS]
	else:
		required = []
		optional = [(key, value) for key, value in values if key == 'Nat-Trav-Msg-Type']

	body_old = slp.body
	terminator = (b'\x00' if body_old.endswith(b'\x00') else b'')
	body = _build_slp_body(required, optional, (len(body_old) - len(terminator)) if preserve_length else None)
	if body is None:
		return None
	body += terminator

	head_old = data[:data.index(b'\r\n\r\n') + 4]
	if preserve_length:
		head = head_old
	else:
		head = _replace_content_length(head_old, len(body) + (0 if terminator else 1))
	return head + body + data[len(head_old) + len(body_old):]

def refuse_direct_invite(data: bytes) -> bytes | None:
	slp = parse_slp(data)
	if slp is None or not slp.is_request or slp.method != 'INVITE' or slp.content_type != SLP_TRANSREQ:
		return None
	values = slp.body_values()
	body_values = [('Bridge', 'SBBridge'), ('Listening', 'false')] + _nonce_line(values, keep = False) + [
		(key, value) for key, value in values if key in _SLP_SESSION_HEADERS
	]
	body = ''.join('{}: {}\r\n'.format(key, value) for key, value in body_values) + '\r\n'
	headers = [
		('To', slp.get('From') or ''), ('From', slp.get('To') or ''), ('Via', slp.get('Via') or ''),
		('CSeq', '{} '.format(_next_cseq(slp.get('CSeq')))), ('Call-ID', slp.get('Call-ID') or ''), ('Max-Forwards', '0'),
		('Content-Type', SLP_TRANSRESP), ('Content-Length', str(len(body.encode('utf-8')) + 1)),
	]
	return ('MSNSLP/1.0 200 OK\r\n' + ''.join('{}: {}\r\n'.format(key, value) for key, value in headers) + '\r\n' + body).encode('utf-8')

def slp_direct_negotiation_kind(data: bytes) -> str | None:
	slp = parse_slp(data)
	if slp is None or slp.content_type not in SLP_DIRECT_CONTENT_TYPES: return None
	return slp.content_type

def neutralize_direct_p2p(packet: bytes, p2pv2: bool) -> bytes:
	try:
		if p2pv2:
			if len(packet) < 8: return packet
			(hl, _, payload_size, _) = struct.unpack('>BBHI', packet[:8])
			if payload_size == 0 or len(packet) < hl + payload_size: return packet
			payload = packet[hl:hl + payload_size]
			(dhl, tf, _, session_id) = struct.unpack('>BBHI', payload[:8])
			if session_id != 0 or not tf & 0x01 or _get_data_remaining(payload[8:dhl]): return packet
			start = hl + dhl
			end = hl + payload_size
		else:
			if len(packet) < 52: return packet
			(session_id, _, offset, total_size, size, flags) = struct.unpack('<IIQQII', packet[:32])
			if session_id != 0 or offset != 0 or size != total_size or flags not in (0x00, 0x01000000): return packet
			start = 48
			end = 48 + size
			if end > len(packet) - 4: return packet
		rewritten = rewrite_direct_slp(packet[start:end], preserve_length = True)
	except (struct.error, IndexError):
		return packet
	if rewritten is None or len(rewritten) != end - start:
		return packet
	return packet[:start] + rewritten + packet[end:]

def _nonce_line(values: list[tuple[str, str]], *, keep: bool) -> list[tuple[str, str]]:
	for key, value in values:
		if key in ('Hashed-Nonce', 'Nonce'):
			return [(key, value if keep else SLP_NULL_NONCE)]
	return ([] if keep else [('Nonce', SLP_NULL_NONCE)])

def _build_slp_body(required: list[tuple[str, str]], optional: list[tuple[str, str]], length: int | None) -> bytes | None:
	def encode(lines: list[tuple[str, str]], pad: int = 0) -> bytes:
		text = ''.join('{}: {}\r\n'.format(key, value) for key, value in lines)
		if pad:
			text += '{}: {}\r\n'.format(_SLP_PAD_HEADER, '0' * (pad - len(_SLP_PAD_HEADER) - 4))
		return (text + '\r\n').encode('utf-8')

	if length is None:
		return encode(required + optional)
	min_pad = len(_SLP_PAD_HEADER) + 4
	for count in range(len(optional), -1, -1):
		body = encode(required + optional[:count])
		rest = length - len(body)
		if rest == 0:
			return body
		if rest >= min_pad:
			return encode(required + optional[:count], rest)
	return None

def _replace_content_length(head: bytes, length: int) -> bytes:
	lines = head.split(b'\r\n')
	for i, line in enumerate(lines):
		if line.lower().startswith(b'content-length:'):
			lines[i] = b'Content-Length: ' + str(length).encode('ascii')
	return b'\r\n'.join(lines)

def _next_cseq(cseq: str | None) -> int:
	try:
		return int((cseq or '0').strip()) + 1
	except ValueError:
		return 1

def _parse_slp_lines(text: str) -> list[tuple[str, str]]:
	values = []
	for line in text.split('\r\n'):
		if ':' not in line: continue
		key, value = line.split(':', 1)
		values.append((key.strip(), value.strip()))
	return values

_SLP_METHODS = frozenset({ b'INVITE', b'ACK', b'BYE', b'CANCEL' })

def sb_p2p_is_v2(dest: Optional[str]) -> bool:
	return dest is not None and ';' in dest

def neutralize_sdg_data(body: bytes, offsets: str, p2pv2: bool) -> bytes:
	starts = [int(offset) for offset in offsets.split(',') if offset.strip()] or [0]
	ends = starts[1:] + [len(body)]
	out = body[:starts[0]]
	for start, end in zip(starts, ends):
		out += neutralize_direct_p2p(body[start:end], p2pv2)
	return out

def slp_reply_signal(data: bytes) -> bytes | None:
	return refuse_direct_invite(data)

def sb_p2p_messages(packet: bytes, dest: str, src: Optional[str], p2pv2: bool, state: Dict[str, Any]) -> List[bytes]:
	headers = build_sb_p2p_headers(dest, src)
	return [headers + chunk for chunk in chunk_p2p(packet, p2pv2, state, sb_p2p_data_size(headers, p2pv2))]
