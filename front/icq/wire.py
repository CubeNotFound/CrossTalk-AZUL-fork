import struct

from .crypt import add_v5_server_checkcode, decrypt_v4, decrypt_v5, v3_header_checkcode
from .packets import Command, Version


class Header:
	# what every version's client packet header comes down to (the fields a version doesn't have stay 0)
	__slots__ = ('version', 'command', 'seq1', 'seq2', 'uin', 'session_id')

	version: int
	command: int
	seq1: int
	seq2: int
	uin: int
	session_id: int

	def __init__(self, version: int, command: int, seq1: int, seq2: int, uin: int, session_id: int = 0) -> None:
		self.version = version
		self.command = command
		self.seq1 = seq1
		self.seq2 = seq2
		self.uin = uin
		self.session_id = session_id

	def __repr__(self) -> str:
		return '<V{} cmd 0x{:04X} seq {}/{} uin {}>'.format(self.version, self.command, self.seq1, self.seq2, self.uin)

def version_of(packet: bytes) -> int | None:
	if len(packet) < 2:
		return None
	return struct.unpack_from('<H', packet)[0]

def parse(packet: bytes) -> tuple[Header, bytes] | None:
	# client packet -> (header, data); None for anything too short to be one
	version = version_of(packet)
	if version == Version.V5:
		# u16 version, u32 zero, u32 UIN, then (encrypted) u32 session ID, u16 command, u16 seq1, u16 seq2, u32 checkcode
		if len(packet) < 24:
			return None
		plain = decrypt_v5(packet)
		uin, session_id, command, seq1, seq2 = struct.unpack_from('<LLHHH', plain, 6)
		return Header(version, command, seq1, seq2, uin, session_id), plain[24:]
	if version == Version.V4:
		# u16 version, u16 random, then (a quarter of it encrypted) u16 zero, u16 command, u16 seq1, u16 seq2, u32 UIN,
		# u32 checkcode
		if len(packet) < 20:
			return None
		plain = decrypt_v4(packet)
		command, seq1, seq2, uin = struct.unpack_from('<HHHL', plain, 6)
		return Header(version, command, seq1, seq2, uin), plain[20:]
	if version == Version.V3:
		# u16 version, u16 command, u16 seq1, u16 seq2, u32 UIN, u32 checkcode
		if len(packet) < 16:
			return None
		command, seq1, seq2, uin = struct.unpack_from('<HHHL', packet, 2)
		return Header(version, command, seq1, seq2, uin), packet[16:]
	if version in (Version.V1, Version.V2):
		# u16 version, u16 command, u16 seq, u32 UIN; the commands sent before there's a UIN to put in it leave it out
		if len(packet) < 6:
			return None
		command, seq = struct.unpack_from('<HH', packet, 2)
		if command in (Command.FirstLogin, Command.RegNewUser):
			return Header(version, command, seq, 0, 0), packet[6:]
		if command == Command.GetDeps and version == Version.V2:
			# a V2 client sends its pre-login check with a V3 layout: u16 seq1, u16 seq2, u32 UIN
			if len(packet) < 12:
				return None
			seq1, seq2, uin = struct.unpack_from('<HHL', packet, 4)
			return Header(version, command, seq1, seq2, uin), packet[12:]
		if len(packet) < 10:
			return Header(version, command, seq, 0, 0), packet[6:]
		uin = struct.unpack_from('<L', packet, 6)[0]
		return Header(version, command, seq, 0, uin), packet[10:]
	return None

def build(version: int, command: int, data: bytes = b'', *, seq1: int = 0, seq2: int = 0, uin: int = 0, session_id: int = 0) -> bytes:
	# server packet for a client of `version`
	if version == Version.V5:
		# u16 version, u8 zero, u32 session ID, u16 command, u16 seq1, u16 seq2, u32 UIN, u32 checkcode; not encrypted
		packet = bytearray(struct.pack('<HBLHHHL', Version.V5, 0, session_id, command, seq1 & 0xFFFF, seq2 & 0xFFFF, uin) + bytes(4) + data)
		add_v5_server_checkcode(packet)
		return bytes(packet)
	if version in (Version.V3, Version.V4):
		# V3 and V4 clients both get the V3 header (u16 version 3, u16 command, u16 seq1, u16 seq2, u32 UIN, u32), and a
		# V4 client a checkcode in its last field
		header = struct.pack('<HHHHL', Version.V3, command, seq1 & 0xFFFF, seq2 & 0xFFFF, uin)
		check = v3_header_checkcode(header) if version == Version.V4 else 0
		return header + struct.pack('<L', check) + data
	# V1 and V2: u16 version, u16 command, u16 seq
	return struct.pack('<HHH', version, command, seq1 & 0xFFFF) + data
