import asyncio
import ipaddress
import os
import time, struct
import re
from html import escape, unescape

from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple

from util.icq import from_latin1, latin1
from util.misc import Logger, gen_uuid
from core import error
from core.models import MessageData, MessageType, OIM, User, _is_blocking

from ..proto import names
from ..proto.buffer import Buffer
from ..proto.delivery import oscar_sessions
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import find_tlv, unmarshal_tlvs, marshal_tlvs, TLV
from ..proto.userinfo import build_userinfo, pick_session


class ICBMChannel(IntEnum):
	AOLIM	   = 0x0001
	Rendezvous  = 0x0002
	Mime		= 0x0003
	ICQ		 = 0x0004
	CoBrowser   = 0x0005

class ICBMEvent(IntEnum):
	Finished = 0x0000
	Typed	= 0x0001
	Typing   = 0x0002
	Closed   = 0x000F

class ICBMTag(IntEnum):
	ImData = 0x0002
	RequestHostAck = 0x0003
	AutoResponse = 0x0004
	Data = 0x0005
	Store = 0x0006
	WantEvents = 0x000B
	SendTime = 0x0016

class ICBMCharset(IntEnum):
	Ascii = 0x0000
	Unicode = 0x0002
	Latin1 = 0x0003

class ICQMessageType(IntEnum):
	Plain = 0x01
	Chat = 0x02
	File = 0x03
	Url = 0x04
	AuthRequest = 0x06
	AuthDeny = 0x07
	AuthGrant = 0x08
	Server = 0x09
	Added = 0x0C
	WebPager = 0x0D
	EmailExpress = 0x0E
	Contacts = 0x13
	Plugin = 0x1A

class ICBMError(IntEnum):
	RateToHost = 0x0002
	NotLoggedOn = 0x0004
	NotSupportedByHost = 0x0008
	NotSupportedByClient = 0x0009
	RequestDenied = 0x000D
	InLocalPermitDeny = 0x0010

UNICODE_CAPABILITY = bytes.fromhex('0946134E4C7F11D18222444553540000')

from core.abuse import (
	EVIL_DELTA, EVIL_DELTA_ANONYMOUS, EVIL_DECAY, EVIL_DECAY_INTERVAL, EVIL_MAX, CONVERSATION_WINDOW,
)


@Foodgroup(0x0004)
class ICBMFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def add_paramenters(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ICBM__ADD_PARAMENTERS (not implemented)')
		self.logger.info('[Client]', message.data.hex())

	@Subgroup(0x0004)
	def parameter_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ICBM__PARAMENTER_QUERY')

		response_msg = SNACMessage(0x0004, 0x0005, 0x0000, message.request_id)

		# Response from NINA's servers:
		# ==
		# 0000   2a 02 00 0a 00 1a 00 04 00 05 00 00 00 00 00 04   *...............
		#		[FLAP Header....] [SNAC Header................]
		# 0010   00 05 00 00 00 03 02 00 03 84 03 e7 00 00 03 e8   ................
		#
		# The response data are not TLVs and are instead WORD/DWORDs so I cannot fit
		# the names below the hex data.  See https://ninawiki.preloading.dev/wiki/Protocols/OSCAR/SNAC/ICBM_PARAMETER_REPLY and
		# https://ninawiki.preloading.dev/wiki/Protocols/OSCAR/SNAC/ICBM_ADD_PARAMETERS for more information.
		response_msg.write_u16(100)	   # maxSlots
		response_msg.write_u32(0x00003)   # icbmFlags (default)
		response_msg.write_u16(512)	   # maxIncomingICBMLen
		response_msg.write_u16(999)	   # maxSourceEvil
		response_msg.write_u16(999)	   # maxDestinationEvil
		response_msg.write_u32(0)		 # minInterICBMInterval

		self.logger.info('[Server] ICBM__PARAMENTER_REPLY')
		client.send_snac(response_msg)

	@Subgroup(0x0006)
	def channel_msg_tohost(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		cookie = message.read_bytes(8)
		channel = message.read_u16()
		receiver = message.read_bytes(message.read_u8()).decode('latin-1')
		tlvs = unmarshal_tlvs(message.data)

		self.logger.info('[Client] ICBM__CHANNEL_MSG_TOHOST')
		self.logger.info('[Client] Cookie:', cookie)
		self.logger.info('[Client] Channel:', hex(channel))
		self.logger.info('[Client] Message receiver:', receiver)

		for tlv in tlvs:
			self.logger.info('[Client] TLV', hex(tlv.type), '-', tlv.data)

		send = _Send(client, context, message, cookie, channel, receiver, tlvs)

		target = names.resolve_user(context.backend, receiver)
		if target is None or not names.representable(target):
			self.logger.info('[Client] Unknown receiver:', receiver)
			send.error(ICBMError.NotLoggedOn)
			return
		names.remember(context.bs, target, receiver)
		send.target = target

		# the sender blocking the receiver is a local refusal; the receiver blocking the sender just looks like they're away
		if _blocks(context.backend, context.user, target):
			send.error(ICBMError.InLocalPermitDeny)
			return
		if _blocks(context.backend, target, context.user) and not client.ctrl._temp_permitted(target, context.user):
			send.error(ICBMError.NotLoggedOn)
			return

		if channel == ICBMChannel.AOLIM:
			im_data_tlv = find_tlv(tlvs, ICBMTag.ImData)
			if im_data_tlv is None:
				self.logger.info('[Client] Missing IM data TLV')
				return
			text = parse_im_text(im_data_tlv.data)
			if text is None:
				self.logger.info('[Client] Missing IM text TLV inside IM data')
				return
			self.logger.info('[Client] Message text:', text)
			if names.is_icq_session(context.bs) and not looks_like_html(text):
				# ICQ sends plain text, where AIM sends HTML
				send.text(text, plain_to_html(text))
			else:
				send.text(strip_html_tags(text), text)
		elif channel == ICBMChannel.Rendezvous:
			send.rendezvous()
		elif channel == ICBMChannel.ICQ:
			data_tlv = find_tlv(tlvs, ICBMTag.Data)
			parsed = parse_icq_message(data_tlv.data) if data_tlv is not None else None
			if parsed is None:
				self.logger.info('[Client] Malformed channel 4 message')
				return
			send.icq(*parsed)
		else:
			self.logger.info('[Client] Unsupported channel:', hex(channel))
			send.error(ICBMError.NotSupportedByHost)

	@Subgroup(0x0008)
	def evil_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ICBM__EVIL_REQUEST')

		# u16 send as (0: as yourself, 1: anonymously), string08 who
		send_as = message.read_u16()
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		ctrl = client.ctrl
		backend = context.backend
		user = context.user

		target = names.resolve_user(backend, name)
		if target is user:
			# warning yourself puts AIM in a bad state
			ctrl.send_snac_error(0x0004, message.request_id, ICBMError.NotSupportedByHost)
			return
		if target is None or _blocks(backend, user, target) or _blocks(backend, target, user):
			ctrl.send_snac_error(0x0004, message.request_id, ICBMError.NotLoggedOn)
			return
		if not backend.util_get_sessions_by_user(target) or target.status.is_offlineish():
			ctrl.send_snac_error(0x0004, message.request_id, ICBMError.NotLoggedOn)
			return
		level = _warning_level(target)
		if level >= EVIL_MAX:
			ctrl.send_snac_error(0x0004, message.request_id, ICBMError.RequestDenied)
			return

		# the shared core checks the warner may (`_may_warn`), raises the level, starts it wearing off and tells every
		# session of the target, whatever it's signed on with (OSCAR gets OSERVICE__EVIL_NOTIFICATION, `build_evil_notification`)
		result = backend.abuse.warn(user, target, anonymous = (send_as == 1))
		if result is None:
			ctrl.send_snac_error(0x0004, message.request_id, ICBMError.RequestDenied)
			return
		delta, new_level = result

		reply = SNACMessage(0x0004, 0x0009, 0x0000, message.request_id)
		reply.write_u16(delta)
		reply.write_u16(new_level)
		self.logger.info('[Server] ICBM__EVIL_REPLY')
		client.send_snac(reply)

	@Subgroup(0x000B)
	def client_err(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# ICBM__CLIENT_ERR: cookie, u16 channel, string08 who, u16 code, then code specific data; ICQ also acks channel
		# 2 messages (and answers away message requests) this way. it's passed on as is, from us
		cookie = message.read_bytes(8)
		channel = message.read_u16()
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		rest = message.data
		self.logger.info('[Client] ICBM__CLIENT_ERR to', name)

		target = names.resolve_user(context.backend, name)
		if target is None or _blocks(context.backend, target, context.user):
			return
		for bs_target in oscar_sessions(context.backend, target):
			relay = SNACMessage(0x0004, 0x000B)
			relay.write_bytes(cookie)
			relay.write_u16(channel)
			sender = names.name_for(bs_target, context.user).encode('latin-1', errors = 'replace')
			relay.write_u8(len(sender))
			relay.write_bytes(sender)
			relay.write_bytes(rest)
			bs_target.evt.oscar_on_icbm(relay)

	@Subgroup(0x0010)
	def offline_retrieve(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ICBM__OFFLINE_RETRIEVE')
		# ICBM__OFFLINE_RETRIEVE_REPLY ends the batch; it has no body
		deliver_stored_messages(client.ctrl, then = lambda: client.send_snac(SNACMessage(0x0004, 0x0017, 0x0000, message.request_id)))

	@Subgroup(0x0014)
	def client_event(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		cookie   = message.read_bytes(8)
		channel  = message.read_u16()
		receiver = message.read_bytes(message.read_u8()).decode('latin-1')
		event	= message.read_u16()

		self.logger.info('[Client] ICBM__CLIENT_EVENT')
		self.logger.info('[Client] Receiver:', receiver, '| Event:', hex(event))

		if channel != ICBMChannel.AOLIM:
			self.logger.info('[Client] Unsupported channel:', hex(channel))
			return

		receiver_user = names.resolve_user(context.backend, receiver)
		if receiver_user is None:
			self.logger.info('[Client] Unknown receiver:', receiver)
			return
		receiver_uuid = receiver_user.uuid

		# map OSCAR events to respective MessageTypes
		if event == ICBMEvent.Typing:
			msg_type = MessageType.Typing
		elif event in (ICBMEvent.Finished, ICBMEvent.Typed, ICBMEvent.Closed):
			msg_type = MessageType.TypingDone
		else:
			self.logger.info('[Client] Unknown event type:', hex(event))
			return

		# a typing notification only goes to a conversation that's already there
		existing = context.bs.front_data.get('oscar0_chats', {}).get(receiver_uuid)
		if existing is None:
			return
		cs, evt = existing

		md = MessageData(sender=context.user, type=msg_type, text='')
		md.front_cache['icbm_cookie'] = cookie
		md.front_cache['icbm_event'] = event

		if evt._user_in_chat(receiver_uuid):
			cs.send_message_to_user(receiver_uuid, md)


class _Send:
	# one ICBM__CHANNEL_MSG_TOHOST on its way: where it goes, and how the sender hears back about it
	__slots__ = ('client', 'context', 'message', 'cookie', 'channel', 'receiver', 'tlvs', 'target')

	def __init__(
		self, client: OSCARClient, context: OSCARContext, message: SNACMessage, cookie: bytes, channel: int, receiver: str,
		tlvs: List[TLV],
	) -> None:
		self.client = client
		self.context = context
		self.message = message
		self.cookie = cookie
		self.channel = channel
		self.receiver = receiver
		self.tlvs = tlvs
		self.target: Optional[User] = None

	def error(self, code: int) -> None:
		self.client.ctrl.send_snac_error(0x0004, self.message.request_id, code)

	def ack(self) -> None:
		# ICBM__HOST_ACK only goes back when the client asked for one (TLV 0x03)
		if find_tlv(self.tlvs, ICBMTag.RequestHostAck) is None:
			return
		ack = SNACMessage(0x0004, 0x000C)
		ack.request_id = self.message.request_id
		ack.write_bytes(self.cookie)
		ack.write_u16(self.channel)
		receiver = self.receiver.encode('latin-1', errors = 'replace')
		ack.write_u8(len(receiver))
		ack.write_bytes(receiver)
		self.client.ctrl.logger.info('[Server] ICBM__HOST_ACK')
		self.client.send_snac(ack)

	def text(self, plain: str, html: str, *, icq: Optional[Tuple[int, int, str]] = None) -> None:
		# an IM, the one kind of message every frontend understands, goes through the chat machinery like theirs do
		ctrl = self.client.ctrl
		context = self.context
		target = self.target
		assert target is not None
		auto = find_tlv(self.tlvs, ICBMTag.AutoResponse) is not None

		md = MessageData(sender=context.user, type=MessageType.Chat, text=plain)
		md.front_cache['icbm_cookie'] = self.cookie
		md.front_cache['icbm_html'] = html
		if auto:
			md.front_cache['icbm_auto'] = True
			md.front_cache['away_response'] = True
		if icq is not None:
			md.front_cache['icbm_icq'] = icq

		try:
			cs, evt = ctrl._get_private_chat_with(target.uuid)
		except (error.ContactNotOnline, error.ContactNotOnContactList):
			# TLV 0x06 asks for the message to be stored if it can't be delivered; an auto response never is
			if find_tlv(self.tlvs, ICBMTag.Store) is not None and not auto:
				self._store(plain)
				return
			self.error(ICBMError.NotLoggedOn)
			return
		except Exception as ex:
			ctrl.logger.info('[Client] Could not create private chat:', str(ex))
			self.error(ICBMError.NotLoggedOn)
			return

		# the core counts the message for warnings and checks the sender's rate, every frontend the same
		if not context.backend.util_message_allowed(context.user, md):
			self.error(ICBMError.RateToHost)
			return
		evt._send_when_user_joins(target.uuid, md)
		self.ack()

	def _store(self, plain: str) -> None:
		context = self.context
		target = self.target
		assert target is not None
		try:
			ip = self.client.get_ip()
		except Exception:
			ip = ''
		context.backend.user_service.save_oim(
			context.bs, target.uuid, gen_uuid(), ip, plain, True, from_friendly = context.user.status.name,
		)
		self.ack()

	def rendezvous(self) -> None:
		# channel 2 (file transfers, direct IM, chat invitations, ICQ's advanced messages) only means something to
		# another OSCAR client, so it goes straight to the receiver's OSCAR sessions
		context = self.context
		target = self.target
		assert target is not None
		sessions = oscar_sessions(context.backend, target)
		if not sessions:
			online = bool(context.backend.util_get_sessions_by_user(target))
			self.error(ICBMError.NotSupportedByClient if online else ICBMError.NotLoggedOn)
			return
		tlvs = []
		for tlv in self.tlvs:
			# the ack request and store flag are for the server, and only the server may stamp a send time
			if tlv.type in (ICBMTag.RequestHostAck, ICBMTag.Store, ICBMTag.SendTime):
				continue
			if tlv.type == ICBMTag.Data:
				tlv = TLV(tlv.type, add_external_ip(tlv.data, self.client))
			tlvs.append(tlv)
		relay_icbm(context.backend, context.user, target, self.cookie, self.channel, marshal_tlvs(tlvs), sessions = sessions)
		self.ack()

	def icq(self, uin: int, msg_type: int, flags: int, text: str) -> None:
		# channel 4: ICQ's own messages (text, URLs, contacts, authorization requests and answers...)
		context = self.context
		target = self.target
		assert target is not None
		kind = msg_type & 0xFF

		if kind in (ICQMessageType.AuthRequest, ICQMessageType.AuthDeny, ICQMessageType.AuthGrant, ICQMessageType.Added):
			from .feedbag import auth_event_from_icq_message
			auth_event_from_icq_message(context.backend, context.user, target, kind, text)
			self.ack()
			return

		plain = icq_message_text(kind, text)
		if plain is not None:
			self.text(plain, plain_to_html(plain), icq = (msg_type, flags, text))
			return

		# anything else (file and chat requests, plugins) only an ICQ client can make sense of: one on OSCAR gets the ICBM,
		# a pre-OSCAR one the message
		sessions = [bs for bs in oscar_sessions(context.backend, target) if names.is_icq_session(bs)]
		legacy = [
			bs for bs in context.backend.util_get_sessions_by_user(target) if hasattr(bs.evt, 'icq_on_message') and not bs.closed
		]
		if not sessions and not legacy:
			self.error(ICBMError.NotSupportedByClient if context.backend.util_get_sessions_by_user(target) else ICBMError.NotLoggedOn)
			return
		for bs in legacy:
			bs.evt.icq_on_message(context.user, msg_type, text)
		if sessions:
			tlvs = [tlv for tlv in self.tlvs if tlv.type not in (ICBMTag.RequestHostAck, ICBMTag.Store, ICBMTag.SendTime)]
			relay_icbm(context.backend, context.user, target, self.cookie, self.channel, marshal_tlvs(tlvs), sessions = sessions)
		self.ack()


def _blocks(backend: Any, blocker: User, blockee: User) -> bool:
	# `_is_blocking` needs the blocker's contact list loaded; someone offline can still have an explicit block on file
	if blocker.detail is not None:
		return _is_blocking(blocker, blockee)
	detail = backend._load_detail(blocker)
	ctc = detail.contacts.get(blockee.uuid) if detail is not None else None
	return ctc is not None and bool(ctc.lists & 0x04)

def strip_html_tags(text: str) -> str:
	return unescape(re.compile(r'<[^>]+>').sub('', text))

_BR_RE = re.compile(r'<br\s*/?>', re.IGNORECASE)

def html_to_plain(text: str) -> str:
	# line breaks survive, the rest of the markup doesn't
	return strip_html_tags(_BR_RE.sub('\n', text))

def plain_to_html(text: str) -> str:
	# AIM renders whatever it gets as HTML, so text from anywhere else has to be escaped for it
	return escape(text, quote = False).replace('\r\n', '\n').replace('\n', '<BR>')

def looks_like_html(text: str) -> bool:
	return text[:6].lower() == '<html>' or text[:5].lower() == '<html'

def supports_unicode(bs: Any) -> bool:
	# UCS-2 text for clients that say they take it, and AIM 5 and up, which all do; everyone else gets Windows-1252
	if bs is None:
		return False
	if UNICODE_CAPABILITY in (bs.front_data.get('oscar0_caps') or ()):
		return True
	if names.is_icq_session(bs):
		return False
	try:
		return int(bs.client.version.split('.')[0]) >= 5
	except (ValueError, IndexError):
		return False

def decode_im_text(charset: int, raw: bytes) -> str:
	if charset == ICBMCharset.Unicode:
		return raw.decode('utf-16-be', errors = 'replace')
	# "ASCII" from a Windows client is whatever its codepage was, which in practice is Windows-1252
	return from_latin1(raw)

def encode_im_text(text: str, unicode_ok: bool) -> Tuple[int, bytes]:
	if all(ord(c) < 0x80 for c in text):
		return ICBMCharset.Ascii, text.encode('ascii')
	if unicode_ok:
		return ICBMCharset.Unicode, text.encode('utf-16-be', errors = 'replace')
	if all(ord(c) < 0x100 for c in text):
		return ICBMCharset.Latin1, text.encode('latin-1')
	return ICBMCharset.Ascii, latin1(text)

def parse_im_text(data: bytes) -> Optional[str]:
	# TLV 0x02 holds message fragments: u8 id, u8 version, u16 length, data. id 5 lists capabilities, id 1 is text
	# (u16 charset, u16 language, then the text), and a message can be split over several text fragments
	parts = []
	found = False
	while len(data) >= 4:
		frag_id, _, length = struct.unpack('>BBH', data[:4])
		payload = data[4:4 + length]
		data = data[4 + length:]
		if frag_id != 0x01 or len(payload) < 4:
			continue
		found = True
		charset, _ = struct.unpack('>HH', payload[:4])
		parts.append(decode_im_text(charset, payload[4:]))
	return ''.join(parts) if found else None

def build_im_data(text: str, unicode_ok: bool) -> bytes:
	# the fragment list for TLV 0x02: capabilities (text, plus Unicode when it's used), then the text
	charset, encoded = encode_im_text(text, unicode_ok)
	caps = b'\x01\x06' if charset == ICBMCharset.Unicode else b'\x01\x01\x02'
	# (the capability bytes are the ones AIM 5 sends, with Unicode's when the text needs it; the encoding is ASCII, Latin-1
	# or UCS-2 by what the text holds and what the client takes)
	return b''.join([
		struct.pack('>BBH', 0x05, 0x01, len(caps)), caps,							 # capabilities: plain text (1 byte)
		struct.pack('>BBH', 0x01, 0x01, len(encoded) + 4), struct.pack('>HH', charset, 0x0000), encoded, # encoding=ASCII, language=0, text
	])

def parse_icq_message(data: bytes) -> Optional[Tuple[int, int, int, str]]:
	# a channel 4 message is little endian: u32 sender UIN, u8 type, u8 flags, u16 length, null-terminated text
	if len(data) < 8:
		return None
	uin, msg_type, flags, length = struct.unpack('<LBBH', data[:8])
	raw = data[8:8 + length]
	if b'\x00' in raw:
		raw = raw[:raw.index(b'\x00')]
	return uin, msg_type, flags, from_latin1(raw)

def build_icq_message(uin: int, msg_type: int, flags: int, text: str) -> bytes:
	raw = latin1(text) + b'\x00'
	return struct.pack('<LBBH', uin, msg_type, flags, len(raw)) + raw

def icq_message_text(kind: int, text: str) -> Optional[str]:
	# the ICQ message types that come down to text anyone can read (fields are split by 0xFE)
	fields = text.split('\xfe')
	if kind == ICQMessageType.Plain:
		return text
	if kind == ICQMessageType.Url:
		# description, then the URL
		description = fields[0] if fields else ''
		url = fields[1] if len(fields) > 1 else ''
		return '{}\r\n{}'.format(description, url).strip()
	if kind in (ICQMessageType.WebPager, ICQMessageType.EmailExpress):
		# nick, (empty), (empty), e-mail, (empty), text
		return fields[-1] if fields else text
	if kind == ICQMessageType.Contacts:
		# count, then UIN and nick for each contact
		entries = fields[1:]
		pairs = ['{} ({})'.format(entries[i], entries[i + 1]) for i in range(0, len(entries) - 1, 2) if entries[i]]
		return 'Contacts: ' + ', '.join(pairs) if pairs else None
	return None

def add_external_ip(data: bytes, client: OSCARClient) -> bytes:
	# a rendezvous proposal (u16 type 0, 8 byte cookie, 16 byte capability, TLVs) gets the address the server sees it
	# coming from in place of whatever LAN address the client put in, plus the verified-IP TLV peers check it against
	if len(data) < 26 or struct.unpack('>H', data[:2])[0] != 0x0000:
		return data
	tlvs = unmarshal_tlvs(data[26:])
	if find_tlv(tlvs, 0x0003) is None:
		return data
	try:
		address = ipaddress.ip_address(client.get_ip())
	except Exception:
		return data
	if not isinstance(address, ipaddress.IPv4Address):
		ipv4 = getattr(address, 'ipv4_mapped', None)
		if ipv4 is None:
			return data
		address = ipv4
	packed = address.packed
	tlvs = [TLV(0x0003, packed) if tlv.type == 0x0003 else tlv for tlv in tlvs]
	tlvs.append(TLV(0x0004, packed))
	return data[:26] + marshal_tlvs(tlvs)

def sender_userinfo(backend: Any, sender: User, viewer: Any) -> bytes:
	return build_userinfo(
		sender, pick_session(backend, sender), name = names.name_for(viewer, sender), viewer_icq = names.is_icq_session(viewer),
	)

def build_icbm_to_client(backend: Any, sender: User, viewer: Any, cookie: bytes, channel: int, tlvs: bytes) -> SNACMessage:
	# ICBM__CHANNEL_MSG_TOCLIENT: cookie, u16 channel, the sender's USERINFO (as this viewer knows them), TLVs
	msg = SNACMessage(0x0004, 0x0007)
	msg.write_bytes(cookie)
	msg.write_u16(channel)
	msg.write_bytes(sender_userinfo(backend, sender, viewer))
	msg.write_bytes(tlvs)
	return msg

def relay_icbm(
	backend: Any, sender: User, target: User, cookie: bytes, channel: int, tlvs: bytes, *, sessions: Optional[List[Any]] = None,
) -> None:
	for bs_target in (sessions if sessions is not None else oscar_sessions(backend, target)):
		bs_target.evt.oscar_on_icbm(build_icbm_to_client(backend, sender, bs_target, cookie, channel, tlvs))

def send_icq_system_message(ctrl: Any, sender: User, kind: int, text: str) -> None:
	# a channel 4 message as if from `sender` (how a client without a feedbag hears about authorization and adds)
	uin = names.uin_of(sender) or 0
	tlvs = marshal_tlvs([TLV(ICBMTag.Data, build_icq_message(uin, kind, 0x00, text))])
	ctrl.send_snac(build_icbm_to_client(ctrl.backend, sender, ctrl.bs, gen_cookie(), ICBMChannel.ICQ, tlvs))

def gen_cookie() -> bytes:
	# ICBM cookies are opaque 8 byte message ids; clients drop a message whose cookie they've just seen
	return os.urandom(8)

def messagedata_to_icbm(cookie: bytes, data: MessageData, viewer: Any) -> SNACMessage:
	#   cookie		 - 8 bytes, chat sess cookie
	#   channel		- u16, 0x0001 for plain text IM
	#   sender		 - string08 (u8 length prefix), sender's screen name
	#   warning level  - u16, always 0
	#   userinfo TLVs  - write_tlv_block (count-prefixed) containing:
	#					  TLV(0x0001) user class
	#					  TLV(0x0003) account signon time (unix time_t)
	#					  TLV(0x000F) session length in seconds
	#					  TLV(0x0005) account creation time (unix time_t)
	#   TLV(0x0002)	- IM data block containing nested TLVs:
	#					  TLV(0x0501) capabilities (1 byte = 0x01 for plain text)
	#					  TLV(0x0101) text: u16 encoding + u16 language + bytes
	sender = data.sender
	backend = viewer.backend
	viewer_icq = names.is_icq_session(viewer)

	# an ICQ client gets ICQ messages (URLs, contacts...) back as channel 4, from someone it knows by UIN
	icq = data.front_cache.get('icbm_icq')
	if viewer_icq and icq is not None and names.uin_of(sender) is not None:
		msg_type, flags, text = icq
		tlvs = marshal_tlvs([TLV(ICBMTag.Data, build_icq_message(names.uin_of(sender), msg_type, flags, text))])
		return build_icbm_to_client(backend, sender, viewer, cookie, ICBMChannel.ICQ, tlvs)

	# ICQ shows text as it is, AIM renders HTML
	if viewer_icq:
		text = (data.text or '').replace('\r\n', '\n').replace('\n', '\r\n')
	else:
		text = data.front_cache.get('icbm_html') or plain_to_html(data.text or '')

	msg = SNACMessage(0x0004, 0x0007)
	msg.write_bytes(cookie)
	msg.write_u16(ICBMChannel.AOLIM)

	# sender, warning level and the userinfo TLV block, all as one OSERVICE__USERINFO
	# usually would include TLV(0x001D) (BART info), but we don't support that yet
	msg.write_bytes(sender_userinfo(backend, sender, viewer))

	# IM data: TLV(0x0002) wrapping nested capability + text TLVs
	tlvs = [TLV(ICBMTag.ImData, build_im_data(text, supports_unicode(viewer)))]
	if data.front_cache.get('icbm_auto'):
		tlvs.append(TLV(ICBMTag.AutoResponse))
	if data.front_cache.get('icbm_sent') is not None:
		tlvs.append(TLV(ICBMTag.SendTime, struct.pack('>L', int(data.front_cache['icbm_sent']))))
	msg.write_tlvs(tlvs)

	return msg

def messagedata_to_icbm_event(data: MessageData, viewer: Any) -> SNACMessage:

	if data.type is MessageType.Typing:
		event = ICBMEvent.Typing
	else:
		event = data.front_cache.get('icbm_event', ICBMEvent.Finished)

	msg = SNACMessage(0x0004, 0x0014)
	msg.write_bytes(data.front_cache.get('icbm_cookie') or b'\x00' * 8)
	msg.write_u16(ICBMChannel.AOLIM)
	sender = names.name_for(viewer, data.sender).encode('latin-1', errors = 'replace')
	msg.write_u8(len(sender))
	msg.write_bytes(sender)
	msg.write_u16(event)
	return msg

def deliver_stored_messages(ctrl: Any, *, then: Optional[Callable[[], None]] = None) -> None:
	# everything stored for the account; reading the store is file work, done off the event loop
	ctrl.backend.loop.create_task(_deliver_stored_messages(ctrl, then))

async def _deliver_stored_messages(ctrl: Any, then: Optional[Callable[[], None]]) -> None:
	bs = ctrl.bs
	if bs is None:
		return
	oims = await ctrl.backend.loop.run_in_executor(None, ctrl.backend.user_service.get_oim_batch, bs.user)
	if bs.closed:
		return
	deliver_offline_messages(ctrl, oims)
	if then is not None:
		then()

async def delete_stored_messages(backend: Any, recipient_uuid: str, uuids: List[str]) -> None:
	for uuid in uuids:
		await backend.loop.run_in_executor(None, backend.user_service.delete_oim, recipient_uuid, uuid)

def deliver_offline_messages(ctrl: Any, oims: List[OIM]) -> None:
	# stored messages (from any frontend) go to an AIM client as IMs stamped with when they were sent (TLV 0x16)
	bs = ctrl.bs
	if bs is None:
		return
	backend = ctrl.backend
	delivered = []
	for oim in oims:
		sender = None
		if oim.from_username:
			uuid = backend.util_get_uuid_from_username(oim.from_username)
			sender = backend._load_user_record(uuid) if uuid is not None else None
		if sender is None:
			uuid = backend.util_get_uuid_from_email(oim.from_email)
			sender = backend._load_user_record(uuid) if uuid is not None else None
		if sender is not None:
			md = MessageData(sender = sender, type = MessageType.Chat, text = oim.message or '')
			md.front_cache['icbm_sent'] = int(oim.sent.timestamp())
			ctrl.send_snac(messagedata_to_icbm(gen_cookie(), md, bs))
		delivered.append(oim.uuid)
	if delivered:
		backend.loop.create_task(delete_stored_messages(backend, bs.user.uuid, delivered))

def _track_conversation(sender: User, recipient: User, backend: Any = None) -> None:
	# (every message sent through a chat is counted by the core, `ChatSession.send_message_to_everyone`; this is for messages
	# that don't go through one)
	if backend is not None:
		backend.abuse.track_message(sender, recipient)

def _may_warn(warner: User, warnee: User, backend: Any) -> bool:
	# only someone who has messaged you can be warned, at most once for each message, three times an hour
	return bool(backend.abuse.may_warn(warner, warnee))

def _warning_level(user: User) -> int:
	return max(0, min(EVIL_MAX, int(user.evil_permanent or 0) + int(user.evil_temporary or 0)))

def _announce_warning(backend: Any, user: User) -> None:
	# the warning level is in every USERINFO, so buddies get a fresh arrival and the user an update of their own
	backend.abuse.announce(user, None)

def _start_decay(backend: Any, user: User) -> None:
	backend.abuse._start_decay(user)

async def _decay_warnings(backend: Any) -> None:
	await backend.abuse._decay_warnings()

def build_evil_notification(bs_target: Any, level: int, warner: Optional[User]) -> SNACMessage:
	# OSERVICE__EVIL_NOTIFICATION: u16 new level, then who did it (unless it was anonymous)
	notif = SNACMessage(0x0001, 0x0010)
	notif.write_u16(level)
	if warner is not None:
		name = names.name_for(bs_target, warner).encode('latin-1', errors = 'replace')
		notif.write_u8(len(name))
		notif.write_bytes(name)
		notif.write_u16(_warning_level(warner))
		notif.write_u16(0)
	return notif
