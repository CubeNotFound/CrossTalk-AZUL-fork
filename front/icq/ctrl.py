import asyncio
import socket
import struct
import time

from datetime import datetime
from typing import Any, TYPE_CHECKING

import settings

from core import error
from core.backend import BackendSession, ChatSession
from core.client import Client
from core.models import Contact, ContactList, LoginOption, MessageData, MessageType as ChatMessageType, OIM, Substatus, User
from util import icq
from util.misc import Logger, gen_uuid

from front.oscar.proto.names import uin_of
from front.oscar.proto.userinfo import icq_status_for, pick_session, substatus_from_icq_status

from . import directory, meta, wire
from .packets import (
	Command, LE, MAX_ABOUT, MAX_HOMEPAGE, MAX_NAME, MAX_NICK, MAX_PHONE, MessageType, Reader, Server, Version, uin_list,
)

if TYPE_CHECKING:
	from .entry import ListenerICQ
	from .events import ChatEventHandler
	from .wire import Header

Address = tuple[str, int]

# what the old (pre-META) packets say about authorization: 1 means it's required
OLD_AUTH_REQUIRED = 1

# the trailing words a V4 login reply carries (the third is the keep-alive interval)
V4_HELLO_WORDS = (0x0000, 0x0000, 0x0019, 0x0002, 0x0001, 0x00FA, 0x002D, 0x0005, 0x000A, 0x0005)

# the V5 deps list reply is a bare V3 header with this in its checkcode field
V5_DEPS_LIST_CHECK = 0x8FFCACBF

REGISTRATION_NOTES = 'New accounts are made on the website. Choose "existing user" to sign on with your UIN.'


def _ip_bytes(addr: Address) -> bytes:
	try:
		return socket.inet_aton(addr[0])
	except OSError:
		return bytes(4)

def downgrade_v2(status: int) -> int:
	# V1/V2 clients only show online, away and the combined DND/occupied (0x11); the rest map to the nearest of those
	base = status & 0xFF
	flags = status & 0xFFFFFF00
	base = { 0x02: 0x11, 0x04: 0x01, 0x05: 0x01, 0x10: 0x11, 0x13: 0x11, 0x20: 0x00 }.get(base, base)
	return flags | base

def status_word(backend: Any, user: User, substatus: Substatus) -> int:
	# the status dword ICQ shows for `user`: the one their ICQ client set while it still holds, else worked out
	return icq_status_for(user, pick_session(backend, user), substatus)


class LoginRequest:
	__slots__ = ('password', 'status', 'port', 'internal_ip', 'dc_type', 'dc_version', 'login_seq')

	password: str
	status: int
	port: int
	internal_ip: int
	dc_type: int
	dc_version: int
	login_seq: int

	def __init__(self) -> None:
		self.password = ''
		self.status = 0
		self.port = 0
		self.internal_ip = 0
		self.dc_type = 0
		self.dc_version = 0
		self.login_seq = 0

def parse_login(version: int, data: bytes) -> LoginRequest | None:
	request = LoginRequest()
	reader = Reader(data)
	try:
		if version == Version.V1:
			# CMD_GET_DEPS doubles as V1's login: password, u32 status
			request.password = icq.from_latin1(reader.raw_string())
			request.status = reader.u32() if reader.remaining() >= 4 else 0
		elif version == Version.V2:
			# u32 TCP port, password, u32, u32 IP, u8, u16 status, u16 DC version, 12 bytes; the login's own sequence
			# number (which the reply echoes) sits 17 bytes past the password
			request.port = reader.u32()
			request.password = icq.from_latin1(reader.raw_string())
			rest = reader.rest()
			if len(rest) >= 11:
				request.status = struct.unpack_from('<H', rest, 9)[0]
			if len(rest) >= 19:
				request.login_seq = struct.unpack_from('<H', rest, 17)[0]
		elif version == Version.V3:
			# u32 TCP port, password; a V3 client signs on as online
			request.port = reader.u32()
			request.password = icq.from_latin1(reader.raw_string())
		else:
			# u32 time, u32 TCP port, password, u32, u32 LAN IP, u8 DC type, u32 status, (V5) u32 DC version
			reader.u32()
			request.port = reader.u32()
			request.password = icq.from_latin1(reader.raw_string())
			if reader.remaining() >= 13:
				reader.u32()
				request.internal_ip = reader.u32()
				request.dc_type = reader.u8()
				request.status = reader.u32()
				if version == Version.V5 and reader.remaining() >= 4:
					request.dc_version = reader.u32()
	except ValueError:
		return None
	return request


class LegacyCtrl:
	# one signed on pre-OSCAR client, found again by the address its datagrams come from
	__slots__ = (
		'server', 'backend', 'logger', 'addr', 'version', 'uin', 'session_id', 'seq', 'bs', 'last_activity', 'closed',
		'contacts', 'visible', 'invisible', 'shown', 'offline_pending', 'chats', 'dc_info',
	)

	server: 'ListenerICQ'
	backend: Any
	logger: Logger
	addr: Address
	version: int
	uin: int
	session_id: int
	seq: int
	bs: BackendSession | None
	last_activity: float
	closed: bool
	# the client's own contact list (sent at every sign-on), by UIN, with the account each one is
	contacts: dict[int, str]
	visible: set[int]
	invisible: set[int]
	# who the client was last told is online, and with what status dword
	shown: dict[int, int]
	# offline messages handed over, deleted once the client says it has them
	offline_pending: list[str]
	chats: dict[str, tuple[ChatSession, 'ChatEventHandler']]
	# u32 TCP port, u32 LAN IP, u8 DC type, u16 DC version, from the login
	dc_info: tuple[int, int, int, int]

	def __init__(self, server: 'ListenerICQ', addr: Address, version: int, uin: int, session_id: int) -> None:
		self.server = server
		self.backend = server.backend
		self.logger = Logger('ICQ', self)
		self.addr = addr
		self.version = version
		self.uin = uin
		self.session_id = session_id
		# server sequence numbers start from 0
		self.seq = 0
		self.bs = None
		self.last_activity = time.monotonic()
		self.closed = False
		self.contacts = {}
		self.visible = set()
		self.invisible = set()
		self.shown = {}
		self.offline_pending = []
		self.chats = {}
		self.dc_info = (0, 0, 0, 0)

	@property
	def user(self) -> User:
		assert self.bs is not None
		return self.bs.user

	def next_seq(self) -> int:
		seq = self.seq
		self.seq = (self.seq + 1) & 0xFFFF
		return seq

	def send(self, command: int, data: bytes = b'', *, seq1: int | None = None, seq2: int = 0) -> None:
		# what the server sends unprompted takes the next server sequence number
		if self.closed:
			return
		if seq1 is None:
			seq1 = self.next_seq()
		packet = wire.build(self.version, command, data, seq1 = seq1, seq2 = seq2, uin = self.uin, session_id = self.session_id)
		self.server.send(packet, self.addr)

	def ack(self, header: 'Header', *, with_seq2: bool = False) -> None:
		if self.version == Version.V5:
			seq2 = header.seq2 if with_seq2 else 0
		elif self.version in (Version.V3, Version.V4):
			seq2 = header.seq2
		else:
			seq2 = 0
		self.send(Server.Ack, seq1 = header.seq1, seq2 = seq2)

	def is_old(self) -> bool:
		return self.version in (Version.V1, Version.V2)

	# sign on

	def send_login_reply(self, header: 'Header', login: LoginRequest) -> None:
		ip = _ip_bytes(self.addr)
		if self.version == Version.V5:
			# u16 keep-alive interval (low, high), u16 ping time, u16 timeout, u16 0x0A, u16 retries, the client's IP, u32
			# server ID; seq1 0, the login's seq2
			data = LE().u16(0x008C).u16(0x0000).u16(50).u16(60).u16(0x000A).u16(5).raw(ip).u32(0x80CDC19B).bytes()
			self.send(Server.Hello, data, seq1 = 0, seq2 = header.seq2)
		elif self.version == Version.V4:
			# the client's IP, then ten words
			body = LE().raw(ip)
			for word in V4_HELLO_WORDS:
				body.u16(word)
			self.send(Server.Hello, body.bytes(), seq2 = header.seq2)
		elif self.version == Version.V3:
			# the client's IP, u32 0, u32 externals, u32 deps list version, u8 must change password, u8 can broadcast,
			# u32 0xFA, u16 ping frequency, u16 packet timeout, u16 retry timeout, u16 retries
			data = LE().raw(ip).u32(0).u32(0).u32(1).u8(0).u8(0).u32(0x000000FA).u16(50).u16(60).u16(10).u16(3).bytes()
			self.send(Server.Hello, data, seq1 = 0, seq2 = header.seq2)
		else:
			# u32 UIN, the client's IP, the login's own sequence number, then the 23 bytes a Mirabilis server sent
			body = LE().u32(self.uin).raw(ip).u16(login.login_seq)
			body.raw(bytes.fromhex('01000500' '00000000' '8c000000' 'f0000a00' '0a0005000a0001'))
			self.send(Server.Hello, body.bytes())

	def signed_on(self, login: LoginRequest) -> None:
		bs = self.bs
		assert bs is not None
		bs.front_data['icq0'] = True
		bs.front_data['icq0_status'] = login.status
		self.dc_info = (login.port, login.internal_ip, login.dc_type, login.dc_version)
		bs.me_update({ 'substatus': substatus_from_icq_status(login.status) })
		# authorization requests and answers held while this account wasn't on ICQ
		from front.oscar.foodgroups.feedbag import deliver_queued_auth_events
		deliver_queued_auth_events(self)

	# packets from a signed on client

	def on_packet(self, header: 'Header', data: bytes) -> None:
		self.last_activity = time.monotonic()
		command = header.command
		if command == Command.Ack:
			return
		handler = self._handler(command)
		if handler is None:
			# anything else is acknowledged and dropped, so the client stops resending it
			self.logger.info('[Client] Unhandled command', hex(command), 'from V{}'.format(self.version))
			self.ack(header)
			return
		handler(header, data)

	def _handler(self, command: int) -> Any:
		version = self.version
		common = {
			Command.KeepAlive: self._keepalive,
			Command.KeepAlive2: self._keepalive,
			Command.Logoff: self._logoff,
			Command.ContactList: self._contact_list,
			Command.UserAdd: self._user_add,
			Command.SetStatus: self._set_status,
			Command.ThruServer: self._message,
			Command.Authorize: self._message,
			Command.SysMsgReq: self._offline_request,
			Command.SysMsgDoneAck: self._offline_done,
			Command.VisibleList: self._visible_list,
			Command.InvisibleList: self._invisible_list,
			Command.SearchUin: self._search_uin,
			Command.SearchUser: self._search_user,
			Command.InfoReq: self._info,
			Command.ExtInfoReq: self._ext_info,
		}
		if version == Version.V5:
			common.update({
				Command.MetaUser: lambda header, data: meta.handle(self, header, data),
				Command.ChangeVILists: self._change_vi_lists,
				# searches a V5 client sends outside META_USER, with the old answers
				0x0514: self._direct_search_name, 0x0515: self._direct_search_name,
				0x051F: self._direct_search_uin,
				0x0528: self._direct_search_email, 0x0529: self._direct_search_email,
				0x0532: self._direct_search_white, 0x0533: self._direct_search_white,
			})
		elif version in (Version.V3, Version.V4):
			common.update({
				Command.UserGetInfo: self._info,
				Command.SetBasicInfo: self._update_basic,
			})
			if version == Version.V4:
				common[Command.UpdateDetail] = self._update_detail
			else:
				common[Command.SetAuth] = self._set_auth_v3
				# V3 has no extended info request of its own
				del common[Command.ExtInfoReq]
		else:
			common.update({
				Command.UpdateBasic: self._update_basic,
				Command.SetBasicInfo: self._update_basic,
				Command.UpdateDetail: self._update_detail,
			})
		return common.get(command)

	def _keepalive(self, header: 'Header', data: bytes) -> None:
		self.ack(header)

	def _logoff(self, header: 'Header', data: bytes) -> None:
		# CMD_LOGOFF ends the session; nothing goes back
		self.close()

	# presence

	def _contact_list(self, header: 'Header', data: bytes) -> None:
		# u8 count and that many UINs; a long list comes in several, each adding to what's there
		self.ack(header)
		for uin in uin_list(data):
			self._watch(uin)
		if self.is_old():
			self.send(Server.UserListDone, LE().u32(self.uin).bytes())
		else:
			self.send(Server.UserListDone, seq2 = header.seq2)

	def _watch(self, uin: int) -> User | None:
		if uin == self.uin or self.bs is None:
			return None
		uuid = self.contacts.get(uin) or self.backend.util_get_uuid_from_uin(uin)
		if uuid is None:
			return None
		user = self.backend._load_user_record(uuid)
		if user is None:
			return None
		self.contacts[uin] = uuid
		self.backend.util_watch(self.bs, uuid)
		self.push_presence(user)
		return user

	def push_presence(self, user: User) -> None:
		# where `user` stands right now, as this account sees them
		from core.backend import _watch_contact
		detail = self.user.detail
		ctc = detail.contacts.get(user.uuid) if detail is not None else None
		if ctc is None or not ctc.lists & ContactList.FL:
			ctc = _watch_contact(user, self.user)
		else:
			ctc.compute_visible_status(self.user)
		self.show(user, ctc.status.substatus)

	def on_presence(self, ctc: Contact) -> None:
		uin = uin_of(ctc.head)
		if uin is None or uin not in self.contacts:
			return
		ctc.compute_visible_status(self.user)
		self.show(ctc.head, ctc.status.substatus)

	def show(self, user: User, substatus: Substatus) -> None:
		# a contact's arrival (SRV_USER_ONLINE), a change while on (SRV_USER_STATUS) or departure (SRV_USER_OFFLINE)
		uin = uin_of(user)
		if uin is None or self.closed:
			return
		online = not substatus.is_offlineish() and bool(self.backend.util_get_sessions_by_user(user))
		if not online:
			if self.shown.pop(uin, None) is not None:
				self.send(Server.UserOffline, LE().u32(uin).bytes())
			return
		status = status_word(self.backend, user, substatus)
		if self.is_old():
			status = downgrade_v2(status)
		previous = self.shown.get(uin)
		self.shown[uin] = status
		if previous is None:
			self.send(Server.UserOnline, self._user_online(user, uin, status))
		elif previous != status:
			# u32 UIN, u32 status (u16 status and u16 extended status)
			self.send(Server.UserStatus, LE().u32(uin).u32(status).bytes())

	def _user_online(self, user: User, uin: int, status: int) -> bytes:
		if self.version == Version.V5:
			# u32 UIN, u32 IP, u32 TCP port, u32 LAN IP, u8 DC type, u16 status, u16 extended status, u32 DC version, u32 DC
			# cookie, u32 web port, u32 client features, three u32 update times
			ip, port, lan_ip, dc_type, dc_version = self._peer_dc(user)
			body = LE().u32(uin).raw(ip).u32(port).u32(lan_ip).u8(dc_type).u16(status & 0xFFFF).u16(status >> 16)
			return body.u32(dc_version).raw(bytes(24)).bytes()
		if self.version in (Version.V3, Version.V4):
			# u32 UIN, u32 IP, u32 TCP port, u32 LAN IP, u8 DC type, u16 status, u16 extended status, u16 DC version, u16
			return LE().u32(uin).u32(0).u32(0).u32(0).u8(0).u16(status & 0xFFFF).u16(status >> 16).u16(0).u16(0).bytes()
		# u32 UIN, u32 IP, u16 TCP port, u32 LAN IP, u16 DC version (3), u8 (4), u16 status, then six bytes
		return LE().u32(uin).u32(0).u16(0).u32(0).u16(0x0003).u8(0x04).u16(status).raw(bytes.fromhex('020000000000')).bytes()

	def _peer_dc(self, user: User) -> tuple[bytes, int, int, int, int]:
		# a V5 peer's direct connection details go out only when the operator allows it (they give its IP address away)
		if not getattr(settings, 'ICQ_DIRECT_CONNECTIONS', False):
			return bytes(4), 0, 0, 0, 0
		for bs_other in self.backend.util_get_sessions_by_user(user):
			other = getattr(bs_other.evt, 'ctrl', None)
			if isinstance(other, LegacyCtrl) and other.version == Version.V5 and not other.closed:
				port, lan_ip, dc_type, dc_version = other.dc_info
				return _ip_bytes(other.addr), port, lan_ip, dc_type, dc_version
		return bytes(4), 0, 0, 0, 0

	def _set_status(self, header: 'Header', data: bytes) -> None:
		# u32 status
		self.ack(header)
		if len(data) < 4 or self.bs is None:
			return
		status = struct.unpack_from('<L', data)[0]
		self.bs.front_data['icq0_status'] = status
		self.bs.me_update({ 'substatus': substatus_from_icq_status(status) })

	def _visible_list(self, header: 'Header', data: bytes) -> None:
		# who may see this account while it's invisible; kept for the session (the other frontends have no such list)
		self.ack(header)
		self.visible = set(uin_list(data))

	def _invisible_list(self, header: 'Header', data: bytes) -> None:
		self.ack(header)
		self.invisible = set(uin_list(data))

	def _change_vi_lists(self, header: 'Header', data: bytes) -> None:
		# u8 action (1: add to visible, 2: remove from visible, 3: add to invisible, 4: remove from invisible), u32 UIN
		self.ack(header)
		if len(data) < 5:
			return
		action, uin = struct.unpack_from('<BL', data)
		if action == 1:
			self.visible.add(uin)
		elif action == 2:
			self.visible.discard(uin)
		elif action == 3:
			self.invisible.add(uin)
		elif action == 4:
			self.invisible.discard(uin)

	def _user_add(self, header: 'Header', data: bytes) -> None:
		# u32 UIN: one more contact, who hears they were added
		self.ack(header)
		if len(data) < 4:
			return
		user = self._watch(struct.unpack_from('<L', data)[0])
		if user is None or icq.requires_authorization(user, self.user):
			return
		from front.oscar.foodgroups.feedbag import _deliver_auth_event
		_deliver_auth_event(self.backend, user, self.user, 'added')

	# messages

	def _message(self, header: 'Header', data: bytes) -> None:
		# u32 UIN, u16 type, the text (fields of the structured types split by 0xFE)
		self.ack(header)
		reader = Reader(data)
		try:
			to = reader.u32()
			msg_type = reader.u16()
			text = icq.from_latin1(reader.raw_string())
		except ValueError:
			return
		target = directory.find(self.backend, to)
		if target is None or self.bs is None or target is self.user:
			return
		kind = msg_type & 0xFF
		from front.oscar.foodgroups.icbm import icq_message_text
		if kind in (MessageType.AuthRequest, MessageType.AuthDeny, MessageType.AuthGrant, MessageType.Added):
			from front.oscar.foodgroups.feedbag import auth_event_from_icq_message
			auth_event_from_icq_message(self.backend, self.user, target, kind, text)
			return
		plain = icq_message_text(kind, text)
		if plain is not None:
			self._send_text(target, plain, msg_type, text)
			return
		# anything else (chat and file requests, plugins, auto-away requests) only another ICQ client can make sense of
		relay_icq_message(self.backend, self.user, target, msg_type, text)

	def _send_text(self, target: User, plain: str, msg_type: int, text: str) -> None:
		# a message anyone can read goes through the chat machinery like every frontend's, carrying its ICQ form along for
		# ICQ clients on the other end
		md = MessageData(sender = self.user, type = ChatMessageType.Chat, text = plain)
		md.front_cache['icbm_icq'] = (msg_type, 0x00, text)
		md.front_cache['icq0_message'] = (msg_type, text)
		try:
			cs, evt = self._get_private_chat_with(target)
		except (error.ContactNotOnline, error.ContactNotOnContactList):
			# the server keeps messages for whoever isn't on, which is what the client counts on
			self._store_offline(target, plain)
			return
		except Exception as ex:
			self.logger.info('[Client] Could not open a chat:', str(ex))
			return
		evt.send_when_joined(target.uuid, md)

	def _store_offline(self, target: User, plain: str) -> None:
		bs = self.bs
		if bs is None:
			return
		detail = self.backend._load_detail(target)
		ctc_self = detail.contacts.get(self.user.uuid) if detail is not None else None
		if ctc_self is not None and ctc_self.lists & ContactList.BL:
			return
		self.backend.user_service.save_oim(bs, target.uuid, gen_uuid(), self.addr[0], plain, True, from_friendly = self.user.status.name)

	def _get_private_chat_with(self, other: User) -> tuple[ChatSession, 'ChatEventHandler']:
		from .events import ChatEventHandler
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		ctc = detail.contacts.get(other.uuid) if detail is not None else None
		if ctc is not None and ctc.lists & ContactList.BL:
			raise error.ContactNotOnContactList()
		# a chat whose other side has gone can't carry anything any more
		existing = self.chats.get(other.uuid)
		if existing is not None and existing[0].closed:
			del self.chats[other.uuid]
			existing = None
		if existing is not None:
			if other.status.is_offlineish():
				raise error.ContactNotOnline()
			return existing
		other_detail = self.backend._load_detail(other)
		if other_detail is None:
			raise error.ContactNotOnline()
		ctc_self = other_detail.contacts.get(user.uuid)
		if ctc_self is not None and ctc_self.lists & ContactList.BL:
			raise error.ContactNotOnline()
		chat = self.backend.chat_create()
		chat.front_data['icq0'] = True
		evt = ChatEventHandler(self)
		cs = chat.join('icq0', bs, evt)
		try:
			cs.invite(other)
		except error.ClientError:
			cs.close()
			raise
		self.chats[other.uuid] = (cs, evt)
		return cs, evt

	def join_chat(self, chat: Any, inviter: User) -> None:
		# someone started a conversation; it replaces whatever older one there was with them
		from .events import ChatEventHandler
		if self.bs is None:
			return
		previous = self.chats.pop(inviter.uuid, None)
		if previous is not None and previous[0].chat is not chat:
			previous[0].close()
		evt = ChatEventHandler(self)
		cs = chat.join('icq0', self.bs, evt)
		chat.send_participant_joined(cs)
		self.chats[inviter.uuid] = (cs, evt)

	def deliver_chat_message(self, data: MessageData) -> None:
		# a message reaches an ICQ client from a UIN, as the type it was sent as when that's known
		sender = data.sender
		uin = uin_of(sender)
		if uin is None:
			return
		sent = data.front_cache.get('icq0_message')
		if sent is None and data.front_cache.get('icbm_icq') is not None:
			msg_type, _, text = data.front_cache['icbm_icq']
			sent = (msg_type, text)
		if sent is None:
			sent = (MessageType.Text, data.text or '')
		msg_type, text = sent
		if msg_type & 0xFF == MessageType.Text:
			text = text.replace('\r\n', '\n').replace('\n', '\r\n')
		self.deliver_message(uin, msg_type, text)

	def deliver_message(self, from_uin: int, msg_type: int, text: str) -> None:
		# SRV_SYS_MSG_ONLINE: u32 UIN, u16 type (just the low byte for V3/V4), the text
		if self.version in (Version.V3, Version.V4):
			msg_type &= 0x00FF
		self.send(Server.SysMsgOnline, LE().u32(from_uin).u16(msg_type).string(text).bytes())

	def on_auth_event(self, event: str, sender: User, text: str) -> None:
		# an authorization request or answer, or "you were added", as the message types ICQ has always had for them
		uin = uin_of(sender)
		if uin is None:
			return
		info = directory.profile(sender, self.user)
		fields = [info['nick'], info['first'], info['last'], info['email']]
		if event == 'request':
			from front.oscar.foodgroups.feedbag import _legacy_auth_request_text
			self.deliver_message(uin, MessageType.AuthRequest, _legacy_auth_request_text(sender, self.user, text))
		elif event in ('granted', 'preauth'):
			self.deliver_message(uin, MessageType.AuthGrant, '\xfe'.join(fields + ['']))
			if uin in self.contacts:
				self.push_presence(sender)
		elif event == 'denied':
			self.deliver_message(uin, MessageType.AuthDeny, '\xfe'.join(fields + [text]))
		elif event == 'added':
			self.deliver_message(uin, MessageType.Added, '\xfe'.join(fields + ['0']))

	# offline messages

	def _offline_request(self, header: 'Header', data: bytes) -> None:
		self.ack(header)
		self.backend.loop.create_task(self._send_offline_messages(header.seq2))

	async def _send_offline_messages(self, seq2: int) -> None:
		bs = self.bs
		if bs is None:
			return
		loop = self.backend.loop
		user_service = self.backend.user_service
		oims = await loop.run_in_executor(None, user_service.get_oim_batch, bs.user)
		if self.closed:
			return
		for oim in oims:
			sender = _oim_sender(self.backend, oim)
			uin = uin_of(sender) if sender is not None else None
			if uin is None:
				# an ICQ client can only show a message from a UIN; the rest wait for another client
				continue
			self._send_offline_message(uin, oim)
			self.offline_pending.append(oim.uuid)
		# SRV_SYS_MSG_DONE: V1/V2 carry the UIN, the rest answer the request's seq2
		if self.is_old():
			self.send(Server.SysMsgDone, LE().u32(self.uin).bytes())
		else:
			self.send(Server.SysMsgDone, seq2 = seq2)

	def _send_offline_message(self, uin: int, oim: OIM) -> None:
		# SRV_SYS_MSG_OFFLINE: u32 UIN, u16 year, u8 month, u8 day, u8 hour, u8 minute, u16 type, the text
		sent = oim.sent if isinstance(oim.sent, datetime) else datetime.utcnow()
		text = (oim.message or '').replace('\r\n', '\n').replace('\n', '\r\n')
		body = LE().u32(uin).u16(sent.year).u8(sent.month).u8(sent.day).u8(sent.hour).u8(sent.minute)
		self.send(Server.SysMsgOffline, body.u16(MessageType.Text).string(text).bytes())

	def _offline_done(self, header: 'Header', data: bytes) -> None:
		# CMD_SYS_MSG_DONE_ACK: the client has them, so they go
		self.ack(header)
		delivered, self.offline_pending = self.offline_pending, []
		if delivered and self.bs is not None:
			self.backend.loop.create_task(_delete_oims(self.backend, self.bs.user.uuid, delivered))

	def deliver_oim_now(self, oim: OIM) -> None:
		# an offline message stored while this client was on (it signed on invisible, say) goes straight to it
		sender = _oim_sender(self.backend, oim)
		uin = uin_of(sender) if sender is not None else None
		if uin is None or self.bs is None:
			return
		self.deliver_message(uin, MessageType.Text, (oim.message or '').replace('\r\n', '\n').replace('\n', '\r\n'))
		self.backend.loop.create_task(_delete_oims(self.backend, self.bs.user.uuid, [oim.uuid]))

	# white pages, the old way

	def _search_uin(self, header: 'Header', data: bytes) -> None:
		# V1/V2: u16 search id, u32 UIN; later versions just the UIN
		self.ack(header)
		reader = Reader(data)
		try:
			search_id = reader.u16() if self.is_old() else 0
			uin = reader.u32()
		except ValueError:
			self._search_done(header, 0)
			return
		user = directory.find(self.backend, uin)
		if user is not None:
			self._search_found(header, search_id, user)
		self._search_done(header, search_id)

	def _search_user(self, header: 'Header', data: bytes) -> None:
		# V1/V2: u16 search id, nick, first, last, e-mail; the later versions' layout of it isn't known, so they're told
		# nothing was found
		self.ack(header)
		if not self.is_old():
			self._search_done(header, 0)
			return
		reader = Reader(data)
		try:
			search_id = reader.u16()
			nick, first, last, email = reader.string(), reader.string(), reader.string(), reader.string()
		except ValueError:
			self._search_done(header, 0)
			return
		for user in directory.search(self.backend, email = email, first = first, last = last, nick = nick):
			self._search_found(header, search_id, user)
		self._search_done(header, search_id)

	def _direct_search_name(self, header: 'Header', data: bytes) -> None:
		self.ack(header)
		reader = Reader(data)
		try:
			nick, first, last = reader.string(), reader.string(), reader.string()
		except ValueError:
			self._search_done(header, 0)
			return
		for user in directory.search(self.backend, nick = nick, first = first, last = last):
			self._search_found(header, 0, user)
		self._search_done(header, 0)

	def _direct_search_uin(self, header: 'Header', data: bytes) -> None:
		self.ack(header)
		user = directory.find(self.backend, struct.unpack_from('<L', data)[0]) if len(data) >= 4 else None
		if user is not None:
			self._search_found(header, 0, user)
		self._search_done(header, 0)

	def _direct_search_email(self, header: 'Header', data: bytes) -> None:
		self.ack(header)
		try:
			email = Reader(data).string()
		except ValueError:
			email = ''
		for user in directory.search(self.backend, email = email):
			self._search_found(header, 0, user)
		self._search_done(header, 0)

	def _direct_search_white(self, header: 'Header', data: bytes) -> None:
		self.ack(header)
		reader = Reader(data)
		try:
			first, last, nick, email = reader.string(), reader.string(), reader.string(), reader.string()
		except ValueError:
			self._search_done(header, 0)
			return
		for user in directory.search(self.backend, email = email, first = first, last = last, nick = nick):
			self._search_found(header, 0, user)
		self._search_done(header, 0)

	def _old_record(self, info: dict[str, Any]) -> LE:
		# u32 UIN, nick, first, last, e-mail, u8 auth (1: required), trimmed to what the old clients' buffers take
		record = LE().u32(info['uin']).string(info['nick'], MAX_NICK).string(info['first'], MAX_NAME).string(info['last'], MAX_NAME)
		return record.string(info['email'], MAX_NAME).u8(OLD_AUTH_REQUIRED if info['auth_required'] else 0)

	def _search_found(self, header: 'Header', search_id: int, user: User) -> None:
		# SRV_SEARCH_FOUND: (V1/V2) u16 search id, the record, (V5) a trailing zero byte
		record = self._old_record(directory.profile(user, self.user))
		if self.is_old():
			self.send(Server.SearchFound, LE().u16(search_id).raw(record.bytes()).bytes())
		elif self.version == Version.V5:
			self.send(Server.SearchFound, record.u8(0).bytes(), seq2 = header.seq2)
		else:
			self.send(Server.SearchFound, record.bytes(), seq2 = header.seq2)

	def _search_done(self, header: 'Header', search_id: int) -> None:
		# SRV_SEARCH_DONE: (V1/V2) u16 search id, u8 more (never: all hits went out)
		if self.is_old():
			self.send(Server.SearchDone, LE().u16(search_id).u8(0).bytes())
		else:
			self.send(Server.SearchDone, LE().u8(0).bytes(), seq2 = header.seq2)

	def _info(self, header: 'Header', data: bytes) -> None:
		# CMD_INFO_REQ (and V3/V4's CMD_USER_GET_INFO): V1/V2 send u16 request id, u32 UIN; the rest just the UIN
		self.ack(header)
		reader = Reader(data)
		try:
			request_id = reader.u16() if self.is_old() else 0
			uin = reader.u32()
		except ValueError:
			return
		user = directory.find(self.backend, uin)
		if user is None and self.version == Version.V5:
			self.send(Server.InvalidUin, LE().u32(uin).bytes())
			return
		# the older clients get a bare entry for a UIN nobody has
		info = directory.profile(user, self.user) if user is not None else directory.unknown_profile(uin)
		names = LE().string(info['nick'], MAX_NICK).string(info['first'], MAX_NAME).string(info['last'], MAX_NAME).string(info['email'], MAX_NAME)
		auth = OLD_AUTH_REQUIRED if info['auth_required'] else 0
		if self.is_old():
			# SRV_INFO_REPLY: u16 request id, u32 UIN, nick, first, last, e-mail, u8 auth, two zero words
			body = LE().u16(request_id).u32(uin).raw(names.bytes()).u8(auth).u16(0).u16(0)
			self.send(Server.InfoReply, body.bytes())
		elif self.version == Version.V5:
			# u32 UIN, nick, first, last, e-mail, u8 auth
			self.send(Server.InfoReply, LE().u32(uin).raw(names.bytes()).u8(auth).bytes())
		else:
			# V3/V4: u32 UIN, nick, first, last, e-mail, u8 status, u8 auth
			self.send(Server.InfoReply, LE().u32(uin).raw(names.bytes()).u8(0).u8(auth).bytes(), seq2 = header.seq2)

	def _ext_info(self, header: 'Header', data: bytes) -> None:
		# CMD_EXT_INFO_REQ: the same request as CMD_INFO_REQ
		self.ack(header)
		reader = Reader(data)
		try:
			request_id = reader.u16() if self.is_old() else 0
			uin = reader.u32()
		except ValueError:
			return
		user = directory.find(self.backend, uin)
		if user is None and self.version == Version.V5:
			self.send(Server.InvalidUin, LE().u32(uin).bytes())
			return
		info = directory.profile(user, self.user) if user is not None else directory.unknown_profile(uin)
		body = LE()
		if self.is_old():
			# u16 request id, u32 UIN, city, u16 country, u8 country status, state, u16 age, u8 gender, phone, homepage, about
			body.u16(request_id).u32(uin).string(info['city'], MAX_NAME).u16(info['country']).u8(0)
		else:
			# u32 UIN, city, u16 country, u8 time zone, state, u16 age, u8 gender, phone, homepage, about, u32 ZIP
			body.u32(uin).string(info['city'], MAX_NAME).u16(info['country']).u8(info['gmt'])
		body.string(info['state'], MAX_NAME).u16(info['age']).u8(info['gender']).string(info['phone'], MAX_PHONE)
		body.string(info['homepage'], MAX_HOMEPAGE).string(info['notes'], MAX_ABOUT)
		if self.is_old():
			self.send(Server.ExtInfoReply, body.bytes())
		elif self.version == Version.V5:
			self.send(Server.ExtInfoReply, body.u32(info['zip_number']).bytes())
		else:
			self.send(Server.ExtInfoReply, body.u32(info['zip_number']).bytes(), seq2 = header.seq2)

	# profile changes, the old way

	def set_nickname(self, nick: str) -> None:
		# the ICQ nickname is what other people see this account as, which elsewhere is its friendly name
		if nick and self.bs is not None and nick != self.user.status.name:
			self.bs.me_update({ 'name': nick })

	def _update_basic(self, header: 'Header', data: bytes) -> None:
		# V1/V2: u16 update id, nick, first, last, e-mail, u8 auth (1: required); V4 the same without the id; V3 without
		# the auth byte either
		self.ack(header)
		reader = Reader(data)
		try:
			update_id = reader.u16() if self.is_old() else 0
			nick, first, last, email = reader.string(), reader.string(), reader.string(), reader.string()
			# (V1/V2 only take the auth byte from CMD_UPDATE_BASIC)
			takes_auth = self.version == Version.V4 or (self.is_old() and header.command == Command.UpdateBasic)
			auth = reader.u8() if reader.remaining() and takes_auth else None
		except ValueError:
			if self.is_old():
				self.send(Server.UpdateBasicFail, LE().u16(0).bytes())
			return
		if self.bs is None:
			return
		self.set_nickname(nick)
		icq.set_basic(self.user, { 'nick': nick, 'first': first, 'last': last, 'email': email })
		if auth is not None:
			icq.set_permissions(self.user, auth_required = auth == OLD_AUTH_REQUIRED)
		icq.save(self.backend, self.user)
		if self.is_old():
			reply = Server.UpdatedBasic if header.command == Command.UpdateBasic else Server.UpdatedBasicV4
			self.send(reply, LE().u16(update_id).bytes())
		else:
			self.send(Server.UpdatedBasicV4, seq2 = header.seq2)

	def _update_detail(self, header: 'Header', data: bytes) -> None:
		# (V1/V2: u16 update id), city, u16 country, u8 country status or time zone, state, u16 age (worked out from the
		# birth date instead), u8 gender, phone, homepage, about
		self.ack(header)
		reader = Reader(data)
		try:
			update_id = reader.u16() if self.is_old() else 0
			city = reader.string()
			country = reader.u16()
			zone = reader.u8()
			state = reader.string()
			reader.u16()
			gender = reader.u8()
			phone, homepage, about = reader.string(), reader.string(), reader.string()
		except ValueError:
			if self.is_old():
				self.send(Server.UpdateDetailFail, LE().u16(0).bytes())
			return
		if self.bs is None:
			return
		basic: dict[str, Any] = { 'city': city, 'country': country, 'state': state, 'phone': phone }
		if not self.is_old():
			basic['gmt'] = zone
		icq.set_basic(self.user, basic)
		icq.set_more(self.user, { 'gender': gender, 'homepage': homepage })
		if about:
			icq.set_notes(self.user, about)
		icq.save(self.backend, self.user)
		if self.is_old():
			self.send(Server.UpdatedDetail, LE().u16(update_id).bytes())
		else:
			self.send(Server.UpdatedDetail, seq2 = header.seq2)

	def _set_auth_v3(self, header: 'Header', data: bytes) -> None:
		# u8 authorization mode (anything but 0: required), answered with 0x01F4
		self.ack(header)
		if not data or self.bs is None:
			return
		icq.set_permissions(self.user, auth_required = data[0] != 0)
		icq.save(self.backend, self.user)
		self.send(0x01F4, seq2 = header.seq2)

	# the end

	def force_offline(self) -> None:
		# signed on somewhere else: SRV_SET_OFFLINE tells the client it's off, without the reconnect SRV_NOT_CONNECTED makes
		self.send(Server.SetOffline)
		self.close()

	def close(self) -> None:
		if self.closed:
			return
		self.closed = True
		self.server.remove(self)
		for cs, _ in list(self.chats.values()):
			cs.close()
		self.chats.clear()
		bs = self.bs
		if bs is not None and not bs.closed:
			bs.close()


def _oim_sender(backend: Any, oim: OIM) -> User | None:
	uuid = backend.util_get_uuid_from_username(oim.from_username) if oim.from_username else None
	if uuid is None and oim.from_email:
		uuid = backend.util_get_uuid_from_email(oim.from_email)
	return backend._load_user_record(uuid) if uuid is not None else None

async def _delete_oims(backend: Any, recipient_uuid: str, uuids: list[str]) -> None:
	# deleting is plain file work, done off the event loop
	loop = backend.loop
	for uuid in uuids:
		await loop.run_in_executor(None, backend.user_service.delete_oim, recipient_uuid, uuid)

def legacy_sessions(backend: Any, user: User) -> list[LegacyCtrl]:
	# the pre-OSCAR clients `user` is signed on with
	ctrls = []
	for bs in backend.util_get_sessions_by_user(user):
		ctrl = getattr(bs.evt, 'ctrl', None)
		if isinstance(ctrl, LegacyCtrl) and not ctrl.closed:
			ctrls.append(ctrl)
	return ctrls

def relay_icq_message(backend: Any, sender: User, target: User, msg_type: int, text: str) -> None:
	# a message only ICQ clients understand (chat/file requests, plugins...) goes to `target`'s ICQ clients as it is: a
	# pre-OSCAR client gets SRV_SYS_MSG_ONLINE, an OSCAR one a channel 4 ICBM
	uin = uin_of(sender)
	if uin is None:
		return
	for ctrl in legacy_sessions(backend, target):
		ctrl.deliver_message(uin, msg_type, text)
	from front.oscar.foodgroups.icbm import ICBMChannel, ICBMTag, build_icq_message, gen_cookie, relay_icbm
	from front.oscar.proto import names
	from front.oscar.proto.delivery import oscar_sessions
	from front.oscar.proto.tlv import TLV, marshal_tlvs
	sessions = [bs for bs in oscar_sessions(backend, target) if names.is_icq_session(bs)]
	if sessions:
		tlvs = marshal_tlvs([TLV(ICBMTag.Data, build_icq_message(uin, msg_type, 0x00, text))])
		relay_icbm(backend, sender, target, gen_cookie(), ICBMChannel.ICQ, tlvs, sessions = sessions)


# before there's a session: the registration wizard's questions, the pre-login password check, the login itself

def prelogin(server: 'ListenerICQ', header: 'Header', data: bytes, addr: Address) -> None:
	version = header.version
	command = header.command
	if command == Command.Ack:
		return
	if command == Command.Login or (version == Version.V1 and command == Command.GetDeps):
		login(server, header, data, addr)
		return
	if command == Command.GetDeps:
		_check_password(server, header, data, addr)
		return
	if command == Command.FirstLogin:
		if version == Version.V5:
			# the reply is an ACK carrying u8 0x0A, the u32 the client sent, u16 1
			session_id2 = struct.unpack_from('<L', data)[0] if len(data) >= 4 else 0
			_send_to(server, addr, header, Server.Ack, LE().u8(0x0A).u32(session_id2).u16(0x0001).bytes(), seq1 = header.seq1, seq2 = header.seq2)
		else:
			_prelogin_ack(server, header, addr)
			if version == Version.V4:
				_send_register_info(server, header, addr)
		return
	if command == Command.RegRequestInfo and version == Version.V4:
		_prelogin_ack(server, header, addr)
		_send_register_info(server, header, addr)
		return
	if command in (Command.RegNewUser, Command.RegNewUserInfo):
		# accounts are only made on the website
		_prelogin_ack(server, header, addr)
		return
	# anything else from someone who isn't signed on: SRV_NOT_CONNECTED, so the client signs on again
	if version == Version.V5:
		_send_to(server, addr, header, Server.NotConnected, seq1 = header.seq1, seq2 = header.seq2)
	elif version in (Version.V3, Version.V4):
		_send_to(server, addr, header, Server.NotConnected, seq1 = 0, seq2 = header.seq2)
	else:
		_send_to(server, addr, header, Server.NotConnected, seq1 = header.seq1)

def _send_to(
	server: 'ListenerICQ', addr: Address, header: 'Header', command: int, data: bytes = b'', *,
	seq1: int = 0, seq2: int = 0, version: int | None = None,
) -> None:
	packet = wire.build(
		version if version is not None else header.version, command, data, seq1 = seq1, seq2 = seq2, uin = header.uin,
		session_id = header.session_id,
	)
	server.send(packet, addr)

def _prelogin_ack(server: 'ListenerICQ', header: 'Header', addr: Address) -> None:
	if header.version in (Version.V1, Version.V2):
		_send_to(server, addr, header, Server.Ack, seq1 = header.seq1)
	else:
		_send_to(server, addr, header, Server.Ack, seq1 = header.seq1, seq2 = header.seq2)

def _send_wrong_password(server: 'ListenerICQ', header: 'Header', addr: Address) -> None:
	if header.version == Version.V5 or header.version == Version.V3:
		_send_to(server, addr, header, Server.WrongPassword, seq1 = 0, seq2 = header.seq2)
	elif header.version == Version.V4:
		_send_to(server, addr, header, Server.WrongPassword, seq1 = header.seq1, seq2 = header.seq2)
	else:
		_send_to(server, addr, header, Server.WrongPassword, seq1 = header.seq1)

def _send_register_info(server: 'ListenerICQ', header: 'Header', addr: Address) -> None:
	# SRV_REGISTER_INFO (the registration wizard's admin notes): u16 length and the notes with their NUL, u8 registration
	# enabled (not here), u16 2, u16 0x2A
	notes = icq.latin1(REGISTRATION_NOTES) + b'\x00'
	data = LE().u16(len(notes)).raw(notes).u8(0x00).u16(0x0002).u16(0x002A).bytes()
	_send_to(server, addr, header, 0x037A, data, seq1 = 0, seq2 = header.seq2)

def _check_password(server: 'ListenerICQ', header: 'Header', data: bytes, addr: Address) -> None:
	# CMD_GET_DEPS: the password check the registration wizard (and older clients) make before signing on, answered with
	# the (empty) departments list
	version = header.version
	reader = Reader(data)
	try:
		if version == Version.V2:
			uin = header.uin
		else:
			uin = reader.u32()
		password = icq.from_latin1(reader.raw_string())
	except ValueError:
		_send_wrong_password(server, header, addr)
		return
	if uin <= 0 or server.backend.user_service.login_with_uin(uin, password) is None:
		_send_wrong_password(server, header, addr)
		return
	if version == Version.V5:
		_prelogin_ack(server, header, addr)
		server.send(struct.pack('<HHHHLL', Version.V3, Server.DepsList, 0, header.seq2, uin, V5_DEPS_LIST_CHECK), addr)
	elif version in (Version.V3, Version.V4):
		# u32 deps list version, u32 count (none), u16 2, u16 0x2A
		_prelogin_ack(server, header, addr)
		deps = LE().u32(1).u32(0).u16(0x0002).u16(0x002A).bytes()
		packet = wire.build(version, Server.DepsList, deps, seq1 = 0, seq2 = header.seq2, uin = uin)
		server.send(packet, addr)
		# the login reply then takes the next server sequence number
		server.note_preauth(addr)
	else:
		# V2: a V2 ACK, then the deps list as the wizard reads it: u16 connection id (the check's seq2), u32 UIN
		_send_to(server, addr, header, Server.Ack, seq1 = header.seq1)
		_send_to(server, addr, header, Server.DepsList, LE().u16(header.seq2).u32(uin).bytes(), seq1 = header.seq1)

def login(server: 'ListenerICQ', header: 'Header', data: bytes, addr: Address) -> None:
	# CMD_LOGIN: acknowledged straight away (V3-V5), then answered with SRV_HELLO or SRV_WRONG_PASSWORD
	from .events import BackendEventHandler
	version = header.version
	if version not in (Version.V1, Version.V2):
		_prelogin_ack(server, header, addr)
	request = parse_login(version, data)
	if request is not None and version == Version.V1:
		# V1's reply echoes the login packet's own sequence number
		request.login_seq = header.seq1
	uuid = None
	if request is not None and header.uin > 0:
		uuid = server.backend.user_service.login_with_uin(header.uin, request.password)
	if request is None or uuid is None:
		_send_wrong_password(server, header, addr)
		return
	# a client signing on again from where it was (after a crash, say) replaces its own earlier session quietly; one
	# somewhere else is told it's off, like sessions on the other frontends are booted
	existing = server.by_uin.get(header.uin)
	if existing is not None:
		if existing.addr == addr:
			existing.close()
		else:
			existing.force_offline()
	ctrl = LegacyCtrl(server, addr, version, header.uin, header.session_id)
	if server.take_preauth(addr) and version == Version.V4:
		ctrl.seq = 1
	evt = BackendEventHandler(ctrl)
	bs = server.backend.login(uuid, Client('icq', 'V{}'.format(version), 'direct'), evt, option = LoginOption.BootOthers)
	if bs is None:
		_send_wrong_password(server, header, addr)
		return
	ctrl.bs = bs
	server.add(ctrl)
	if version in (Version.V1, Version.V2):
		ctrl.send(Server.Ack, seq1 = header.seq1)
	ctrl.send_login_reply(header, request)
	ctrl.signed_on(request)
