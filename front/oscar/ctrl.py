import asyncio
import random
import struct
import time

from core import error
from core.backend import Backend, BackendSession, Chat, ChatSession
from core.client import Client
from core.models import LoginOption, ContactList, User, _is_blocking
from itertools import cycle
from typing import Any, Dict, Optional, Callable, Tuple, List
from util.icq import from_latin1
from util.misc import Logger, is_valid_oscar_screenname

from .proto import names
from .proto.backend import (
	BackendEventHandler, FOODGROUP_VERSIONS, SERVICE_FOODGROUPS, SERVICE_BOS, login, LoginError, bos_cookies, take_cookie,
)
from .proto.buffer import Buffer
from .proto.chat import ChatEventHandler
from .proto.snac import OSCARClient, OSCARContext, SNACMessage, foodgroups
from .proto.tlv import TLV, marshal_tlvs, unmarshal_tlvs, find_tlv


ROASTING_CHARS = b'\xF3\x26\x81\xC4\x39\x86\xDB\x92\x71\xA3\xB9\xE6\x53\x7A\x95\x7C'


def roast(password: bytes) -> bytes:
	chars = cycle(ROASTING_CHARS)
	return bytes(byte ^ next(chars) for byte in password)


def client_version(tlvs: List[TLV]) -> str:
	# the login request's client major/minor/build TLVs (0x17, 0x18, 0x1A), as "major.minor.build"
	parts = []
	for tag in (0x0017, 0x0018, 0x001A):
		tlv = find_tlv(tlvs, tag)
		parts.append(struct.unpack('>H', tlv.data[:2])[0] if tlv is not None and len(tlv.data) >= 2 else 0)
	return '{}.{}.{}'.format(*parts)

def multi_conn_flag(tlvs: List[TLV]) -> Optional[int]:
	# TLV 0x4A: a client that sends it knows about multiple sessions and takes a signoff frame with a reason in it
	tlv = find_tlv(tlvs, 0x004A)
	return tlv.data[0] if tlv is not None and tlv.data else None

def authenticate(backend: Backend, screen_name: str, check: Callable[[str], bool]) -> Tuple[Optional[str], bool, Optional[int]]:
	# a login name may be a screen name or a UIN; every account it could mean is tried, so a numeric screen name and
	# somebody else's UIN can both still sign on. returns the account, whether it signed on by UIN, and an error code
	candidates = backend.util_get_uuids_for_login(screen_name) if names.valid_name(screen_name) else []
	icq_name = names.is_uin(screen_name.replace(' ', ''))
	if not candidates:
		return None, icq_name, (LoginError.ICQUserError if icq_name else LoginError.UnregisteredScreenname)
	for uuid in candidates:
		if not check(uuid):
			continue
		user = backend._load_user_record(uuid)
		icq = icq_name and user is not None and names.uin_of(user) == int(screen_name.replace(' ', ''))
		return uuid, icq, None
	return candidates[0], icq_name, LoginError.IncorrectPassword


# TODO(subpurple): as the foodgroups are no longer handled just in this file, might want to combine this and entry
class OSCARCtrl:
	logger: Logger
	transport: Optional[asyncio.WriteTransport]

	close_callback: Optional[Callable[[], None]]
	closed: bool

	backend: Backend
	bs: Optional[BackendSession]

	client: Client

	oscarClient: OSCARClient
	context: OSCARContext
	sequence: int

	# a service connection (BART, chat, ...) borrows the BOS connection's session instead of having one of its own
	is_service: bool
	service: int
	room: Optional[Any]
	multi_conn: Optional[int]
	versions: Dict[int, int]

	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		self.logger = logger
		self.transport = None

		self.close_callback = None
		self.closed = False

		self.backend = backend
		self.bs = None
		self.client = Client('aim', '?', via)

		self.context = OSCARContext(self.backend, self.client)
		self.oscarClient = OSCARClient(self)

		# FLAP sequence numbers start at a random value, per connection
		self.sequence = random.randint(0x0000, 0xFFFF)
		self.is_service = False
		self.service = SERVICE_BOS
		self.room = None
		self.multi_conn = None
		# what the client said it speaks (OSERVICE__CLIENT_VERSIONS), per connection
		self.versions = {}

	def send_specific_frame(self, frame: int, data: bytes) -> None:
		if self.transport is None or self.transport.is_closing():
			return

		if self.sequence == 0xFFFF:
			self.sequence = 0x0000
		else:
			self.sequence += 1

		packet = b''.join([
			struct.pack('>BBHH', 0x2A, frame, self.sequence, len(data)),
			data
		])

		self.transport.write(packet)

	def send_snac(self, msg: SNACMessage) -> None:
		self.send_specific_frame(0x02, msg.marshal())

	def send_snac_error(self, foodgroup: int, request_id: int, code: int, subcode: Optional[int] = None) -> None:
		# SNAC(xx,01): u16 error code, then TLV 0x08 with a foodgroup specific subcode when there is one
		msg = SNACMessage(foodgroup, 0x0001, 0x0000, request_id)
		msg.write_u16(code)
		if subcode is not None:
			msg.write_tlv(TLV(0x0008, struct.pack('>H', subcode)))
		self.send_snac(msg)

	def signoff(self, reason: Optional[int] = None) -> None:
		# clients that never sent TLV 0x4A only know a bare signoff header (no length field); newer ones take a reason
		if self.transport is None or self.transport.is_closing():
			return
		if self.multi_conn is None or reason is None:
			self.sequence = (self.sequence + 1) & 0xFFFF
			self.transport.write(struct.pack('>BBH', 0x2A, 0x04, self.sequence))
			return
		self.send_specific_frame(0x04, marshal_tlvs([
			TLV(0x0009, struct.pack('>H', reason)),
			TLV(0x000B, 'https://crosstalk.im/'),
		]))

	def on_connect(self) -> None:
		self.send_specific_frame(0x01, struct.pack('>L', 1))

	def on_signon_frame(self, data: bytes) -> None:
		if len(data) > 4:
			tlvs = unmarshal_tlvs(data[4:])

			if (cookie_tlv := find_tlv(tlvs, 0x0006)) is not None:
				found = False
				is_service_connection = False

				entry = take_cookie(cookie_tlv.data)
				if entry is not None and (entry.bs is None or not entry.bs.closed):
					self.logger.info('found BOS cookie')
					self.multi_conn = entry.multi_conn

					if entry.bs is not None:
						# cookie maps to an existing BackendSession (placed there by OSERVICE__SERVICE_REQUEST)
						# reuse it directly so the main session is not booted and its substatus is preserved
						self.context.bs = entry.bs
						self.context.user = entry.bs.user
						self.client = entry.bs.client
						self.context.client = self.client
						self.bs = entry.bs
						self.is_service = True
						self.service = entry.service
						self.room = entry.room
						is_service_connection = True
						entry.bs.front_data.setdefault('oscar0_services', set()).add(self)
						found = True
					else:
						self.client = Client(entry.program, entry.version, self.client.via)
						self.context.client = self.client

						self.context.bs = self.backend.login(entry.uuid,
														 self.client,
														 BackendEventHandler(self),
														 option=LoginOption.BootOthers)
						if self.context.bs is not None:
							self.context.user = self.context.bs.user
							self.bs = self.context.bs
							found = True

				if found:
					# NINA also sends OSERVICE__WELL_KNOWN_URLS right after (should we?)
					self.logger.info('[Server] OSERVICE__HOST_ONLINE')

					msg = SNACMessage(0x0001, 0x0003)

					for foodgroup in SERVICE_FOODGROUPS.get(self.service, SERVICE_FOODGROUPS[SERVICE_BOS]):
						msg.write_u16(foodgroup)

					self.send_snac(msg)

					if not is_service_connection:
						# only initialize these keys on the primary BOS connection
						# so other service connections don't wipe the chat state built up so far
						self.bs.front_data['oscar0'] = True
						self.bs.front_data['oscar0_chats'] = {}
						self.bs.front_data['oscar0_signon'] = int(time.time())
						self.bs.front_data['oscar0_sn'] = entry.screen_name or self.bs.user.username
						self.bs.front_data['oscar0_icq'] = entry.icq
						self.bs.front_data['oscar0_client_id'] = entry.client_id
				else:
					self.logger.info('invalid BOS cookie given')
					self.close()

			elif find_tlv(tlvs, 0x0001) is not None:
				self.logger.info('Using FLAP-level authentication')

				screen_name_tlv = find_tlv(tlvs, 0x0001)
				roasted_pw_tlv = find_tlv(tlvs, 0x0002)

				screen_name = screen_name_tlv.data.decode('latin-1')
				roasted_pw = roasted_pw_tlv.data if roasted_pw_tlv is not None else b''

				self.logger.info('Screen Name (client-given):', screen_name)
				self.logger.info('Password (roasted):', roasted_pw.hex())

				context = self.context
				version = client_version(tlvs)
				password = from_latin1(roast(roasted_pw))

				uuid, icq, error_code = authenticate(
					context.backend, screen_name, lambda uuid: context.backend.user_service.login_with_uuid(uuid, password) is not None,
				)
				if error_code in (LoginError.UnregisteredScreenname, LoginError.ICQUserError):
					self.logger.info('Unregistered screenname')
				elif error_code == LoginError.IncorrectPassword:
					self.logger.info('Incorrect password')

				self.client = Client('icq' if icq else 'aim', version, self.client.via)
				context.client = self.client
				self.send_specific_frame(0x04, login(
					self.logger, self.context, tlvs, uuid, error_code, icq = icq, multi_conn = multi_conn_flag(tlvs),
				))

	def on_data_frame(self, message: SNACMessage) -> None:
		found = False

		# kick client off if we haven't authenticated and client is trying to access something outside of BUCP
		if message.foodgroup != 0x0017 and self.bs is None:
			self.close()
			return

		for value, cls in foodgroups.items():
			if value == message.foodgroup:
				# the foodgroup handlers are shared, so they log through whichever connection the SNAC came in on
				cls.logger = self.logger

				if message.subgroup in cls.subgroups:
					found = True

					func = cls.subgroups[message.subgroup]
					try:
						func(cls, self.oscarClient, self.context, message)
					except Exception as ex:
						self.logger.error(ex)

		if not found:
			self.logger.info(f'[Client] Unknown SNAC({hex(message.foodgroup)},{hex(message.subgroup)})')
			self.logger.info('[Client]', message.data.hex())
			# an unanswered request leaves the client waiting on it, so it gets told the SNAC isn't one we know
			if message.subgroup != 0x0001:
				self.send_snac_error(message.foodgroup, message.request_id, 0x0001)

	def on_error_frame(self, data: bytes) -> None:
		self.logger.info('[Client] Recieved error frame with:', data.hex())

	def on_signoff_frame(self, data: bytes) -> None:
		self.logger.info('[Client] Recieved signoff frame')
		self.close()

	def close(self) -> None:
		if self.closed:
			return
		self.closed = True

		if self.close_callback:
			self.close_callback()

		if self.room is not None:
			from .foodgroups.chat import leave_room
			leave_room(self)

		if self.bs:
			if self.is_service:
				# a service connection going away leaves the session it borrowed alone
				self.bs.front_data.get('oscar0_services', set()).discard(self)
			else:
				for service_ctrl in list(self.bs.front_data.get('oscar0_services', ())):
					service_ctrl.close()
				self.bs.close()

	def _temp_permitted(self, target: User, sender: User) -> bool:
		# PD__ADD_TEMP_PERMIT_LIST_ENTRIES lets a name bypass the target's permit/deny settings for as long as their session lasts
		for bs_target in self.backend.util_get_sessions_by_user(target):
			if sender.uuid in bs_target.front_data.get('oscar0_temp_permits', ()):
				return True
		return False

	def _get_private_chat_with(self, other_user_uuid: str) -> Tuple[ChatSession, 'ChatEventHandler']:
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None

		other_user = self.backend._load_user_record(other_user_uuid)
		if other_user is None or not names.representable(other_user):
			raise error.ContactNotOnContactList()
		other_user_ctc = detail.contacts.get(other_user.uuid)
		if other_user_ctc is not None and other_user_ctc.lists & ContactList.BL:
			raise error.ContactNotOnContactList()
		chats = bs.front_data.setdefault('oscar0_chats', {})
		# a chat whose other side has gone (they signed off, or picked up a newer one) can't carry anything any more
		existing = chats.get(other_user_uuid)
		if existing is not None and existing[0].closed:
			del chats[other_user_uuid]
		if other_user_uuid not in chats:
			other_user_detail = self.backend._load_detail(other_user)
			if other_user_detail is None: raise error.ContactNotOnline()
			ctc_self = other_user_detail.contacts.get(user.uuid)
			if ctc_self is not None:
				if ctc_self.lists & ContactList.BL: raise error.ContactNotOnline()
			# the target's permit/deny mode decides whether we may reach them at all, unless we hold a temp permit
			if other_user.detail is not None and _is_blocking(other_user, user) and not self._temp_permitted(other_user, user):
				raise error.ContactNotOnline()
			chat = self.backend.chat_create()
			chat.front_data['oscar0'] = True

			# `user` joins
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('icbm', bs, evt)
			try:
				cs.invite(other_user)
			except error.ClientError:
				cs.close()
				raise
			chats[other_user_uuid] = (cs, evt)
		elif other_user.status.is_offlineish():
			raise error.ContactNotOnline()
		return chats.get(other_user_uuid)
