import asyncio
import random
import struct

from core import error
from core.backend import Backend, BackendSession, Chat, ChatSession
from core.client import Client
from core.models import LoginOption, ContactList
from itertools import cycle
from typing import Optional, Callable, Tuple
from util.misc import Logger

from .proto.backend import BackendEventHandler, FOODGROUP_VERSIONS, login, LoginError, bos_cookies
from .proto.chat import ChatEventHandler
from .proto.snac import OSCARClient, OSCARContext, SNACMessage, foodgroups
from .proto.tlv import unmarshal_tlvs, find_tlv


ROASTING_CHARS = b'\xF3\x26\x81\xC4\x39\x86\xDB\x92\x71\xA3\xB9\xE6\x53\x7A\x95\x7C'


def roast(password: bytes) -> bytes:
	chars = cycle(ROASTING_CHARS)
	return bytes(byte ^ next(chars) for byte in password)


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
	sequence: int = random.randint(0x0000, 0xFFFF)

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

	def send_specific_frame(self, frame: int, data: bytes) -> None:
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

	def on_connect(self) -> None:
		self.send_specific_frame(0x01, struct.pack('>L', 1))

	def on_signon_frame(self, data: bytes) -> None:
		if len(data) > 4:
			tlvs = unmarshal_tlvs(data[4:])

			if (cookie_tlv := find_tlv(tlvs, 0x0006)) is not None:
				found = False
				is_service_connection = False

				for i, d in enumerate(bos_cookies):
					for cookie in d.items():
						if cookie[0] == cookie_tlv.data:
							self.logger.info('found BOS cookie')

							if hasattr(cookie[1], 'user') and getattr(cookie[1].user, 'uuid', None) is not None:
								# cookie maps to an existing BackendSession (placed there by OSERVICE__SERVICE_REQUEST)
								# reuse it directly so the main session is not booted and its substatus is preserved
								self.context.bs = cookie[1]
								self.context.user = cookie[1].user
								self.bs = cookie[1]
								is_service_connection = True
							else:
								if isinstance(cookie[1], dict):
									uuid = cookie[1].get('uuid')
									version = cookie[1].get('version', '?')
									self.client = Client('aim', version, self.client.via)
									self.context.client = self.client
								elif getattr(cookie[1], 'uuid', None) is not None:
									uuid = cookie[1].uuid
								else:
									uuid = cookie[1]

								self.context.bs = self.backend.login(uuid,
																 self.client,
																 BackendEventHandler(self),
																 option=LoginOption.BootOthers)
								self.context.user = self.context.bs.user
								self.bs = self.context.bs

							bos_cookies.pop(i)
							found = True
							break
					if found:
						break

				if found:
					# NINA also sends OSERVICE__WELL_KNOWN_URLS right after (should we?)
					self.logger.info('[Server] OSERVICE__HOST_ONLINE')

					msg = SNACMessage(0x0001, 0x0003)

					for foodgroup in FOODGROUP_VERSIONS.keys():
						msg.write_u16(foodgroup)

					self.send_snac(msg)

					if not is_service_connection:
						# only initialize these keys on the primary BOS connection
						# so other service connections don't wipe the chat state built up so far
						self.bs.front_data['oscar0'] = True
						self.bs.front_data['oscar0_chats'] = {}
				else:
					self.logger.info('invalid BOS cookie given')

			else:
				self.logger.info('Using FLAP-level authentication')

				screen_name_tlv = find_tlv(tlvs, 0x0001)
				roasted_pw_tlv = find_tlv(tlvs, 0x0002)

				screen_name = screen_name_tlv.data.decode()
				roasted_pw = roasted_pw_tlv.data

				self.logger.info('Screen Name (client-given):', screen_name)
				self.logger.info('Password (roasted):', roasted_pw.hex())

				context = self.context
				error_code = None

				if (uuid := context.backend.util_get_uuid_from_username(screen_name)) is None:
					error_code = LoginError.UnregisteredScreenname

					self.logger.info('Unregistered screenname')
				else:
					unroasted_pw = roast(roasted_pw)

					if context.backend.user_service.login_with_username(screen_name, unroasted_pw.decode()) is None:
						error_code = LoginError.IncorrectPassword

						self.logger.info('Incorrect password')

				self.bs.front_data['oscar0'] = True
				self.bs.front_data['oscar0_chats'] = {}
				self.send_specific_frame(0x04, login(self.logger, self.context, tlvs, uuid, error_code))

	def on_data_frame(self, message: SNACMessage) -> None:
		found = False

		# kick client off if we haven't authenticated and client is trying to access something outside of BUCP
		if message.foodgroup != 0x0017 and self.bs is None:
			self.close()
			return

		for value, cls in foodgroups.items():
			if value == message.foodgroup:
				if not hasattr(cls, 'logger'):
					cls.logger = self.logger

				if message.subgroup in cls.subgroups:
					found = True

					func = cls.subgroups[message.subgroup]
					func(cls, self.oscarClient, self.context, message)

		if not found:
			self.logger.info(f'[Client] Unknown SNAC({hex(message.foodgroup)},{hex(message.subgroup)})')
			self.logger.info('[Client]', message.data.hex())

	def on_error_frame(self, data: bytes) -> None:
		self.logger.info('[Client] Recieved error frame with:', data.hex())

	def on_signoff_frame(self, data: bytes) -> None:
		self.logger.info('[Client] Recieved signoff frame')

	def close(self) -> None:
		if self.closed:
			return
		self.closed = True

		if self.close_callback:
			self.close_callback()

		if self.bs:
			self.bs.close()

	def _get_private_chat_with(self, other_user_uuid: str) -> Tuple[ChatSession, 'ChatEventHandler']:
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		other_user = self.backend._load_user_record(other_user_uuid)
		if other_user is None:
			raise error.ContactNotOnContactList()
		other_user_ctc = detail.contacts.get(other_user.uuid)
		if other_user_ctc is not None and other_user_ctc.lists & ContactList.BL:
			raise error.ContactNotOnContactList()
		if other_user_uuid not in bs.front_data['oscar0_chats']:
			other_user_detail = self.backend._load_detail(other_user)
			if other_user_detail is None: raise error.ContactNotOnline()
			ctc_self = other_user_detail.contacts.get(user.uuid)
			if ctc_self is not None:
				if ctc_self.lists & ContactList.BL: raise error.ContactNotOnline()
			chat = self.backend.chat_create()
			chat.front_data['oscar0'] = True
			
			# `user` joins
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('icbm', bs, evt)
			bs.front_data['oscar0_chats'][other_user_uuid] = (cs, evt)
			cs.invite(other_user)
		elif other_user.status.is_offlineish():
			raise error.ContactNotOnline()
		return bs.front_data['oscar0_chats'].get(other_user_uuid)