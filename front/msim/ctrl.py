import asyncio
import base64
import io
import random
import secrets
import hashlib

from core import event
from core.backend import Backend, BackendSession, Chat
from core.client import Client
from core.models import LoginOption, Contact, Substatus, User, TextWithData, OIM, Circle, CircleRole, List
from settings import TARGET_HOST
from util.misc import Logger
from typing import Optional, Callable, Dict, Iterable, Any
from arc4 import ARC4

from .misc import get_grouped_contacts, unmarshal_msim_dict, CommandBitFlag, get_contact_groups

last_sesskey = 0


class MSIMCtrl:
	__slots__ = (
		'logger',
		'reader',
		'writer',
		'close_callback',
		'closed',
		'transport',
		'backend',
		'bs',
		'client',
		'nonce',
		'sesskey',
		'keep_alive_task'
	)

	# Escargot-specific
	logger: Logger
	reader: 'MSIMReader'
	writer: 'MSIMWriter'
	close_callback: Optional[Callable[[], None]]
	closed: bool
	transport: Optional[asyncio.WriteTransport]
	backend: Backend
	bs: Optional[BackendSession]
	client: Client

	# Frontend-specific
	nonce: bytes
	sesskey: int
	keep_alive_task: Optional[asyncio.Task]

	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		self.logger = logger
		self.reader = MSIMReader(logger)
		self.writer = MSIMWriter(logger)
		self.close_callback = None
		self.closed = False
		self.transport = None

		self.backend = backend
		self.bs = None
		self.client = Client('msim', '?', via)

		global last_sesskey
		last_sesskey += 1

		self.nonce = secrets.token_bytes(64)
		self.sesskey = last_sesskey
		self.keep_alive_task = None

	def _m_login2(self, data_pairs: Dict[str, str]) -> None:
		email = data_pairs['username']
		response = base64.b64decode(data_pairs['response'])
		clientver = data_pairs['clientver']

		valid = False

		# get nc1 & nc2 (first/last 0x20 bytes respectively)
		nc1, nc2 = self.nonce[:32], self.nonce[32:]

		# log what we got
		self.logger.info('Packet email:', email)
		self.logger.info('Packet response:', response)
		self.logger.info('Packet clientver:', clientver)

		if (uuid := self.backend.util_get_uuid_from_email(email)) is None:
			self.logger.info('E-mail not found!')
		else:
			# get our hashed password
			hashed_pwd = self.backend.user_service.msim_get_sha1_password(email)

			if hashed_pwd is None:
				self.logger.info('MySpaceIM frontend-specific password not found!')
			else:
				final_hash = hashlib.sha1(b''.join([hashed_pwd, nc2])).digest()
				rc4_key = final_hash[:16]	# we only need the first 128 bits of the result

				self.logger.info('Hashed password:', hashed_pwd.hex(' '))
				self.logger.info('Full hash:', final_hash.hex(' '))
				self.logger.info('RC4 key:', rc4_key.hex(' '))

				arc4 = ARC4(rc4_key)
				blob = arc4.decrypt(response)

				self.logger.info('RC4 blob data:', blob)

				seperator = blob.find(bytes(4))
				if seperator != -1:
					blob_nc1 = blob[:32]
					blob_email = blob[32:seperator]

					self.logger.info('nc1 (context):', nc1)
					self.logger.info('nc1 (request):', blob_nc1)
					self.logger.info('E-mail (blob):', blob_email)

					if nc1 == blob_nc1 and email == blob_email.decode():
						valid = True

		# allow user in if valid flag was set
		if valid:
			# set client to use `clientver`
			self.client = Client('msim', f'1.0.{clientver}.0', self.client.via)

			# set BackendSession
			self.bs = self.backend.login(uuid, self.client, BackendEventHandler(self), option=LoginOption.BootOthers)

			# log that they successfully signed in and send reply giving sesskey / user id / username / etc
			self.logger.info(email, "successfully signed-in!")
			self.send_reply({
				'lc': 2,
				'sesskey': self.sesskey,
				'proof': random.randint(0x00000, 0xFFFFF),
				'userid': self.bs.user.id,
				'profileid': self.bs.user.id,
				'uniquenick': self.bs.user.username,
				'id': 1
			})

			# start 180-second timer to send keep-alives periodically
			self.keep_alive_task = asyncio.create_task(self.send_keep_alive_periodically())
		else:
			self.send_reply({
				'error': True,
				'errmsg': 'The password provided is incorrect.',
				'err': 260,
				'fatal': True
			})
			self.close()

	def _m_persist(self, data_pairs: Dict[str, str]) -> None:
		bs = self.bs
		user = bs.user
		detail = user.detail

		# get cmd, dsn, lid (command type/family/subcode respectively)
		cmd = int(data_pairs['cmd'])	# i.e. 1 - Get, 2 - Action, 3 - Delete
		dsn = int(data_pairs['dsn'])
		lid = int(data_pairs['lid'])

		# get request/response ID
		rid = int(data_pairs['rid'])

		# get body
		body = data_pairs['body']

		def get_user_by_id(id: int) -> Optional[User]:
			if (uuid := self.backend.util_get_uuid_from_user_id(id)) is None:
				self.logger.info('User ID', id, 'not found!')
				self.send_persist_error(cmd, dsn, lid, rid, f'User ID {id} not found')
				return None

			found_user = self.backend._load_user_record(uuid)
			if found_user is None:
				self.logger.info('Unable to find uuid')
				self.send_persist_error(cmd, dsn, lid, rid, 'Unable to find uuid')
				return None

			return found_user

		match (cmd, dsn, lid):
			# 1;0;1 - list all contacts
			case (1, 0, 1):
				msim_contacts = []
				grouped_contacts = get_grouped_contacts(self.bs)
				pos = 0

				for group, contacts in grouped_contacts.items():
					for contact in contacts:
						head = contact.head

						pos += 1

						# For some reason, the MySpaceIM devs made it UNIX time in nano-seconds.
						# *Ahem* Kill me.
						last_login = int(head.date_login.timestamp() * 1e9)

						msim_contacts.append({
							'ContactID': head.id,
							'Headline': '?',		# Status
							'Position': pos,
							'GroupName': group,
							'Visibility': 1,
							'AvatarUrl': '',
							'ShowAvatar': False,	# No avatar yet xd
							'LastLogin': last_login,
							'IMName': head.username,
							'NickName': head.username,
							'NameSelect': 0,		# 0 = nickname, 1 = email, 2 = email address
							'OfflineMsg': '',
							'SkyStatus': 0
						})

				self.send_persist_reply(cmd, dsn, lid, rid, msim_contacts)

			# 1;2;6 - list all contact groups
			case (1, 2, 6):
				msim_groups = []
				id = 0

				for group in get_contact_groups(bs):
					id += 1

					msim_groups.append({
						'GroupID': id,
						'GroupName': group,
						'Position': id,
						'GroupFlag': 131073	 # unclear what GroupFlag does, TODO(subpurple): figure it out
					})

				# self.send_persist_reply(cmd, dsn, lid, rid, msim_groups)

			# 1;1;4 or 1;1;7 - look-up MySpaceIM-specific user info about yourself or by user ID
			#
			#   1;1;4 - should lookup self
			#   1;1;7 - should lookup by given user ID
			#	   - contains `UserID` field that 1;1;7 does not
			case (1, 1, 4) | (1, 1, 7):
				# default to our user id unless we are given a 1;1;4 persist message
				user_id = self.bs.user.id

				if lid == 7:
					body_dict = unmarshal_msim_dict(body)
					user_id = body_dict['UserID']

				if (user := get_user_by_id(user_id)) is None:
					pass

				self.send_persist_reply(cmd, dsn, lid, rid, {
					'UserID': user.id,
					'Sound': True,
					'!PrivacyMode': 0,		  # 0 = Anyone, 1 = Only people on my Contact List
					'!ShowOnlyToList': False,   # False = Anyone, True = Only people on my Contact List.
					'!OfflineMessageMode': 0,   # 0 = Everyone, 1 = Only people on my Contact List, 2 = No one.
					'Headline': '',
					'Avatarurl': '',
					'Alert': '',
					'!ShowAvatar': False,
					'IMName': '',			   # No real way to get this right now so default
					'!ClientVersion': 0,		# No real way to get this right now so default
					'!AllowBrowse': True,
					'IMLang': 'English',
					'LangID': 8192
				})

			# 1;4;3 or 1;4;5 - look-up MySpace user info by user ID
			#
			#   1;4;3 - should lookup by given user ID
			#   1;4;5 - should lookup self
			case (1, 4, 3) | (1, 4, 5):
				body_dict = unmarshal_msim_dict(body)
				user_id = body_dict['UserID']

				if (user := get_user_by_id(user_id)) is None:
					pass

				# Since CrossTalk doesn't have a social media platform unlike the original MySpaceIM platform, we simply
				# give default values to some of the keys here (e.g. BandName, SongName, Age, Gender, and Location).
				self.send_persist_reply(cmd, dsn, lid, rid, {
					'UserName': user.username,
					'Email': user.email,
					'UserID': user.id,
					'ImageURL': '',
					'DisplayName': user.username,
					'BandName': '',
					'SongName': '',
					'Age': 0,
					'Gender': 'M',
					'Location': '',
					'!TotalFriends': len(user.detail.contacts)
				})

			# 1;7;18 - query for social media (MySpace) notifications
			case (1, 7, 18):
				self.send_persist_reply(cmd, dsn, lid, rid, {
					# 'Mail': 'On',
					# 'BlogComment': 'Off',
					# 'ProfileComment': 'Off',
					# 'FriendRequest': 'Off',
					# 'PictureComment': 'Off'
				})

			# 1;6;11 - network hyperlink request
			case (1, 6, 11):
				# e.g. Target=now.FriendID=1
				#
				# i'm not certain what the appropriate URLs to `Target` would be, but for now we send
				# `TARGET_HOST`
				body_dict = unmarshal_msim_dict(body)
				target = body_dict['Target']

				self.logger.info('Target:', target)

				self.send_persist_reply(cmd, dsn, lid, rid, {
					'WebTicket': TARGET_HOST
				})

			# 514;0;9 (2^512;0;9) - update contact info
			case (514, 0, 9):
				self.logger.info('Update contact info')

			# 2;1;16 - undocumented
			#
			# however, based off of the command type (2 - reply), and client packet logs, it appears to be
			# update group info
			case (2, 2, 16):
				self.send_persist_reply(cmd, dsn, lid, rid, '')

			case _:
				self.logger.info(f'Unknown persist command: {cmd};{dsn};{lid}')

	def on_connect(self) -> None:
		self.send_reply({
			'lc': 1,
			'nc': self.nonce,
			'id': 1
		})

	def on_data_recieved(self, data: bytes, *, transport: Optional[asyncio.BaseTransport] = None) -> None:
		if transport is None:
			transport = self.transport

		assert transport is not None

		for m in self.reader.data_recieved(data):
			# get command, which is always the first key
			command = next(iter(m))

			# run `_m_xxx` where xxx is the command if found in class, otherwise log that we didn't find it
			try:
				f = getattr(self, f'_m_{command}')
				f(m)
			except AttributeError:
				self.logger.info('Invalid command:', command)

	def send_reply(self, data_pairs: Dict[str, int | str | bytes | bool]) -> None:
		self.writer.write(data_pairs)

		transport = self.transport
		if transport is not None:
			transport.write(self.flush())

	def send_persist_reply(self, cmd: int, dsn: int, lid: int, rid: int, body: Any) -> None:
		self.send_reply({
			'persistr': True,
			'uid': self.bs.user.id,
			'cmd': cmd ^ CommandBitFlag.CallbackReply,
			'dsn': dsn,
			'lid': lid,
			'rid': rid,
			'body': body
		})

	def send_persist_error(self, cmd: int, dsn: int, lid: int, rid: int, error_msg: str) -> None:
		self.send_reply({
			'persistr': True,
			'cmd': cmd ^ CommandBitFlag.CallbackError,
			'dsn': dsn,
			'uid': self.bs.user.id,
			'lid': lid,
			'rid': rid,
			'ErrorMessage': error_msg
		})

	async def send_keep_alive_periodically(self):
		while True:
			await asyncio.sleep(180)

			self.send_reply({
				'ka': True
			})

	def flush(self) -> bytes:
		return self.writer.flush()

	def close(self) -> None:
		if self.closed:
			return
		self.closed = True

		if self.close_callback:
			self.close_callback()
		if self.bs:
			self.bs.close()


class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('ctrl', 'bs')

	ctrl: MSIMCtrl

	def __init__(self, ctrl: MSIMCtrl) -> None:
		self.ctrl = ctrl

	def on_maintenance_message(self, *args: Any, **kwargs: Any) -> None:
		self.ctrl.logger.info('on_maintenance message')
		pass

	def on_maintenance_boot(self) -> None:
		self.ctrl.logger.info('on_maintenance_boot')
		pass

	def on_presence_notification(
			self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
			trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True,
			send_status_on_bl: bool = False, sess_id: Optional[int] = None,
			updated_phone_info: Optional[Dict[str, Any]] = None,
	) -> None:
		self.ctrl.logger.info('on_presence_notification')
		pass

	def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True,
									  update_info: bool = True) -> None:
		self.ctrl.logger.info('on_presence_self_notification')
		pass

	def on_chat_invite(
			self, chat: Chat, inviter: User, *, circle: bool = False, inviter_id: Optional[str] = None,
			invite_msg: str = '',
	) -> None:
		self.ctrl.logger.info('on_chat_invite')
		pass

	def on_declined_chat_invite(self, chat: Chat, circle: bool = False) -> None:
		self.ctrl.logger.info('on_declined_chat_invite')
		pass

	def on_added_me(self, user: User, *, adder_id: Optional[str] = None,
					message: Optional[TextWithData] = None) -> None:
		self.ctrl.logger.info('on_added_me')
		pass

	def on_removed_me(self, user: User) -> None:
		self.ctrl.logger.info('on_removed_me')
		pass

	def on_contact_request_denied(self, user_added: User, message: Optional[str], *,
								  contact_id: Optional[str] = None) -> None:
		self.ctrl.logger.info('on_contact_request_denied')
		pass

	def on_oim_sent(self, oim: OIM) -> None:
		self.ctrl.logger.info('on_oim_sent')
		pass

	def on_login_elsewhere(self, option: LoginOption) -> None:
		self.ctrl.logger.info('on_login_elsewhere')
		pass

	def on_circle_invite_revoked(self, chat_id: str) -> None:
		self.ctrl.logger.info('on_circle_invite_revoked')
		pass

	def on_accepted_circle_invite(self, circle: Circle) -> None:
		self.ctrl.logger.info('on_accepted_circle_invite')
		pass

	def on_circle_updated(self, circle: Circle) -> None:
		self.ctrl.logger.info('on_circle_updated')
		pass

	def on_left_circle(self, circle: Circle) -> None:
		self.ctrl.logger.info('on_left_circle')
		pass

	def on_circle_role_updated(self, chat_id: str, role: CircleRole) -> None:
		self.ctrl.logger.info('on_circle_role_updated')
		pass

	def on_circle_created(self, circle: Circle) -> None:
		self.ctrl.logger.info('on_circle_created')
		pass

	def on_close(self) -> None:
		self.ctrl.close()


class MSIMReader:
	__slots__ = ('_logger', '_buf')

	_logger: Logger
	_buf: bytes

	def __init__(self, logger: Logger) -> None:
		self._logger = logger
		self._buf = b''

	def data_recieved(self, data: bytes) -> Iterable[Dict[str, str]]:
		self._buf += data

		while self._buf:
			m = self._read()
			if m is None:
				break

			yield m

	def _read(self) -> Optional[Dict[str, str]]:
		# e.g.
		#   >>> \lc\1\nc\b'YFKltYx6p9Ve2YE+jX9aJjLxynwgzkdi+nOZqZZufXE='\id\1\final\
		#   <<< \login2\196610\username\toxidation@msn.com\response\bFKdo4E01WHpwimji5wdSgnjifhV7zv1mGg+ZzHSKqaO4bjV0uq9MzMU9Nk0UmzTFN+nI/u2KUf7fuM=\clientver\673\reconn\0\status\100\id\1\final\
		#
		# each message is terminated with \final\
		try:
			i = self._buf.index(b'\\final\\')
		except (IndexError, ValueError):
			return None

		# extract message up to \final\`
		data = self._buf[:i + len(b'\\final\\')].decode('utf-8')

		# advance buffer to exclude `data`
		self._buf = self._buf[i + len(b'\\final\\'):]

		# log what we got
		self._logger.debug('[Client]', data)

		# split string by `\` and skip first member due to leading backslash
		parts = data.split('\\')[1:]

		# convert `parts` into dict by treating first member as key, second member as value, and so on
		data_pairs = {}

		for i in range(0, len(parts), 2):
			key = parts[i]
			value = parts[i + 1] if i + 1 < len(parts) else ""

			data_pairs[key] = value

		return data_pairs


class MSIMWriter:
	__slots__ = ('_logger', '_buf')

	_logger: Logger
	_buf: io.BytesIO

	def __init__(self, logger: Logger) -> None:
		self._logger = logger
		self._buf = io.BytesIO()

	def write(self, data_pairs: Dict[str, Any]) -> None:
		m = ''

		for key, value in data_pairs.items():
			m += f'\\{key}'

			# skip over if value is bool and it isn't True
			if isinstance(value, bool):
				if not value:
					continue

				# otherwise, add \1 as the value pair
				m += '\\1'
				continue

			# MySpaceIM dictionaries are e.g.
			#   k1=v2\x1ck2=v3
			#
			# which then deserialize to:
			#   k1: v2
			#   k2: v3
			if isinstance(value, list):
				m += '\\'

				for d in value:
					if isinstance(d, dict):
						m += '\x1c'.join(f'{key}={value}' for key, value in d.items())
			elif isinstance(value, dict):
				m += '\\'
				m += '\x1c'.join(f'{key}={value}' for key, value in value.items())

			# encode `value` in base64 and add that as its value
			elif isinstance(value, bytes):
				b = base64.b64encode(value)
				m += f'\\{b.decode('ascii')}'

			# treat any other type (e.g. int or str) not seen above as a string
			else:
				m += f'\\{value}'

		m += '\\final\\'

		self._logger.debug('[Server]', m)
		self._buf.write(m.encode('utf-8'))

	def flush(self) -> bytes:
		data = self._buf.getvalue()
		if data:
			self._buf = io.BytesIO()

		return data
