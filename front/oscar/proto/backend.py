import os
import struct
import settings

from array import array
from core import event
from core.backend import Chat, ChatSession, BackendSession
from core.models import Contact, Substatus, Circle, CircleRole, User, TextWithData, OIM, LoginOption
from enum import IntEnum
from util.misc import Logger
from urllib.parse import quote
from typing import Optional, Any, Dict

from ..foodgroups.buddy import build_presence_notif
from ..foodgroups.popup import popup_display
from ..proto.snac import OSCARContext
from ..proto.tlv import TLV, marshal_tlvs, find_tlv
from ..proto.chat import ChatEventHandler

# TODO(subpurple): move this to a config of some sort
FOODGROUP_VERSIONS: {int, int} = {
	0x0001: 4,  # OSERVICE
	0x0002: 1,  # LOCATE
	0x0003: 1,  # BUDDY
	0x0004: 1,  # ICBM
	0x0006: 1,  # INVITE
	0x0008: 1,  # POPUP
	0x0009: 1,  # BOS
	0x000A: 1,  # USER_LOOKUP
	0x000B: 1,  # STATS
	0x000C: 1,  # TRANSLATE
	0x0013: 6,  # FEEDBAG
	0x0015: 2,  # ICQ
	0x0022: 1,  # PLUGIN
	0x0024: 1,  # UNNAMED (possibly NACHOS?)
	0x0025: 1   # MDIR
}

ERROR_URLS: {int, str} = {
	0x0001: 'http://www.aim.aol.com/errors/UNREGISTERED_SCREENNAME.html',   # Unregistered screen name
	0x0005: 'http://www.aim.aol.com/errors/MISMATCH_PASSWD.html',		   # Incorrect password
	0x0011: 'http://www.aim.aol.com/errors/SUSPENDED.html',				 # Suspended
}

PW_CHANGE_URL_FORMAT = 'http://aim.aol.com/redirects/password/change_password.adp?ScreenName={}&ccode={}&lang={}'


bos_cookies: array[{bytes, OSCARContext}] = []


class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('ctrl', 'bs')

	ctrl: Any

	def __init__(self, ctrl: Any) -> None:
		self.ctrl = ctrl

	def on_maintenance_message(self, *args: Any, **kwargs: Any) -> None:
		self.ctrl.logger.info("on_maintenance message dispatched")
		if args[1] is not None and args[1] > 0:
			message = """CrossTalk will be down for maintenance in around {} minute(s). \
Now is a good time to wrap up any conversations.""".format(args[1])
		self.ctrl.send_snac(popup_display(self, "https://crosstalk.im/maintenance", message))

	def on_client_alert(self, icon_url: Optional[str], url: Optional[str], message: str = '') -> None:
		self.ctrl.logger.info("on_client_alert dispatched")
		self.ctrl.send_snac(popup_display(self, url, message))

	def on_maintenance_boot(self) -> None:
		# TODO(HIDEN): can we pass an informative message to the user?
		self.ctrl.close()
		return

	def on_presence_notification(
			self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
			trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True,
			send_status_on_bl: bool = False, sess_id: Optional[int] = None,
			updated_phone_info: Optional[Dict[str, Any]] = None,
	) -> None:
		self.ctrl.logger.info('on_presence_notification dispatched')
		self.ctrl.logger.info('update_status:', update_status)
		self.ctrl.logger.info('update_info_other:', update_info_other)
		self.ctrl.logger.info('status:', ctc.status.substatus.name)

		# don't want any non-status updates
		if not update_status:
			self.ctrl.logger.info('fell into update_status check')
			return

		# for now, we only send presence notifications if the buddy changing status is offline(-ish) or online
		if not ctc.status.is_offlineish() and ctc.status.substatus != Substatus.Online:
			self.ctrl.logger.info('fell into status check')
			return

		self.ctrl.logger.info('sending presence notif')
		self.ctrl.send_snac(build_presence_notif(ctc))

	def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True,
									  update_info: bool = True) -> None:
		self.ctrl.logger.info('on_presence_self_notification')
		pass

	def on_chat_invite(
			self, chat: Chat, inviter: User, *, circle: bool = False, inviter_id: Optional[str] = None,
			invite_msg: str = '',
	) -> None:
		self.ctrl.logger.info('on_chat_invite')
		if chat is None:
			chat = self.backend.chat_create()
			chat.add_id('oscar0', chat.ids['main'])
		evt = ChatEventHandler(self.ctrl.backend.loop, self.ctrl, self.bs)
		cs = chat.join('oscar0', self.bs, evt)
		chat.send_participant_joined(cs)
		self.bs.front_data['oscar0_chats'][inviter.uuid] = (cs, evt)
		return

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
		self.ctrl.close()
		return

	# circles are not a thing in AIM
	def on_circle_invite_revoked(self, chat_id: str) -> None:
		pass

	def on_accepted_circle_invite(self, circle: Circle) -> None:
		pass

	def on_circle_updated(self, circle: Circle) -> None:
		pass

	def on_left_circle(self, circle: Circle) -> None:
		pass

	def on_circle_role_updated(self, chat_id: str, role: CircleRole) -> None:
		pass

	def on_circle_created(self, circle: Circle) -> None:
		pass

	def on_close(self) -> None:
		self.ctrl.close()

class LoginError(IntEnum):
	UnregisteredScreenname = 0x0001,
	IncorrectPassword = 0x0005,
	NotATester = 0x0009,
	Suspended = 0x0011


def login(logger: Logger,
		  context: OSCARContext,
		  tlvs: array[TLV],
		  uuid: Optional[str],
		  error_code: Optional[int]) -> bytes:

	# get user if found
	user = context.backend.user_service.get(uuid) if uuid else None

	# find screen name TLV and use it if not found in DB
	screen_name_tlv = find_tlv(tlvs, 0x0001)
	screen_name = user.username if user else screen_name_tlv.data.decode()

	# additionally check if user is suspended here
	if error_code is None and user.suspended:
		error_code = LoginError.Suspended

		logger.info(screen_name, 'tried to sign on but is suspended!')

	if error_code is None and not user.is_tester:
		error_code = LoginError.NotATester

		logger.info(screen_name, 'tried to sign on but is not a tester!')
		
	if error_code is None:
		logger.info(screen_name, 'signed on successfully!')

		# generate BOS cookie and add it to array
		bos_cookie = os.urandom(256)
		bos_cookies.append({
			bos_cookie: uuid
		})

		# get user email
		email = user.email

		# find client's country TLV for use in password change URL
		country_tlv = find_tlv(tlvs, 0x000E)
		country = country_tlv.data if country_tlv else 'us'

		# find client's language TLV for use in password change URL
		language_tlv = find_tlv(tlvs, 0x000F)
		language = language_tlv.data if language_tlv else 'en'

		# format password change URL with found client country and language
		pw_change_url = PW_CHANGE_URL_FORMAT.format(
			quote(screen_name),
			country,
			language
		)

		return marshal_tlvs([
			TLV(0x0001, screen_name),					   # Screen name
			TLV(0x0005, f'{settings.TARGET_IP}:5190'),	# BOS address
			TLV(0x0006, bos_cookie),						# BOS authorization cookie
			TLV(0x0011, email),							 # User's e-mail address
			TLV(0x0013, struct.pack('>H', 1)),			  # Registration status
			TLV(0x0054, pw_change_url),					 # Password change URL
			TLV(0x008E, struct.pack('>B', 0))			   # Unknown
		])

	return marshal_tlvs([
		TLV(0x0001, screen_name),						   # Screen name
		TLV(0x0008, struct.pack('>H', error_code)),		 # Error code
		TLV(0x0004, ERROR_URLS[error_code]),				# Error URL
	])
