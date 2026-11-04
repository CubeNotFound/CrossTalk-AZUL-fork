import os
import struct
import time
import settings

from array import array
from core import event
from core.backend import Chat, ChatSession, BackendSession
from core.models import Contact, Substatus, Circle, CircleRole, User, TextWithData, OIM, LoginOption
from core.alerts import Alert
from dataclasses import dataclass, field
from enum import IntEnum
from util.misc import Logger, is_valid_oscar_screenname
from urllib.parse import quote
from typing import Optional, Any, Dict, List

from ..foodgroups.buddy import build_presence_notif, watching
from ..foodgroups.feedbag import build_buddy_added_notif
from ..foodgroups.popup import popup_display
from ..proto.snac import OSCARContext
from ..proto.tlv import TLV, marshal_tlvs, find_tlv
from ..proto.chat import ChatEventHandler
from . import names
from .delivery import oscar_sessions

# TODO: move this to a config of some sort
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
	0x000F: 1,  # DIRECTORY
	0x0013: 6,  # FEEDBAG
	0x0015: 2,  # ICQ
	0x0018: 1,  # EMAIL
	0x0022: 1,  # PLUGIN
	0x0024: 1,  # UNNAMED (possibly NACHOS?)
	0x0025: 1   # MDIR
}

SERVICE_BOS = 0x0000

SERVICE_FOODGROUPS: Dict[int, List[int]] = {
	SERVICE_BOS: [0x0018, 0x0010, 0x0003, 0x0013, 0x0004, 0x0015, 0x0002, 0x0001, 0x0009, 0x000A, 0x0006, 0x0008, 0x000B],
	0x0007: [0x0001, 0x0007],   # ADMIN
	0x000D: [0x000D, 0x0001],   # CHAT_NAV
	0x000E: [0x0001, 0x000E],   # CHAT
	0x000F: [0x000F, 0x0001],   # ODIR
	0x0010: [0x0010, 0x0001],   # BART
	0x0018: [0x0018, 0x0001],   # ALERT
}

ERROR_URLS: {int, str} = {
	0x0001: 'http://www.aim.aol.com/errors/UNREGISTERED_SCREENNAME.html',   # Unregistered screen name
	0x0005: 'http://www.aim.aol.com/errors/MISMATCH_PASSWD.html',		   # Incorrect password
	0x0009: '', # Not a tester (inaccurate)
	0x0011: 'http://www.aim.aol.com/errors/SUSPENDED.html',				 # Suspended
	0x0006: '', # Unverified E-mail (inaccurate)
	0x0008: '', # ICQ user doesn't exist
}

PW_CHANGE_URL_FORMAT = 'http://aim.aol.com/redirects/password/change_password.adp?ScreenName={}&ccode={}&lang={}'

DISCONNECT_NEW_LOGIN = 0x0001

COOKIE_LIFETIME = 300


@dataclass
class ServiceCookie:
	uuid: Optional[str] = None
	version: str = '?'
	program: str = 'aim'
	screen_name: Optional[str] = None
	icq: bool = False
	client_id: str = ''
	multi_conn: Optional[int] = None
	bs: Optional[BackendSession] = None
	service: int = SERVICE_BOS
	room: Optional[Dict[str, Any]] = None
	issued: float = field(default_factory = time.time)


bos_cookies: Dict[bytes, ServiceCookie] = {}

def issue_cookie(entry: ServiceCookie) -> bytes:
	now = time.time()
	for stale in [cookie for cookie, other in bos_cookies.items() if now - other.issued > COOKIE_LIFETIME]:
		del bos_cookies[stale]
	cookie = os.urandom(256)
	bos_cookies[cookie] = entry
	return cookie

def take_cookie(cookie: bytes) -> Optional[ServiceCookie]:
	entry = bos_cookies.pop(cookie, None)
	if entry is None or time.time() - entry.issued > COOKIE_LIFETIME:
		return None
	return entry


class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('ctrl', 'bs')

	ctrl: Any

	def __init__(self, ctrl: Any) -> None:
		self.ctrl = ctrl

	def on_maintenance_message(self, *args: Any, **kwargs: Any) -> None:
		self.ctrl.logger.info("on_maintenance message dispatched")
		message = "CrossTalk will be down for maintenance soon. Now is a good time to wrap up any conversations."
		if args[1] is not None and args[1] > 0:
			message = """CrossTalk will be down for maintenance in around {} minute(s). \
Now is a good time to wrap up any conversations.""".format(args[1])
		self.ctrl.send_snac(popup_display(self, "https://crosstalk.im/maintenance", message))

	def on_client_alert(self, alert: Alert) -> bool:
		self.ctrl.logger.info("on_client_alert dispatched")
		self.ctrl.send_snac(popup_display(self, alert.url or '', alert.plain()))
		return True

	def on_maintenance_boot(self) -> None:
		# TODO(HIDEN): can we pass an informative message to the user?
		self.ctrl.close()
		return

	def on_warning_level_changed(self, level: int, warner: Optional[User]) -> None:
		# a warning (from AIM, TOC or an MSN spam report) gets OSERVICE__EVIL_NOTIFICATION; any change, wearing off too, a
		# fresh OSERVICE__USER_INFO_UPDATE, since the level is part of the user's own info
		from ..foodgroups.icbm import build_evil_notification
		from ..foodgroups.oservice import build_self_info
		previous = self.bs.front_data.get('oscar0_evil', 0)
		self.bs.front_data['oscar0_evil'] = level
		if level > previous:
			self.ctrl.send_snac(build_evil_notification(self.bs, level, warner))
		self.ctrl.send_snac(build_self_info(self.bs))

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

		# don't want updates from users with invalid usernames
		if not names.representable(ctc.head):
			return

		# don't want any non-status updates
		if not update_status:
			self.ctrl.logger.info('fell into update_status check')
			return

		# presence only starts flowing once the client says it's ready for it (OSERVICE__CLIENT_READY), and only for
		# people on the buddy list the client actually runs on (its own one, unless it uses the feedbag)
		if not self.bs.front_data.get('oscar0_ready') or not watching(self.bs, ctc.head):
			return

		try:
			ctc.compute_visible_status(self.bs.user)

			self.ctrl.logger.info('sending presence notif')
			self.ctrl.send_snac(build_presence_notif(ctc, self.ctrl.backend, self.bs))
		except Exception as ex:
			self.ctrl.logger.error(ex)

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
			chat = self.ctrl.backend.chat_create()
			chat.add_id('oscar0', chat.ids['main'])
		chats = self.bs.front_data.setdefault('oscar0_chats', {})
		# a conversation with the same person moves to the newest chat they started
		previous = chats.pop(inviter.uuid, None)
		if previous is not None and previous[0].chat is not chat:
			previous[0].close()
		evt = ChatEventHandler(self.ctrl.backend.loop, self.ctrl, self.bs)
		cs = chat.join('oscar0', self.bs, evt)
		chat.send_participant_joined(cs)
		chats[inviter.uuid] = (cs, evt)
		return

	def on_declined_chat_invite(self, chat: Chat, circle: bool = False) -> None:
		self.ctrl.logger.info('on_declined_chat_invite')
		pass

	def on_added_me(self, user: User, *, adder_id: Optional[str] = None,
					message: Optional[TextWithData] = None) -> None:
		self.ctrl.logger.info('on_added_me')

		if not names.representable(user):
			return

		# an add still waiting on our authorization isn't announced until it's granted
		from ..foodgroups.buddy import buddy_pending
		if buddy_pending(user, self.bs.user):
			return

		from ..foodgroups.icbm import send_icq_system_message, ICQMessageType
		if self.bs.front_data.get('oscar0_feedbag'):
			self.ctrl.send_snac(build_buddy_added_notif(names.name_for(self.bs, user)))
		elif names.is_icq_session(self.bs):
			# ICQ clients without a feedbag only learn this from a "you were added" message (MSG_TYPE_ADDED)
			send_icq_system_message(self.ctrl, user, ICQMessageType.Added, '')

	def on_removed_me(self, user: User) -> None:
		self.ctrl.logger.info('on_removed_me')
		pass

	def on_contact_request_denied(self, user_added: User, message: Optional[str], *,
								  contact_id: Optional[str] = None) -> None:
		self.ctrl.logger.info('on_contact_request_denied')
		pass

	def on_oim_sent(self, oim: OIM) -> None:
		self.ctrl.logger.info('on_oim_sent')
		# an offline message only gets stored while its recipient can't be reached, so a session that hears about one
		# (signed on invisible, say) gets it straight away, like the YMSG frontend does
		from ..foodgroups.icbm import deliver_offline_messages
		deliver_offline_messages(self.ctrl, [oim])

	def on_login_elsewhere(self, option: LoginOption) -> None:
		self.ctrl.logger.info('on_login_elsewhere')
		self.ctrl.signoff(DISCONNECT_NEW_LOGIN)
		self.ctrl.close()
		return

	def oscar_on_icbm(self, msg: Any) -> None:
		# an ICBM (rendezvous, ICQ message, client error/ack) passed straight between OSCAR clients, bypassing the chat
		# machinery the other frontends message through
		self.ctrl.send_snac(msg)

	def oscar_on_snac(self, msg: Any) -> None:
		self.ctrl.send_snac(msg)

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
	Suspended = 0x0011,
	EmailNotVerified = 0x0006
	ICQUserError = 0x0008


def login(logger: Logger,
		  context: OSCARContext,
		  tlvs: array[TLV],
		  uuid: Optional[str],
		  error_code: Optional[int],
		  *,
		  icq: bool = False,
		  multi_conn: Optional[int] = None) -> bytes:

	# get user if found
	user = context.backend.user_service.get(uuid) if uuid else None

	# find screen name TLV and use it if not found in DB
	screen_name_tlv = find_tlv(tlvs, 0x0001)
	given_name = screen_name_tlv.data.decode('latin-1') if screen_name_tlv else ''
	# an ICQ client gets its UIN back, an AIM one the screen name's own formatting
	screen_name = (given_name.replace(' ', '') if icq else user.username) if user else given_name

	# additionally check if user is suspended here
	if error_code is None and user.suspended:
		error_code = LoginError.Suspended

		logger.info(screen_name, 'tried to sign on but is suspended!')

	# and check if the user has verified their e-mail address
	#if error_code is None and not user.verified_to_login:
	#	error_code = LoginError.EmailNotVerified
	#
	#	logger.info(screen_name, 'tried to sign on but has not verified their e-mail address!')

	if error_code is None:
		logger.info(screen_name, 'signed on successfully!')

		# generate BOS cookie and add it to array
		client_id_tlv = find_tlv(tlvs, 0x0003)
		bos_cookie = issue_cookie(ServiceCookie(
			uuid = uuid, version = context.client.version, program = 'icq' if icq else 'aim',
			screen_name = screen_name, icq = icq,
			client_id = client_id_tlv.data.decode('latin-1') if client_id_tlv else '', multi_conn = multi_conn,
		))

		# get user email
		email = user.email

		# find client's country TLV for use in password change URL
		country_tlv = find_tlv(tlvs, 0x000E)
		country = country_tlv.data.decode('latin-1') if country_tlv else 'us'

		# find client's language TLV for use in password change URL
		language_tlv = find_tlv(tlvs, 0x000F)
		language = language_tlv.data.decode('latin-1') if language_tlv else 'en'

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
		TLV(0x0004, ERROR_URLS.get(int(error_code), '')),	# Error URL
	])
