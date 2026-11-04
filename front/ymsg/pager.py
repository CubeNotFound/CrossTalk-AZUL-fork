from typing import Optional, Dict, Any, Tuple
import datetime, asyncio, time, settings, base64, util, secrets, json, traceback
 
from urllib.parse import parse_qs
from disposable_email_domains import blocklist as disposable_emails
 
from util.misc import Logger, gen_uuid, MultiDict, arbitrary_decode, arbitrary_encode
 
from core import event, error
from core.backend import Backend, BackendSession, Chat, ChatSession
from core.models import (
	Substatus, ContactList, User, Contact, Circle, CircleRole, TextWithData,
	MessageData, MessageType, UserStatus, LoginOption, OIM,
)
from core.client import Client
from core.auth import GenTokenStr
from core.alerts import Alert
 
from .ymsg_ctrl import YMSGCtrlBase
from .misc import YMSGService, YMSGStatus, split_to_chunks
from . import misc, Y64, avatar_sync
 
# "Pre" because it's needed before BackendSession is created.
# Comment out session ID stuff as that'll have to be reworked with account usernames being a thing
#PRE_SESSION_ID: Dict[str, int] = {}
 
class YMSGCtrlPager(YMSGCtrlBase):
	__slots__ = ('backend', 'dialect', 'sess_id', 'challenge', 't_cookie_token', 'bs', 'client')
	
	backend: Backend
	dialect: int
	sess_id: int
	challenge: Optional[bytes]
	t_cookie_token: Optional[str]
	bs: Optional[BackendSession]
	client: Client
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.sess_id = 0
		self.challenge = None
		self.t_cookie_token = None
		self.bs = None
		self.client = Client('ymsg', '?', via)
	
	def _on_close(self, remove_sess_id: bool = True) -> None:
		if self.bs:
			self.bs.close()
	
	# State = Auth
	
	def _y_004c(self, *args: Any) -> None:
		# SERVICE_HANDSHAKE (0x4c); acknowledgement of the server
		
		self.client = Client('ymsg', 'YMSG{}'.format(str(args[0])), self.client.via)
		self.dialect = int(args[0])
		self.set_dialect(self.dialect)
		self.send_reply(YMSGService.Handshake, YMSGStatus.BRB, 0, None)
	
	def _y_0057(self, *args: Any) -> None:
		# SERVICE_AUTH (0x57); send a challenge string for the client to craft two response strings with
		backend = self.backend
 
		# Yahoo for Vista & 9+ doesn't send SERVICE_HANDSHAKE apparently, so I'm adding this here as well
		self.client = Client('ymsg', 'YMSG{}'.format(str(args[0])), self.client.via)
		self.dialect = int(args[0])
		self.set_dialect(self.dialect)
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = yahoo_data.get(b'1')
		
		self.sess_id = secrets.randbelow(4294967294) + 1
		
		auth_dict = MultiDict([
			(b'1', yahoo_id),
		]) # type: MultiDict[bytes, bytes]
		if settings.STRESS_TEST_ACTIVE:
			send_system_message(self, "We're currently doing a stress test of the CrossTalk service. Put load on the server, and tell your friends!")
 
		if settings.FORCE_HOSTS_UPDATE:
			send_system_message(self, "You are required to update your patches before continuing. Go here to learn more: http://diet.crosstalk.im/moving-hosts")
			
			authresp_error = int(YMSGStatus.Bad)
			self.close()
			return

		if self.dialect <= 12:
			self.challenge = generate_challenge_v1()
		else:
			auth_dict.add(b'13', b'2')
			self.challenge = base64.b64encode(util.misc.generate_random_string(chars=48))
 
		auth_dict.add(b'94', self.challenge)			
 
		self.send_reply(YMSGService.Auth, YMSGStatus.BRB, self.sess_id, auth_dict)
 
	def _y_0001(self, *args: Any) -> None:
		backend = self.backend
		
		y = None
		t = None
		authresp_error = None
		
		status = args[2]
		if status is YMSGStatus.WebLogin:
			status = YMSGStatus.Available
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = yahoo_data.get(b'0') or b''
		active_yid = yahoo_data.get(b'1') or b''
		resp_6 = yahoo_data.get(b'6')
		resp_96 = yahoo_data.get(b'96')
		resp_307 = yahoo_data.get(b'307')
		
		if b'' in (active_yid,yahoo_id):
			authresp_error = int(YMSGStatus.NotAtHome)
		
		yahoo_id_str = arbitrary_decode(yahoo_id)
		
		uuid = backend.util_get_uuid_from_username(yahoo_id_str)
		if uuid is None:
			authresp_error = int(YMSGStatus.NotAtHome)
		
		version = arbitrary_decode(yahoo_data.get(b'135') or b'') or 'unknown'
		self.client = Client('ymsg', version, self.client.via)
				
		assert self.challenge is not None
		if authresp_error is None:
			if self.dialect >= 13:
				if b'277' in yahoo_data and b'278' in yahoo_data:
					y = arbitrary_decode(yahoo_data.get(b'277'))
					t = arbitrary_decode(yahoo_data.get(b'278'))
					self.logger.debug(f'Y Cookie sent by client: {y}')
					self.logger.debug(f'T Cookie sent by client: {t}')
 
					token = None
					if t:
						qs = parse_qs(t, keep_blank_values=True, strict_parsing=False)
						if 'z' in qs and qs['z']:
							token = qs['z'][0]
						elif 'sk' in qs and qs['sk']:
							token = qs['sk'][0]
						elif 'd' in qs and qs['d']:
							token = qs['d'][0]
 
					if not token:
						self.logger.error('Could not extract tokenfrom T cookie')
						authresp_error = int(YMSGStatus.Bad)
					else:
						tpl = self.backend.login_auth_service.get_token('ymsg/cookie', token)
						if tpl is not None:
							bs = self.backend.login(uuid, self.client, BackendEventHandler(self.backend.loop, self), option=LoginOption.BootOthers)
							if bs is None:
								authresp_error = int(YMSGStatus.Bad)
							else:
								self.bs = bs
								user = bs.user
								self._util_authresp_final(status, cached_y=y, cached_t=t)
						else:
							authresp_error = int(YMSGStatus.Bad)
			else:
				is_resp_correct = self._verify_challenge_v1(arbitrary_decode(yahoo_id), resp_6, resp_96)
				if is_resp_correct:
					assert uuid is not None
					bs = self.backend.login(uuid, self.client, BackendEventHandler(self.backend.loop, self), option = LoginOption.BootOthers)
					if bs is None:
						authresp_error = int(YMSGStatus.Bad)
					else:
						self.bs = bs
						user = bs.user
						self._util_authresp_final(status, cached_y = y, cached_t = t)
				else:
					authresp_error = int(YMSGStatus.Bad)
		
		if authresp_error is not None:
			self.send_reply(YMSGService.AuthResp, YMSGStatus.LoginError, self.sess_id, MultiDict([
				(b'1', active_yid),
				(b'66', str(authresp_error).encode('utf-8')),
				(b'0', yahoo_id),
			]))
			self.close()
 
	def _y_0054(self, *args: Any) -> None:
		backend = self.backend
		
		y = None
		t = None
		authresp_error = None
		
		status = args[2]
		if status is YMSGStatus.WebLogin:
			status = YMSGStatus.Available
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = yahoo_data.get(b'0') or b''
		active_yid = yahoo_data.get(b'1') or b''
		resp_6 = yahoo_data.get(b'6')
		resp_96 = yahoo_data.get(b'96')
		resp_307 = yahoo_data.get(b'307')
		
		if b'' in (active_yid,yahoo_id):
			authresp_error = int(YMSGStatus.NotAtHome)
		
		yahoo_id_str = arbitrary_decode(yahoo_id)
		
		uuid = backend.util_get_uuid_from_username(yahoo_id_str)
		if uuid is None:
			authresp_error = int(YMSGStatus.NotAtHome)
		
		version = arbitrary_decode(yahoo_data.get(b'135') or b'') or 'unknown'
		self.client = Client('ymsg', version, self.client.via)
				
		assert self.challenge is not None
		if authresp_error is None:
			if self.dialect >= 13:
				if b'277' in yahoo_data and b'278' in yahoo_data:
					y = arbitrary_decode(yahoo_data.get(b'277'))
					t = arbitrary_decode(yahoo_data.get(b'278'))
					self.logger.debug(f'Y Cookie sent by client: {y}')
					self.logger.debug(f'T Cookie sent by client: {t}')
 
					token = None
					if t:
						qs = parse_qs(t, keep_blank_values=True, strict_parsing=False)
						if 'z' in qs and qs['z']:
							token = qs['z'][0]
						elif 'sk' in qs and qs['sk']:
							token = qs['sk'][0]
						elif 'd' in qs and qs['d']:
							token = qs['d'][0]
 
					if not token:
						self.logger.info('Could not extract token from T cookie')
						authresp_error = int(YMSGStatus.Bad)
					else:
						tpl = self.backend.login_auth_service.get_token('ymsg/cookie', token)
						if tpl is not None:
							bs = self.backend.login(uuid, self.client, BackendEventHandler(self.backend.loop, self), option=LoginOption.BootOthers)
							if bs is None:
								authresp_error = int(YMSGStatus.Bad)
							else:
								self.bs = bs
								user = bs.user
								self._util_authresp_final(status, cached_y=y, cached_t=t)
						else:
							authresp_error = int(YMSGStatus.Bad)
			else:
				is_resp_correct = self._verify_challenge_v1(arbitrary_decode(yahoo_id), resp_6, resp_96)
				if is_resp_correct:
					assert uuid is not None
					bs = self.backend.login(uuid, self.client, BackendEventHandler(self.backend.loop, self), option = LoginOption.BootOthers)
					if bs is None:
						authresp_error = int(YMSGStatus.Bad)
					else:
						self.bs = bs
						user = bs.user
						self._util_authresp_final(status, cached_y = y, cached_t = t)
				else:
					authresp_error = int(YMSGStatus.Bad)
		
		if authresp_error is not None:
			self.send_reply(YMSGService.AuthResp, YMSGStatus.LoginError, self.sess_id, MultiDict([
				(b'1', active_yid),
				(b'66', str(authresp_error).encode('utf-8')),
				(b'0', yahoo_id),
			]))
			self.close()
 
	def _util_authresp_final(self, status: YMSGStatus, *, cached_y: Optional[str] = None, cached_t: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		email = user.email
		
		self.t_cookie_token = (cached_t[4:24] if cached_y and cached_t else GenTokenStr())
		
		bs.front_data['ymsg'] = True
		bs.front_data['ymsg_private_chats'] = {}
		bs.front_data['ymsg_chat_sessions'] = {}
 
		if user.suspended:
			send_system_message(self, "Your CrossTalk account has been suspended. You may not connect to the service.")
			
			authresp_error = int(YMSGStatus.Bad)
			self.close()
			return
 
		#if not user.verified_to_login:
		#	send_system_message(self, "You need to verify the e-mail address attached to this account belongs to you before you can log in. Log in to the CrossTalk site and do so in your Account Settings.")
		#	
		#	authresp_error = int(YMSGStatus.Bad)
		#	self.close()
		#	return
 
		with open('config/restricted-emails.json', 'r') as file:
			restricted_emails = json.load(file)
			email_domain = email.lower().split('@')[-1]
			if email_domain in restricted_emails or email_domain in disposable_emails:
				send_system_message(self, "Your e-mail address contains a blacklisted domain and needs to be changed before you can log in. Go to https://crosstalk.im/alias-prep to learn more. Change your e-mail in your CrossTalk account settings.")
			
				authresp_error = int(YMSGStatus.Bad)
				self.close()
				return
		
		avatar_sync.note_login(self.backend, user)
		
		self._update_buddy_list(cached_y = cached_y, cached_t = cached_t, on_login = True)
		
		if self.dialect >= 16:
			self.send_reply(YMSGService.PingConfiguration, YMSGStatus.BRB, self.sess_id, MultiDict([
				(b'143', b'60'),
				(b'144', b'1'),
			]))
			self.send_reply(YMSGService.BuddyInfo, YMSGStatus.Available, self.sess_id, misc.build_buddy_info_v16(self._online_contacts(user)))
			self._announce_own_icon(user)
		elif self.dialect >= 10:
			kvs = MultiDict([
				(b'143', b'60'),
				(b'144', b'13')
			]) # type: MultiDict[bytes, bytes]
			self.send_reply(YMSGService.PingConfiguration, YMSGStatus.Available, self.sess_id, kvs)
		
		self._send_pending_requests(user)
		self._get_oims(user)
		
		if self.backend.notify_maintenance:
			bs.evt.on_maintenance_message(None, self.backend.maintenance_mins)
	
	def _announce_own_icon(self, user: User) -> None:
		checksum = misc.yahoo_avatar_checksum(user)
		if checksum is None:
			return
		self.send_reply(YMSGService.FriendIcon, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(user.username)),
			(b'5', arbitrary_encode(user.username)),
			(b'192', checksum),
		]))
	
	def _online_contacts(self, user: User) -> list[Contact]:
		detail = user.detail
		assert detail is not None
		return [
			c for c in detail.contacts.values()
			if c.lists & ContactList.FL and not c.lists & ContactList.BL and not c.status.is_offlineish()
		]
	
	def _send_prelogin_data(self, user: User, cached_y: Optional[str], cached_t: Optional[str]) -> None:
		tpl = self._refresh_cookies()
		if tpl is not None:
			(y_cookie, t_cookie, _, _) = tpl
		else:
			y_cookie = cached_y or ''
			t_cookie = cached_t or ''
		
		username = arbitrary_encode(user.username)
		kvs = MultiDict([
			(b'2', username),
			(b'3', username),
			(b'89', username),
			(b'216', b''),
			(b'254', b''),
			(b'213', (b'2' if misc.yahoo_avatar_checksum(user) is not None else b'0')),
			(b'208', arbitrary_encode(t_cookie)),
			(b'93', str(misc.TOKEN_LIFETIME - 1).encode('utf-8')),
			(b'59', arbitrary_encode('Y\t{}; path=/;'.format(y_cookie))),
			(b'219', b''),
			(b'59', arbitrary_encode('T\t{}; path=/;'.format(t_cookie))),
			(b'219', b''),
			(b'300', b'444'),
			(b'301', b'444'),
		]) # type: MultiDict[bytes, bytes]
		self.send_reply(YMSGService.PreLoginData, YMSGStatus.Available, self.sess_id, kvs)
	
	def _send_preference(self) -> None:
		self.send_reply(YMSGService.Preference, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'302', b'312'),
			(b'303', b'312'),
		]))
 
	# State = Live
	
	def _y_0004(self, *args: Any) -> None:
		# SERVICE_ISBACK (0x04); notify contacts of online presence
		
		bs = self.bs
		assert bs is not None
		
		new_status = YMSGStatus(int(args[2]))
		
		me_status_update(bs, new_status)
	
	def _y_0003(self, *args: Any) -> None:
		# SERVICE_ISAWAY (0x03); notify contacts of FYI idle presence
		
		bs = self.bs
		assert bs is not None
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		new_status = YMSGStatus(int(yahoo_data.get(b'10') or b''))
		message = arbitrary_decode(yahoo_data.get(b'19') or b'')
		is_away_message = (yahoo_data.get(b'47') == b'1')
		me_status_update(bs, new_status, message = message, is_away_message = is_away_message)
	
	def _y_0012(self, *args: Any) -> None:
		# SERVICE_PINGCONFIGURATION (0x12); set the "ticks" and "tocks" of a ping sent
		
		kvs = MultiDict([
			(b'143', b'60'),
			(b'144', b'13')
		]) # type: MultiDict[bytes, bytes]
		self.send_reply(YMSGService.PingConfiguration, YMSGStatus.Available, self.sess_id, kvs)
	
	def _y_0016(self, *args: Any) -> None:
		# SERVICE_CLIENTHOSTSTATS (0x16); collects OS version, processor, and time zone
		#
		# 1: YahooId
		# 25: unknown ('C=0[0x01]F=1,P=0,C=0,H=0,W=0,B=0,O=0,G=0[0x01]M=0,P=0,C=0,S=0,L=3,D=1,N=0,G=0,F=0,T=0')
		# 146: Base64-encoded string of host OS (e.g.: 'V2luZG93cyAyMDAwLCBTZXJ2aWNlIFBhY2sgNA==' = 'Windows 2000, Service Pack 4')
		# 145: Base64-encoded string of processor type (e.g.: 'SW50ZWwgUGVudGl1bSBQcm8gb3IgUGVudGl1bQ==' = 'Intel Pentium Pro or Pentium')
		# 147: Base64-encoded string of time zone (e.g.: 'RWFzdGVybiBTdGFuZGFyZCBUaW1l' = 'Eastern Standard Time')
		
		return
	
	def _y_008a(self, *args: Any) -> None:
		# SERVICE_PING (0x8a)
		if self.dialect >= 16:
			self.send_reply(YMSGService.KeepAlive, YMSGStatus.BRB, self.sess_id, None)
			return
		bs = self.bs
		assert bs is not None
		self.send_reply(YMSGService.Ping, YMSGStatus.Available, self.sess_id, MultiDict([
			(b'1', arbitrary_encode(bs.user.username)),
		]))
	
	def _y_0015(self, *args: Any) -> None:
		# SERVICE_SKINNAME (0x15); used for IMVironments. On YMSG16 this is "Client Stats"
		# (key 211 telemetry), acknowledged with an empty Ack.
		if self.dialect >= 16:
			self.send_reply(YMSGService.ClientStats, YMSGStatus.Ack, self.sess_id, None)
	
	def _y_0002(self, *args: Any) -> None:
		# SERVICE_LOGOFF (0x02); empty request, empty Ack, then tear down.
		self.send_reply(YMSGService.LogOff, YMSGStatus.Ack, self.sess_id, None)
		self.close()
	
	def _y_0083(self, *args: Any) -> None:
		# SERVICE_FRIENDADD (0x83); add a friend to your contact list
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		contact_yahoo_id = arbitrary_decode(yahoo_data.get(b'7') or b'')
		message = arbitrary_decode(yahoo_data.get(b'14') or b'')
		buddy_group = arbitrary_decode(yahoo_data.get(b'65') or b'')
		utf8 = arbitrary_decode(yahoo_data.get(b'97') or b'')
		
		group = None
		old_lists = None
		action_group_refresh = False
		
		def reply(err: bytes, *, pending: bool = False) -> None:
			if self.dialect >= 16:
				kvs = MultiDict([
					(b'1', arbitrary_encode(yahoo_id)),
					(b'241', b'0'),
					(b'65', arbitrary_encode(buddy_group)),
					(b'7', arbitrary_encode(contact_yahoo_id)),
					(b'216', b''),
					(b'254', b''),
					(b'14', arbitrary_encode(message)),
					(b'97', b'1'),
					(b'66', err),
				]) # type: MultiDict[bytes, bytes]
				if pending:
					kvs.add(b'223', b'1')
			else:
				kvs = MultiDict([
					(b'1', arbitrary_encode(yahoo_id)),
					(b'7', arbitrary_encode(contact_yahoo_id)),
					(b'65', arbitrary_encode(buddy_group)),
					(b'66', err),
				])
			self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, kvs)
		
		# Yahoo! Messenger has a function that lets you add people by email address (a.k.a. stripping the "@domain.tld" part of the address and
		# filling that out in the "Yahoo! ID" section of the contact add dialog). Treat as is.
		contact_uuid = backend.util_get_uuid_from_username(contact_yahoo_id)
		if contact_uuid is None:
			reply(b'3') # User doesn't exist in database
			return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		
		contact = contacts.get(contact_uuid)
		if contact is not None:
			old_lists = contact.lists
			if contact.lists & ContactList.FL:
				if contact._groups:
					for group_other in contact._groups.copy():
						if detail._groups_by_id[group_other.id].name == buddy_group:
							reply(b'2') # Contact already in group
							return
				else:
					if buddy_group == '(No Group)':
						reply(b'2')
						return
		
		if buddy_group != '(No Group)':
			for grp in detail._groups_by_id.values():
				if grp.name == buddy_group:
					group = grp
					break
			
			if group is None:
				group = bs.me_group_add(buddy_group)
		
		ctc_head = self.backend._load_user_record(contact_uuid)
		assert ctc_head is not None
		
		try:
			contact_new = bs.me_contact_add(
				ctc_head.uuid, ContactList.FL | ContactList.AL, message = (TextWithData(message, utf8) if message is not None else None),
				adder_id = yahoo_id, needs_notify = True,
			)[0]
		except error.ContactListIsFull:
			reply(b'6') # Contact list full
			return
		except:
			reply(b'1') # General failure
			return
		
		self._clear_pending(user, contact_new)
		
		if (contact_new is not None and contact is None) or (old_lists is not None and (not old_lists & ContactList.FL and not old_lists & ContactList.BL)):
			contact_struct = MultiDict([
				(b'8', (b'1' if not contact_new.status.is_offlineish() else b'0')),
			]) # type: MultiDict[bytes, bytes]
			add_contact_status_to_data(contact_struct, ctc_head.status, ctc_head)
			
			self.send_reply(YMSGService.ContactNew, YMSGStatus.BRB, self.sess_id, contact_struct)
			
		reply(b'0', pending = not (contact_new.lists & ContactList.RL))
		try:
			# TODO: Moving/copying contacts to groups
			if len(contact_new._groups) >= 1 or (contact_new._groups and buddy_group == '(No Group)'): action_group_refresh = True
			if buddy_group == '(No Group)':
				for group_other in contact_new._groups.copy():
					group_full = False
					bs.me_group_contact_remove(group_other.id, contact_new.head.uuid)
					for ctc_other in detail.contacts.values():
						if ctc_other is contact_new: continue
						for group_ctc in ctc_other._groups.copy():
							if group_ctc.id is group_other.id:
								group_full = True
								break
						if group_full:
							break
			if group is not None:
				bs.me_group_contact_add(group.id, contact_new.head.uuid)
			
			if action_group_refresh: self._update_buddy_list(after_login = True)
		except error.ContactAlreadyOnContactList:
			# Ignore, because this condition was checked earlier, so the only way this
			# can happen is if the the contact list gets in an inconsistent state.
			# (I.e. contact is not on FL, but still part of groups.)
			pass

	def _y_0086(self, *args: Any) -> None:
		# SERVICE_CONTACTDENY (0x86); deny a contact request
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		adder_to_deny = arbitrary_decode(yahoo_data.get(b'7') or b'')
		deny_message = arbitrary_decode(yahoo_data.get(b'14') or b'')
		
		adder_uuid = backend.util_get_uuid_from_username(adder_to_deny)
		assert adder_uuid is not None
		bs = self.bs
		assert bs is not None
		bs.me_contact_deny(adder_uuid, deny_message, addee_id = yahoo_id)
		ctc = bs.user.detail.contacts.get(adder_uuid) if bs.user.detail is not None else None
		if ctc is not None:
			self._clear_pending(bs.user, ctc)
	
	def _y_0089(self, *args: Any) -> None:
		# SERVICE_GROUPRENAME (0x89); rename a contact group
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		group_name = arbitrary_decode(yahoo_data.get(b'65') or b'')
		new_group_name = arbitrary_decode(yahoo_data.get(b'67') or b'')
		bs = self.bs
		assert bs is not None
		
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		group = None
		
		# "(No Group)" is used for displaying group-less contacts; ignore any requests to rename the "group"
		
		if '(No Group)' not in (group_name,new_group_name):
			for grp in detail._groups_by_id.values():
				if grp.name == group_name:
					group = grp
			
			if group is not None:
				try:
					bs.me_group_edit(group.id, new_name = new_group_name)
				except:
					pass
			
			group_rename_response = MultiDict([
				(b'1', arbitrary_encode(yahoo_id or '')),
				(b'66', b'0'),
				(b'67', arbitrary_encode(new_group_name or '')),
				(b'65', arbitrary_encode(group_name or '')),
			]) # type: MultiDict[bytes, bytes]
			
			self.send_reply(YMSGService.GroupRename, YMSGStatus.BRB, self.sess_id, group_rename_response)
		
		self._update_buddy_list()
	
	def _y_0084(self, *args: Any) -> None:
		# SERVICE_FRIENDREMOVE (0x84); remove a buddyfrom your list
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		contact_id = arbitrary_decode(yahoo_data.get(b'7') or b'')
		buddy_group = arbitrary_decode(yahoo_data.get(b'65') or b'')
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		group = None
		
		contact_uuid = backend.util_get_uuid_from_username(contact_id)
		if contact_uuid is None:
			return
		
		contact = detail.contacts.get(contact_uuid)
		
		if contact is None:
			return
		
		if contact._groups:
			for group_other in contact._groups.copy():
				if detail._groups_by_id[group_other.id].name == buddy_group:
					group = detail._groups_by_id[group_other.id]
					break
		
		if group is None and buddy_group != '(No Group)':
			return
		
		if group is not None:
			bs.me_group_contact_remove(group.id, contact.head.uuid)
		
		if not contact._groups:
			bs.me_contact_remove(contact_uuid, ContactList.FL)
		
		remove_buddy_response = MultiDict([
			(b'1', arbitrary_encode(yahoo_id)),
			(b'66', b'0'),
			(b'7', arbitrary_encode(contact_id)),
			(b'65', arbitrary_encode(buddy_group)),
		]) # type: MultiDict[bytes, bytes]
		
		self.send_reply(YMSGService.FriendRemove, YMSGStatus.BRB, self.sess_id, remove_buddy_response)
		
		self._update_buddy_list()
	
	def _y_0085(self, *args: Any) -> None:
		# SERVICE_IGNORE (0x85); add/remove someonefrom your ignore list
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		ignored_yahoo_id = arbitrary_decode(yahoo_data.get(b'7') or b'')
		ignore_mode = arbitrary_decode(yahoo_data.get(b'13') or b'')
		
		ignore_reply_response = MultiDict([
			(b'0', arbitrary_encode(yahoo_id)),
			(b'7', arbitrary_encode(ignored_yahoo_id)),
			(b'13', arbitrary_encode(ignore_mode))
		])
		
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		contacts = detail.contacts
		
		ignored_uuid = backend.util_get_uuid_from_username(ignored_yahoo_id)
		if ignored_uuid is None:
			ignore_reply_response.add(b'66', b'3')
			self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
			return
		
		if int(ignore_mode) == 1:
			contact = contacts.get(ignored_uuid)
			if contact is not None:
				if contact.lists & ContactList.BL:
					ignore_reply_response.add(b'66', b'2')
					self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
					return
			
			bs.me_contact_add(ignored_uuid, ContactList.BL, name = ignored_yahoo_id)
		elif int(ignore_mode) == 2:
			bs.me_contact_remove(ignored_uuid, ContactList.BL)
		else:
			return
		
		self.send_reply(YMSGService.AddIgnore, YMSGStatus.BRB, self.sess_id, None)
		ignore_reply_response.add(b'66', b'0')
		self._update_buddy_list()
		self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
	
	def _y_000a(self, *args: Any) -> None:
		# SERVICE_USERSTAT (0x0a); synchronize logged on user's status
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		self.send_reply(
			YMSGService.UserStat, bs.front_data.get('ymsg_status') or YMSGStatus.FromSubstatus(user.status.substatus),
			self.sess_id, self._gen_multi_user_status_dict(user),
		)

	def _y_00d7(self, *args: Any) -> None:
		# SERVICE_PHOTOADD (0xd7); status Ack (18) is the receipt for an offer we relayed
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		status = args[2]
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		photo_id = yahoo_data.get(b'245')
		if recipient is None or photo_id is None:
			return
		
		if status == YMSGStatus.Ack:
			for bs_other in self._peer_sessions(recipient):
				bs_other.evt.ymsg_on_photo_ack(user.username, recipient, photo_id)
			return
		
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_photo_add(
				user.username, recipient, photo_id,
				yahoo_data.get(b'246'), yahoo_data.get(b'267'), yahoo_data.get(b'20'),
			)
	
	def _y_00d8(self, *args: Any) -> None:
		# SERVICE_PHOTOSELECT (0xd8); which photo in the tray is currently displayed.
		# Key 194: 0 deselect, 1 select, 2 remove.
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		photo_id = yahoo_data.get(b'245')
		if recipient is None or photo_id is None:
			return
		
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_photo_select(
				user.username, recipient, photo_id, yahoo_data.get(b'194') or b'0',
			)
	
	def _y_00da(self, *args: Any) -> None:
		# SERVICE_PHOTOFILEREQUEST (0xda); status Ack (18) is the owner answering with token + size
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		status = args[2]
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		photo_id = yahoo_data.get(b'245')
		if recipient is None or photo_id is None:
			return
		
		relay_host = settings.TARGET_IP.encode('utf-8')
		
		if status == YMSGStatus.Ack:
			token = yahoo_data.get(b'251') or yahoo_data.get(b'276')
			if token is None:
				return
			for bs_other in self._peer_sessions(recipient):
				bs_other.evt.ymsg_on_photo_relay(
					user.username, recipient, photo_id, token,
					relay_host = relay_host, filesize = yahoo_data.get(b'28'), ack = True,
				)
			return
		
		token = misc.gen_relay_token().encode('utf-8')
		backend.auth_service.create_token('ymsg/relay', [user.uuid, recipient], token = token.decode('utf-8'), lifetime = 3600)
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_photo_relay(
				user.username, recipient, photo_id, token,
				relay_host = relay_host, filesize = None, ack = False,
			)

	def _y_00d2(self, *args: Any) -> None:
		# photo sharing invite, stub for now
		pass
 
	def _y_00dc(self, *args: Any) -> None:
		# SERVICE_FILETRANSFERINVITE (0xdc). Key 222 is the mode:
		#   1 invite, 3 accept, 4 decline/cancel.
		# 265 is the p2p cookie (always '$$'-suffixed), 266 the file count, and the
		# filename/filesize pair is wrapped in a 302=268 … 303=268 list block.
		# 267 carries a base64 thumbnail for image transfers.
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		cookie = yahoo_data.get(b'265')
		if recipient is None or cookie is None:
			return
		
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_ft_invite(user.username, recipient, cookie, yahoo_data)
	
	def _y_00dd(self, *args: Any) -> None:
		# SERVICE_PEERSETUP (0xdd); sender publishes the relay endpoint (250) and path
		# token (251) for an accepted transfer.
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		cookie = yahoo_data.get(b'265')
		if recipient is None or cookie is None:
			return
		
		token = yahoo_data.get(b'251') or misc.gen_relay_token().encode('utf-8')
		backend.auth_service.create_token(
			'ymsg/relay', [user.uuid, recipient], token = token.decode('utf-8'), lifetime = 3600,
		)
		
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_ft_setup(
				user.username, recipient, cookie,
				filename = yahoo_data.get(b'27') or b'',
				relay_host = settings.TARGET_IP.encode('utf-8'),
				peer_path = token,
				transfer_type = yahoo_data.get(b'249') or b'3',
			)
	
	def _y_00de(self, *args: Any) -> None:
		# SERVICE_PEERINIT (0xde); receiver started pulling from the relay, or cancelled (status -1 / key 66 == -1)
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		cookie = yahoo_data.get(b'265')
		if recipient is None or cookie is None:
			return
		
		cancelled = (args[2] == YMSGStatus.LoginError or yahoo_data.get(b'66') == b'-1')
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_ft_init(user.username, recipient, cookie, yahoo_data, cancelled = cancelled)

	def _y_00bd(self, *args: Any) -> None:
		# SERVICE_PICTURE_CHECKSUM / Friend Icon (0xbd); the client announces its icon after an upload, to
		# everyone (`1, 212, 192`) or to one buddy (`1, 5, 212, 192`). The original answers each with a
		# `4=me, 5=me` notify to the sender and relays to the buddies.
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		avatar_sync.refresh_avatar(backend, user)
		
		checksum = misc.yahoo_avatar_checksum(user)
		if checksum is None:
			return
		
		for bs_self in backend.util_get_sessions_by_user(user):
			bs_self.evt.ymsg_on_friend_icon(user.username, user.username, checksum)
		
		recipient = self._peer_id(yahoo_data)
		if recipient is not None:
			targets = [recipient]
		else:
			if avatar_sync.recently_pushed(user, checksum):
				return
			targets = [head.username for head in avatar_sync.icon_recipients(user)]
		
		for target in targets:
			if target.lower() == user.username.lower():
				continue
			for bs_other in self._peer_sessions(target):
				bs_other.evt.ymsg_on_friend_icon(user.username, target, checksum)
	
	def _y_00be(self, *args: Any) -> None:
		# SERVICE_PICTURE / Friend Icon Download (0xbe); `1=me, 5=owner, 13=1` asks for an icon, and the
		# reply is `4=owner, 5=me, 13=2, 20=url, 192=checksum`. Answered by the server out of the
		# avatar store, so icons stay available while their owner is offline.
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		if arbitrary_decode(yahoo_data.get(b'13') or b'1') != '1':
			return
		
		target = self._peer_id(yahoo_data)
		if target is None:
			return
		target_uuid = backend.util_get_uuid_from_username(target)
		if target_uuid is None:
			return
		target_head = backend._load_user_record(target_uuid)
		if target_head is None:
			return
		
		avatar_sync.refresh_avatar(backend, target_head)
		
		url = misc.yahoo_avatar_url(target_head)
		checksum = misc.yahoo_avatar_checksum(target_head)
		if url is None or checksum is None:
			return
		
		self.send_reply(YMSGService.FriendIconDownload, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(target)),
			(b'5', arbitrary_encode(user.username)),
			(b'13', b'2'),
			(b'20', url),
			(b'192', checksum),
		]))
	
	def _y_00c1(self, *args: Any) -> None:
		# SERVICE_PICTURE_UPDATE / Display Type Changed (0xc1); `1=me, 5=buddy, 206=flag`
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		icon_flag = yahoo_data.get(b'206')
		recipient = self._peer_id(yahoo_data)
		if icon_flag is None or recipient is None:
			return
		
		for bs_other in self._peer_sessions(recipient):
			relay = getattr(bs_other.evt, 'ymsg_on_friend_icon_flag', None)
			if relay is not None:
				relay(user.username, recipient, icon_flag)
	
	def _y_00c7(self, *args: Any) -> None:
		# SERVICE_AVATAR_UPDATE / Display Image Prefs (0xc7); `3=me, 213=flag` is answered with
		# `4=me, 213=flag` 
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		avatar_flag = yahoo_data.get(b'213') or b'2'
		bs.front_data['ymsg_avatar_flag'] = avatar_flag
		
		self.send_reply(YMSGService.DisplayImagePrefs, YMSGStatus.Available, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(user.username)),
			(b'213', avatar_flag),
		]))

	def _y_00d0(self, *args: Any) -> None:
		# SERVICE_AUDIBLE (0xd0). 230 is the audible ID, 231 the spoken text used as the
		# fallback IM body, 232 the SHA-1 of the .swf the client fetches
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		audible_id = yahoo_data.get(b'230')
		if recipient is None or audible_id is None:
			return
		
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_audible(
				user.username, recipient, audible_id,
				yahoo_data.get(b'231') or b'', yahoo_data.get(b'232') or b'',
			)
	
	def _y_00d2(self, *args: Any) -> None:
		# SERVICE_IMPANELFEATURE (0xd2); IM-window feature panel state.
		# 221 is the feature id, 222 the state (1 open, 2 peer-acknowledged, 5 closed).
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		feature = yahoo_data.get(b'221')
		state = yahoo_data.get(b'222')
		if None in (recipient, feature, state):
			return
		
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_im_panel_feature(user.username, recipient or '', feature or b'1', state or b'1')
	
	def _y_00d4(self, *args: Any) -> None:
		# SERVICE_IMSESSION (0xd4); IM window opened/closed against a buddy (key 13).
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		if recipient is None:
			return
		
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_im_session(user.username, recipient, yahoo_data.get(b'13') or b'1')

	def _y_00d6(self, *args: Any) -> None:
		# SERVICE_BUDDYAUTHORIZE (0xd6); our answer to a contact request: `1=me, 5=requester, 13=1 accept / 2 deny, 14=message`
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		yahoo_data = args[4]
		buddy = self._peer_id(yahoo_data) or self._peer_id(yahoo_data, b'4')
		if buddy is None:
			return
		buddy_uuid = backend.util_get_uuid_from_username(buddy)
		if buddy_uuid is None:
			return
		buddy_head = backend._load_user_record(buddy_uuid)
		if buddy_head is None:
			return
		
		accepted = (yahoo_data.get(b'13') or b'1') == b'1'
		message = arbitrary_decode(yahoo_data.get(b'14') or b'')
		
		try:
			if accepted:
				for bs_other in backend.util_get_sessions_by_user(buddy_head):
					bs_other.evt.ymsg_on_buddy_response(user, True, '')
				bs.me_contact_add(buddy_uuid, ContactList.AL, name = buddy)
			else:
				bs.me_contact_deny(buddy_uuid, message, addee_id = user.username)
		except error.ClientError:
			pass
		
		# Answered, so it no longer shows up at login
		ctc = detail.contacts.get(buddy_uuid)
		if ctc is not None:
			self._clear_pending(user, ctc)
			
	def _y_00fb(self, *args: Any) -> None:
		# SERVICE_MESSAGEACK (0xfb); a client acknowledging a message it received:
		# `1=me, 5=original sender, 302=430, 430=id, 303=430`
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		sender = self._peer_id(yahoo_data)
		msg_id = yahoo_data.get(b'430')
		if sender is None or msg_id is None:
			return
		
		for bs_other in self._peer_sessions(sender):
			bs_other.evt.ymsg_on_message_ack(user.username, sender, msg_id)
			
	def _y_0055(self, *args: Any) -> None:
		# SERVICE_LIST (0x55); send a user's buddy list
		
		self._update_buddy_list(after_login = True)
 
	def _y_00c5(self, *args: any) -> None:
		# SERVICE_ISINVISIBLE (0xc5); mark as invisible
		bs = self.bs
		assert bs is not None
		status = None
		
		yahoo_data = args[4]
		new_status = YMSGStatus(int(yahoo_data.get(b'13') or b''))
		if new_status == int(2):
			status = YMSGStatus.Invisible
		elif new_status == int(1):
			status = YMSGStatus.Available
		me_status_update(bs, status)
   
	def _y_00c6(self, *args: Any) -> None:
		# SERVICE_STATUSUPDATE (0xc6); essentially the same as 0x03. For whatever reason, it was changed in YMSG12
		bs = self.bs
		assert bs is not None
   
		yahoo_data = args[4]
		new_status = YMSGStatus(int(yahoo_data.get(b'10') or b''))
		message = arbitrary_decode(yahoo_data.get(b'19') or b'')
		is_away_message = (yahoo_data.get(b'47') == b'1')
		me_status_update(bs, new_status, message = message, is_away_message = is_away_message)
	
	def _y_008a(self, *args: Any) -> None:
		# SERVICE_PING (0x8a); send a response ping after the client pings
		bs = self.bs
		assert bs is not None
		self.send_reply(YMSGService.Ping, YMSGStatus.Available, self.sess_id, MultiDict([
			(b'1', arbitrary_encode(bs.user.username)),
		]))
	
	def _y_0008(self, *args: Any) -> None:
		# SERVICE_IDDEACTIVATE (0x08); deactivate an alias
		
		return
	
	def _y_0007(self, *args: Any) -> None:
		# SERVICE_IDACTIVATE (0x07); activate an alias
		
		return
	
	def _y_004f(self, *args: Any) -> None:
		# SERVICE_PEERTOPEER (0x4f); see if P2P messaging is possible. Possibly also used for other P2P actions
		
		backend = self.backend
		# Formality; make sure unregistered sessions aren't able to send these packets
		bs = self.bs
		assert bs is not None
		
		yahoo_data = args[4]
		recipient_uuid = backend.util_get_uuid_from_username(arbitrary_decode(yahoo_data.get(b'5')))
		if recipient_uuid is None:
			return
		recipient_head = backend._load_user_record(recipient_uuid)
		if recipient_head is None:
			return
		
		for bs_other in backend.util_get_sessions_by_user(recipient_head):
			bs_other.evt.ymsg_on_p2p_msg_request(self.sess_id, yahoo_data)
	
	def _y_004b(self, *args: Any) -> None:
		# SERVICE_NOTIFY (0x4b); notify a contact of an action (typing, games, etc.)
		backend = self.backend
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		notify_type = yahoo_data.get(b'49') # typing, games, etc.
		typing_flag = yahoo_data.get(b'13')
		if typing_flag is not None:
			typing_flag = arbitrary_decode(typing_flag)
		contact_yahoo_id = yahoo_data.get(b'5')
		if contact_yahoo_id is not None:
			contact_yahoo_id = arbitrary_decode(contact_yahoo_id)
		contact_uuid = backend.util_get_uuid_from_username(contact_yahoo_id)
		if contact_uuid is None:
			return
		
		try:
			cs, _ = self._get_private_chat_with(contact_uuid)
			if cs is not None:
				cs.preferred_name = yahoo_id
				cs.send_message_to_everyone(messagedata_from_ymsg(cs.user, yahoo_data, notify_type = notify_type, typing_flag = typing_flag))
		except error.ContactNotOnline:
			pass
 
	def _y_00d4(self, *args: Any) -> None:
	# SERVICE_CHATSESSION (0xD4); start a chat session
		pass
 
	def _y_00e7(self, *args: Any) -> None:
		# gotta figure out what the fuck this one is, but it's used in YMSG14/15 for group management
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
 
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
 
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		contact_yahoo_id = arbitrary_decode(yahoo_data.get(b'7') or b'')
		new_buddy_group = arbitrary_decode(yahoo_data.get(b'264') or b'')
		old_buddy_group = arbitrary_decode(yahoo_data.get(b'224') or b'')
 
		group_new = None
		group_old = None
		action_group_refresh = False
 
		contact_uuid = backend.util_get_uuid_from_username(contact_yahoo_id)
		if contact_uuid is None:
			return
 
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
 
		contacts = detail.contacts
 
		contact = contacts.get(contact_uuid)
		if contact is None:
			return
 
		if new_buddy_group != '(No Group)':
			for grp in detail._groups_by_id.values():
				if grp.name == new_buddy_group:
					group_new = grp
					break
 
			if group_new is None:
				group_new = bs.me_group_add(new_buddy_group)
 
		if old_buddy_group and old_buddy_group != '(No Group)':
			for grp in detail._groups_by_id.values():
				if grp.name == old_buddy_group:
					group_old = grp
					break
 
		try:
			if len(contact._groups) >= 1 or (contact._groups and new_buddy_group == '(No Group)'):
				action_group_refresh = True
 
			if old_buddy_group == '(No Group)':
				for group_other in contact._groups.copy():
					group_full = False
					bs.me_group_contact_remove(group_other.id, contact.head.uuid)
					for ctc_other in detail.contacts.values():
						if ctc_other is contact: continue
						for group_ctc in ctc_other._groups.copy():
							if group_ctc.id is group_other.id:
								group_full = True
								break
						if group_full:
							break
			else:
				if group_old is not None:
					bs.me_group_contact_remove(group_old.id, contact.head.uuid)
 
			if group_new is not None:
				bs.me_group_contact_add(group_new.id, contact.head.uuid)
 
			if action_group_refresh:
				self._update_buddy_list()
		except error.ContactAlreadyOnContactList:
			pass
 
	
	def _y_0006(self, *args: Any) -> None:
		# SERVICE_MESSAGE (0x06); send a message to a user (older YMSG)
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		#yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		contact_yahoo_id = arbitrary_decode(yahoo_data.get(b'5') or b'')
		
		self._message_common(yahoo_data, contact_yahoo_id)
	
	def _y_0017(self, *args: Any) -> None:
		# SERVICE_MASSMESSAGE (0x17); send a message to multiple users
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		#yahoo_id = yahoo_data.get(b'1')
		
		contact_yahoo_ids = [
			arbitrary_decode(contact_yahoo_id)
			for contact_yahoo_id in (yahoo_data.getall(b'5') or [])
		]
		for contact_yahoo_id in contact_yahoo_ids:
			self._message_common(yahoo_data, contact_yahoo_id)
	
	def _y_0050(self, *args: Any) -> None:
		# SERVICE_VIDEOCHAT (0x50); create a webcam token for authentication
		bs = self.bs
		assert bs is not None
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		if not yahoo_data.get(b'1'): return
		
		webcam_token = self.backend.auth_service.create_token('ymsg/webcam', yahoo_data.get(b'1'), lifetime = 86400)
		
		self.send_reply(YMSGService.VideoChat, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'1', yahoo_data.get(b'1')),
			(b'5', yahoo_data.get(b'1')),
			(b'61', webcam_token),
		]))
		
		return
	
	def _y_004d(self, *args: Any) -> None:
		# SERVICE_P2PFILEXFER / "Send Data Thru" (0x4d)
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		yahoo_data = args[4]
		recipient = self._peer_id(yahoo_data)
		if recipient is None:
			return
		
		notify_type = yahoo_data.get(b'49')
		if notify_type == b'IMVIRONMENT':
			for bs_other in self._peer_sessions(recipient):
				bs_other.evt.ymsg_on_imvironment(
					user.username, recipient,
					yahoo_data.get(b'63') or b';0', yahoo_data.get(b'64') or b'0',
				)
			return
		
		for bs_other in self._peer_sessions(recipient):
			bs_other.evt.ymsg_on_xfer_init(self.sess_id, yahoo_data)
	
	def _y_0018(self, *args: Any) -> None:
		# SERVICE_CONFINVITE (0x18); send a conference invite to one or more people
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_roster = [
			arbitrary_decode(conf_member)
			for conf_member in (yahoo_data.getall(b'52') or [])
		]
		# Comma-separated yahoo ids
		conf_roster_2 = yahoo_data.get(b'51')
		if conf_roster_2 is not None:
			conf_roster.extend(arbitrary_decode(conf_roster_2).split(','))
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		invite_msg = arbitrary_decode(yahoo_data.get(b'58') or b'')
		voice_chat = arbitrary_decode(yahoo_data.get(b'13') or b'')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id, create = True)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat, create = True)
		assert cs is not None
		
		chat.front_data['ymsg_voice_chat'] = voice_chat
		
		for conf_user_yahoo_id in conf_roster:
			conf_user_uuid = backend.util_get_uuid_from_username(conf_user_yahoo_id)
			if conf_user_uuid is None: continue
			conf_user = self.backend._load_user_record(conf_user_uuid)
			if conf_user is None: continue
			cs.invite(conf_user, invite_msg = invite_msg)
	
	def _y_001c(self, *args: Any) -> None:
		# SERVICE_CONFADDINVITE (0x1c); send a conference invite to an existing conference to one or more people
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_new_roster_str = yahoo_data.get(b'51')
		if conf_new_roster_str is None:
			return
		conf_new_roster = arbitrary_decode(conf_new_roster_str).split(',')
		conf_roster = [
			arbitrary_decode(conf_member)
			for conf_member in (yahoo_data.getall(b'52') or yahoo_data.getall(b'53') or [])
		]
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		if not conf_id:
			return
		invite_msg = arbitrary_decode(yahoo_data.get(b'58') or b'')
		voice_chat = arbitrary_decode(yahoo_data.get(b'13') or b'')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat)
		assert cs is not None
		
		chat.front_data['ymsg_voice_chat'] = voice_chat
		
		for conf_user_yahoo_id in conf_new_roster:
			conf_user_uuid = backend.util_get_uuid_from_username(conf_user_yahoo_id)
			if conf_user_uuid is None: continue
			conf_user = self.backend._load_user_record(conf_user_uuid)
			if conf_user is None: continue
			cs.invite(conf_user, invite_msg = invite_msg)
	
	def _y_0019(self, *args: Any) -> None:
		# SERVICE_CONFLOGON (0x19); request for me to join a conference
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		inviter_ids = yahoo_data.getall(b'3')
		if inviter_ids is None:
			return
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		if not conf_id:
			return
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat, create = True)
		assert cs is not None
	
	def _y_001a(self, *args: Any) -> None:
		# SERVICE_CONFDECLINE (0x1a); decline a request to join a conference
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		
		bs = self.bs
		assert bs is not None
		
		inviter_ids = [
			arbitrary_decode(inviter_id).lower() for inviter_id in (yahoo_data.getall(b'3') or [])
		]
		if not inviter_ids:
			return
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		deny_msg = arbitrary_decode(yahoo_data.get(b'14') or b'')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		if chat is None:
			return
		
		for cs in chat.get_roster():
			if cs.user.username.lower() not in inviter_ids:
				continue
			cs.evt.on_chat_invite_declined(chat, bs.user, invitee_id = yahoo_id, message = deny_msg)
	
	def _y_001d(self, *args: Any) -> None:
		# SERVICE_CONFMSG (0x1d); send a message in a conference
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		conf_user_ids = yahoo_data.getall(b'53')
		if conf_user_ids is None:
			return
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat)
		assert cs is not None
		cs.preferred_name = yahoo_id
		cs.send_message_to_everyone(messagedata_from_ymsg(cs.user, yahoo_data))
	
	def _y_001b(self, *args: Any) -> None:
		# SERVICE_CONFLOGOFF (0x1b); leave a conference
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		conf_roster = yahoo_data.getall(b'3')
		if conf_roster is None:
			return
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		if chat is None:
			return
		cs = self._get_chat_session(yahoo_id, chat)
		if cs is not None:
			cs.close()
		
	def _message_common(self, yahoo_data: MultiDict[bytes, bytes], contact_yahoo_id: Optional[str]) -> None:
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		# Key 429 is the client's id for this message, key 1 the id it is logged in as
		msg_id = yahoo_data.get(b'429')
		sender_id = arbitrary_decode(yahoo_data.get(b'1') or b'') or user.username
		
		if contact_yahoo_id is not None and contact_yahoo_id.lower() == 'yahoohelper':
			yhlper_msg_dict = MultiDict([
				(b'5', yahoo_data.get(b'1') or b''),
				(b'4', b'YahooHelper'),
				(b'14', YAHOO_HELPER_MSG.encode('utf-8')),
			]) # type: MultiDict[bytes, bytes]
			
			if yahoo_data.get(b'63') is not None:
				yhlper_msg_dict.add(b'63', yahoo_data.get(b'63') or b'')
			
			if yahoo_data.get(b'64') is not None:
				yhlper_msg_dict.add(b'64', yahoo_data.get(b'64') or b'')
			
			yhlper_msg_dict.add(b'97', b'1')
 
			if yahoo_data.get(b'206') is not None:
				yhlper_msg_dict.add(b'206', yahoo_data.get(b'206') or b'')
			
			self.send_reply(YMSGService.Message, YMSGStatus.BRB, self.sess_id, yhlper_msg_dict)
			self._begin_ack(contact_yahoo_id, sender_id, msg_id, wait_for_recipient = False)
			return
		
		contact_uuid = backend.util_get_uuid_from_username(contact_yahoo_id or '')
		if contact_uuid is None:
			return
		
		if self._is_duplicate_message(contact_yahoo_id or '', msg_id):
			if msg_id is not None and msg_id not in self._pending_acks():
				self._begin_ack(contact_yahoo_id or '', sender_id, msg_id, wait_for_recipient = False)
			return
		
		self._deliver_message(yahoo_data, contact_uuid)
		self._begin_ack(contact_yahoo_id or '', sender_id, msg_id, wait_for_recipient = True)
	
	def _deliver_message(self, yahoo_data: MultiDict[bytes, bytes], contact_uuid: str) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		try:
			cs, evt = self._get_private_chat_with(contact_uuid)
			if None not in (cs, evt):
				evt._send_when_user_joins(contact_uuid, messagedata_from_ymsg(cs.user, yahoo_data))
		except error.ContactNotOnline:
			contact_user = self.backend._load_user_record(contact_uuid)
			if contact_user is None:
				return
			contact_detail = self.backend._load_detail(contact_user)
			if contact_detail is None:
				return
			ctc_self = contact_detail.contacts.get(user.uuid)
			if ctc_self is not None:
				if ctc_self.lists & ContactList.BL:
					return
			elif ctc_self is None and contact_user.settings.get('BLP', 'AL') == 'BL':
				return
			md = messagedata_from_ymsg(contact_user, yahoo_data)
			if md.type is MessageType.Chat:
				(ip, _) = self.peername
				from_user_id = None
				
				key1_val = md.front_cache['ymsg'].get(b'1')
				if key1_val is not None:
					from_user_id = arbitrary_decode(key1_val)
				
				self.backend.user_service.save_oim(
					bs, contact_uuid, gen_uuid(), ip, md.text or '', False if md.front_cache['ymsg'].get(b'97') == b'0' else True,
					from_user_id =from_user_id,
				)
		except error.ContactNotOnContactList:
			pass
	
	ACK_MIN_DELAY = 0.2
	ACK_FALLBACK_DELAY = 2.5
	
	def _pending_acks(self) -> Dict[bytes, Dict[str, Any]]:
		bs = self.bs
		assert bs is not None
		return bs.front_data.setdefault('ymsg_pending_acks', {})
	
	def _recipient_acks(self, recipient: str) -> bool:
		for bs_other in self._peer_sessions(recipient):
			ctrl = getattr(bs_other.evt, 'ctrl', None)
			if bs_other.front_data.get('ymsg') and getattr(ctrl, 'dialect', 0) >= 16:
				return True
		return False
	
	def _begin_ack(self, recipient: str, sender_id: str, msg_id: Optional[bytes], *, wait_for_recipient: bool) -> None:
		if msg_id is None:
			return
		loop = self.backend.loop
		if wait_for_recipient and self._recipient_acks(recipient):
			delay = self.ACK_FALLBACK_DELAY
		else:
			delay = self.ACK_MIN_DELAY
		self._pending_acks()[msg_id] = {
			'recipient': recipient,
			'sender': sender_id,
			'at': loop.time(),
			'handle': loop.call_later(delay, self._send_ack, msg_id),
		}
	
	def _on_recipient_ack(self, msg_id: bytes) -> None:
		entry = self._pending_acks().get(msg_id)
		if entry is None:
			return
		loop = self.backend.loop
		entry['handle'].cancel()
		remaining = max(0.0, self.ACK_MIN_DELAY - (loop.time() - entry['at']))
		entry['handle'] = loop.call_later(remaining, self._send_ack, msg_id)
	
	def _send_ack(self, msg_id: bytes) -> None:
		try:
			if self.bs is None or self.closed:
				return
			entry = self._pending_acks().pop(msg_id, None)
			if entry is None:
				return
			self.send_reply(YMSGService.MessageAck, YMSGStatus.BRB, self.sess_id, MultiDict([
				(b'4', arbitrary_encode(entry['recipient'])),
				(b'5', arbitrary_encode(entry['sender'])),
				(b'302', b'430'),
				(b'430', msg_id),
				(b'303', b'430'),
			]))
		except Exception:
			traceback.print_exc()
	
	def _is_duplicate_message(self, recipient: str, msg_id: Optional[bytes]) -> bool:
		if msg_id is None:
			return False
		bs = self.bs
		assert bs is not None
		seen = bs.front_data.setdefault('ymsg_seen_msgs', {}) # type: Dict[Tuple[str, bytes], float]
		now = time.monotonic()
		for key in [k for (k, t) in seen.items() if now - t > 300]:
			del seen[key]
		key = (recipient.lower(), msg_id)
		if key in seen:
			return True
		seen[key] = now
		return False
	
	def _clear_pending(self, user: User, ctc: Contact) -> None:
		if ctc.pending:
			ctc.pending = False
			self.backend._mark_modified(user, detail = user.detail)
	
	def _send_contact_request(self, adder: User, *, adder_id: Optional[str] = None, message: Optional[TextWithData] = None) -> None:
		bs = self.bs
		assert bs is not None
		user_me = bs.user
		
		if self.dialect >= 16:
			self.send_reply(YMSGService.BuddyAuthorize, YMSGStatus.NotAtHome, self.sess_id, MultiDict([
				(b'4', arbitrary_encode(adder_id or adder.username)),
				(b'5', arbitrary_encode(user_me.username)),
				(b'241', b'0'),
				(b'14', arbitrary_encode(message.text if message is not None else '')),
				(b'216', b''),
				(b'254', b''),
			]))
			return
		
		contact_request_data = MultiDict([
			(b'1', arbitrary_encode(user_me.username)),
			(b'3', arbitrary_encode(adder_id or adder.username)),
		]) # type: MultiDict[bytes, bytes]
		
		if message is not None:
			contact_request_data.add(b'14', arbitrary_encode(message.text))
			if message.yahoo_utf8 is not None:
				contact_request_data.add(b'97', arbitrary_encode(message.yahoo_utf8))
		
		contact_request_data.add(b'15', arbitrary_encode(str(time.time())))
		
		self.send_reply(YMSGService.ContactNew, YMSGStatus.NotAtHome, self.sess_id, contact_request_data)
	
	def _send_authorize_response(self, buddy: User, accepted: bool, message: str = '') -> None:
		if self.dialect < 16:
			return
		bs = self.bs
		assert bs is not None
		self.send_reply(YMSGService.BuddyAuthorize, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(buddy.username)),
			(b'5', arbitrary_encode(bs.user.username)),
			(b'241', b'0'),
			(b'14', arbitrary_encode(message)),
			(b'13', (b'1' if accepted else b'2')),
		]))
	
	def _send_pending_requests(self, user: User) -> None:
		detail = user.detail
		if detail is None:
			return
		for ctc in list(detail.contacts.values()):
			if not (ctc.lists & ContactList.RL and ctc.pending):
				continue
			if ctc.lists & (ContactList.FL | ContactList.AL | ContactList.BL):
				self._clear_pending(user, ctc)
				continue
			self._send_contact_request(ctc.head)

	def _peer_sessions(self, yahoo_id: Optional[str]) -> list:
		if not yahoo_id:
			return []
		backend = self.backend
		uuid = backend.util_get_uuid_from_username(yahoo_id)
		if uuid is None:
			return []
		head = backend._load_user_record(uuid)
		if head is None:
			return []
		return backend.util_get_sessions_by_user(head)
	
	def _peer_id(self, yahoo_data: Any, key: bytes = b'5') -> Optional[str]:
		raw = yahoo_data.get(key)
		return arbitrary_decode(raw) if raw is not None else None

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
		if other_user_uuid not in bs.front_data['ymsg_private_chats'] and not other_user.status.is_offlineish():
			other_user_detail = self.backend._load_detail(other_user)
			if other_user_detail is None: raise error.ContactNotOnline()
			ctc_self = other_user_detail.contacts.get(user.uuid)
			if ctc_self is not None:
				if ctc_self.lists & ContactList.BL: raise error.ContactNotOnline()
			chat = self.backend.chat_create()
			chat.front_data['ymsg_twoway_only'] = True
			
			# `user` joins
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('yahoo', bs, evt)
			bs.front_data['ymsg_private_chats'][other_user_uuid] = (cs, evt)
			cs.invite(other_user)
			self.backend.loop.create_task(self._check_private_chat(chat, other_user, bs))
		elif other_user.status.is_offlineish():
			raise error.ContactNotOnline()
		return bs.front_data['ymsg_private_chats'].get(other_user_uuid)
	
	def _get_chat_by_id(self, scope: str, id: str, *, create: bool = False) -> Optional[Chat]:
		chat = self.backend.chat_get(scope, id)
		if chat is None and create:
			chat = self.backend.chat_create()
			chat.add_id(scope, id)
		return chat
	
	def _get_chat_session(self, yahoo_id: Optional[str], chat: Chat, *, create: bool = False) -> Optional[ChatSession]:
		bs = self.bs
		assert bs is not None
		
		cs = bs.front_data['ymsg_chat_sessions'].get(chat)
		if cs is None and create:
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('yahoo', bs, evt, preferred_name = yahoo_id)
			bs.front_data['ymsg_chat_sessions'][chat] = cs
			chat.send_participant_joined(cs)
		return cs
	
	def _update_buddy_list(self, cached_y: Optional[str] = None, cached_t: Optional[str] = None, on_login: bool = False, after_login: bool = False) -> None:
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		cs = list(contacts.values())
		cs_fl = [c for c in cs if c.lists & ContactList.FL and not c.lists & ContactList.BL]
		ignore_list = [c for c in cs if c.lists & ContactList.BL]
		
		if self.dialect >= 16:
			if on_login:
				self._send_prelogin_data(user, cached_y, cached_t)
				self._send_preference()
			self.generate_buddy_list_assnew(user, detail, cs_fl, ignore_list)
		else:
			self.generate_buddy_list_assold(backend, user, detail, cs_fl, ignore_list, cached_y, cached_t)
		
		if on_login:
			me_status_update(bs, YMSGStatus.Available)
		
		if not after_login and self.dialect < 16:
			self.send_reply(YMSGService.LogOn, YMSGStatus.Available, self.sess_id, self._gen_multi_user_status_dict(user))
	
	def generate_buddy_list_assnew(self, user: User, detail: Any, cs_fl: list, ignore_list: list) -> None:
		kvs = MultiDict() # type: MultiDict[bytes, bytes]
		kvs.add(b'1', arbitrary_encode(user.username))
		kvs.add(b'4', arbitrary_encode(user.username))

		kvs.add(b'302', b'318')

		for grp in detail._groups_by_id.values():
			buddies_in_group = []
			for c in cs_fl:
				for group in c._groups.copy():
					if group.id == grp.id:
						buddies_in_group.append(c)
			kvs.add(b'300', b'318')
			kvs.add(b'65', arbitrary_encode(grp.name))
			kvs.add(b'302', b'319')
			for c in buddies_in_group:
				kvs.add(b'300', b'319')
				kvs.add(b'241', b'0')
				kvs.add(b'7', arbitrary_encode(c.head.username))
				kvs.add(b'317', b'1')
				kvs.add(b'301', b'319')
			kvs.add(b'303', b'319')
			kvs.add(b'301', b'318')

		no_group_buddies = [c for c in cs_fl if not c._groups]
		if no_group_buddies:
			kvs.add(b'300', b'318')
			kvs.add(b'65', b'(No Group)')
			kvs.add(b'302', b'319')
			for c in no_group_buddies:
				kvs.add(b'300', b'319')
				kvs.add(b'241', b'0')
				kvs.add(b'7', arbitrary_encode(c.head.username))
				kvs.add(b'317', b'1')
				kvs.add(b'301', b'319')
			kvs.add(b'303', b'319')
			kvs.add(b'301', b'318')

		kvs.add(b'303', b'318')

		kvs.add(b'302', b'320')
		for c in ignore_list:
			kvs.add(b'300', b'320')
			kvs.add(b'7', arbitrary_encode(c.head.username))
			kvs.add(b'301', b'320')
		kvs.add(b'303', b'320')

		# Service 0xF1 (241) is the YMSG16 structured buddy list command.
		self.send_reply(YMSGService(0xF1), YMSGStatus.Available, self.sess_id, kvs)
	
	def generate_buddy_list_assold(
		self, backend: Backend, user: User, detail: Any,
		cs_fl: list, ignore_list: list,
		cached_y: Optional[str], cached_t: Optional[str],
	) -> None:
		# YMSG <= 15: flat text encoding on keys 87 (contacts) and 88 (ignored).
		contact_group_list = []
		for grp in detail._groups_by_id.values():
			contact_list = []
			for c in cs_fl:
				for group in c._groups.copy():
					if group.id == grp.id:
						contact_list.append(c.head.username)
			if contact_list:
				contact_group_list.append(grp.name + ':' + ','.join(contact_list) + '\n')
		# Handle contacts that aren't part of any groups
		no_group = [c.head.username for c in cs_fl if not c._groups]
		if no_group:
			contact_group_list.append('(No Group):' + ','.join(no_group) + '\n')
		
		contact_list_format = ''.join(contact_group_list)
		ignore_list_format = ','.join(c.head.username for c in ignore_list)
		
		list_reply_kvs = MultiDict() # type: MultiDict[bytes, bytes]
		
		if len(contact_list_format) > 815:
			for contact_chunk in split_to_chunks(contact_list_format, 815):
				self.send_reply(YMSGService.List, YMSGStatus.NotInOffice, self.sess_id, MultiDict([
					(b'87', arbitrary_encode(contact_chunk)),
				]))
		else:
			list_reply_kvs.add(b'87', arbitrary_encode(contact_list_format))
		
		if len(ignore_list_format) > 815:
			for ignore_chunk in split_to_chunks(ignore_list_format, 815):
				self.send_reply(YMSGService.List, YMSGStatus.NotInOffice, self.sess_id, MultiDict([
					(b'88', ignore_chunk.encode('utf-8')),
				]))
		else:
			list_reply_kvs.add(b'88', ignore_list_format.encode('utf-8'))
		
		list_reply_kvs.add(b'89', arbitrary_encode(user.username))
		
		if (
			cached_y is not None and cached_t is not None
			and backend.auth_service.get_token('ymsg/cookie', cached_y)
			and backend.auth_service.get_token('ymsg/cookie', cached_t)
		):
			list_reply_kvs.add(b'59', arbitrary_encode(cached_y))
			list_reply_kvs.add(b'59', arbitrary_encode(cached_t))
		else:
			tpl = self._refresh_cookies()
			if tpl is None:
				list_reply_kvs.add(b'59', b'Y\t')
				list_reply_kvs.add(b'59', b'T\t')
			else:
				(y_cookie, t_cookie, y_expiry, t_expiry) = tpl
				domain = settings.TARGET_HOST
				list_reply_kvs.add(b'59', arbitrary_encode('Y\t{}; expires={}; path=/; domain={}'.format(y_cookie, y_expiry, domain)))
				list_reply_kvs.add(b'59', arbitrary_encode('T\t{}; expires={}; path=/; domain={}'.format(t_cookie, t_expiry, domain)))
		
		list_reply_kvs.add(b'59', b'C\tmg=1')
		list_reply_kvs.add(b'3', arbitrary_encode(user.username))
		list_reply_kvs.add(b'90', b'1')
		list_reply_kvs.add(b'100', b'0')
		list_reply_kvs.add(b'101', b'')
		list_reply_kvs.add(b'102', b'')
		list_reply_kvs.add(b'93', b'86400')
		
		self.send_reply(YMSGService.List, YMSGStatus.Available, self.sess_id, list_reply_kvs)
	
	def _gen_multi_user_status_dict(self, user: User) -> MultiDict[bytes, bytes]:
		detail = user.detail
		assert detail is not None
		
		cs = list(detail.contacts.values())
		cs_fl_online = [c for c in cs if c.lists & ContactList.FL and not c.lists & ContactList.BL and not c.status.is_offlineish()]
		
		logon_payload = MultiDict([
			(b'0', arbitrary_encode(user.username)),
			(b'1', arbitrary_encode(user.username)),
			(b'8', str(len(cs_fl_online)).encode('utf-8')),
		]) # type: MultiDict[bytes, bytes]
		
		for c in cs_fl_online:
			add_contact_status_to_data(logon_payload, c.status, c.head)
		
		return logon_payload
	
	async def _check_private_chat(self, chat: Chat, other_user: User, bs: BackendSession) -> None:
		two_users = False
	
		while True:
			await asyncio.sleep(0.04)
		
			if 'ymsg_twoway_only' in chat.front_data:
				if len(list(chat.get_roster_single())) == 2:
					two_users = True
				if len(list(chat.get_roster_single())) > 2 and 'ymsg_twoway_only' in chat.front_data:
					del chat.front_data['ymsg_twoway_only']
					if 'ymsg/conf' not in chat.ids:
						chat.add_id('ymsg/conf', chat.ids['main'])
					for cs_other in chat.get_roster():
						if cs_other.user in (bs.user, other_user) and cs_other.bs.front_data.get('ymsg'):
							target_user = None
							if cs_other.user is bs.user:
								target_user = other_user
							elif cs_other.user is other_user:
								target_user = bs.user
							if 'ymsg_private_chats' in cs_other.bs.front_data:
								if target_user:
									del cs_other.bs.front_data['ymsg_private_chats'][target_user.uuid]
							bs.front_data['ymsg_chat_sessions'][chat] = cs_other
							if target_user:
								cs_other.bs.evt.on_chat_invite(chat, target_user, invite_msg='Two-way chat automatically converted to conference.')
					break
				elif len(list(chat.get_roster_single())) == 1 and two_users:
					for cs_other in chat.get_roster():
						if cs_other.user in (bs.user, other_user) and cs_other.bs.front_data.get('ymsg'):
							if cs_other.user is bs.user:
								target_user = other_user
							elif cs_other.user is other_user:
								target_user = bs.user
							if target_user:
								del cs_other.bs.front_data['ymsg_private_chats'][target_user.uuid]
								cs_other.close()
								break
	
	def _get_oims(self, user: User) -> None:
		oims = self.backend.user_service.get_oim_batch(user)
		oim_msg_dict = MultiDict()  # type: MultiDict[bytes, bytes]
	
		for oim in oims:
			oim_msg_dict.add(b'31', b'6')
			oim_msg_dict.add(b'32', b'6')
			oim_msg_dict.add(b'4', arbitrary_encode(oim.from_username or oim.from_user_id))
			oim_msg_dict.add(b'5', arbitrary_encode(user.username))
			oim_msg_dict.add(b'14', arbitrary_encode(oim.message))
			oim_msg_dict.add(b'15', str(int(oim.sent.timestamp())).encode('utf-8'))
			oim_msg_dict.add(b'97', b'1' if oim.utf8 else b'0')
    
			self.backend.user_service.delete_oim(user.uuid, oim.uuid)
	
			if len(list(oim_msg_dict.items())) > 0:
				self.send_reply(YMSGService.Message, YMSGStatus.NotInOffice, self.sess_id, oim_msg_dict)
	
	def _verify_challenge_v1(self, yahoo_id: Optional[str], resp_6: Optional[bytes], resp_96: Optional[bytes]) -> bool:
		from hashlib import md5
		
		backend = self.backend
		
		if not yahoo_id:
			return False
		
		if not resp_6:
			return False
		
		#if not resp_96:
		#	return False
		
		chal = self.challenge
		if chal is None:
			return False
		
		uuid = backend.util_get_uuid_from_username(yahoo_id)
		if uuid is None:
			return False
		
		# Retrieve Yahoo64-encoded MD5 hash of the user's passwordfrom the database
		# NOTE: The MD5 hash of the password is unsa<ed.
		pass_md5 = Y64.Y64Encode(self.backend.user_service.yahoo_get_md5_password(uuid) or b'')
		# Retrieve MD5-crypt(3)'d hash of the user's passwordfrom the database
		pass_md5crypt = Y64.Y64Encode(md5(self.backend.user_service.yahoo_get_md5crypt_password(uuid) or b'').digest())
		
		seed_val = (chal[15] % 8) % 5
		
		if seed_val == 0:
			checksum = bytes([chal[chal[7] % 16]])
			hash_p = checksum + pass_md5 + arbitrary_encode(yahoo_id) + chal
			hash_c = checksum + pass_md5crypt + arbitrary_encode(yahoo_id) + chal
		elif seed_val == 1:
			checksum = bytes([chal[chal[9] % 16]])
			hash_p = checksum + arbitrary_encode(yahoo_id) + chal + pass_md5
			hash_c = checksum + arbitrary_encode(yahoo_id) + chal + pass_md5crypt
		elif seed_val == 2:
			checksum = bytes([chal[chal[15] % 16]])
			hash_p = checksum + chal + pass_md5 + arbitrary_encode(yahoo_id)
			hash_c = checksum + chal + pass_md5crypt + arbitrary_encode(yahoo_id)
		elif seed_val == 3:
			checksum = bytes([chal[chal[1] % 16]])
			hash_p = checksum + arbitrary_encode(yahoo_id) + pass_md5 + chal
			hash_c = checksum + arbitrary_encode(yahoo_id) + pass_md5crypt + chal
		elif seed_val == 4:
			checksum = bytes([chal[chal[3] % 16]])
			hash_p = checksum + pass_md5 + chal + arbitrary_encode(yahoo_id)
			hash_c = checksum + pass_md5crypt + chal + arbitrary_encode(yahoo_id)
		
		resp_6_server = Y64.Y64Encode(md5(hash_p).digest())
		resp_96_server = Y64.Y64Encode(md5(hash_c).digest())
		
		return resp_6 == resp_6_server and resp_96 == resp_96_server
	
	def _refresh_cookies(self) -> Tuple[str, str, str, str]:
		# Creates the cookies if they don't exist
		
		assert self.t_cookie_token is not None
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		auth_service = self.backend.auth_service
		
		y_cookie = Y_COOKIE_TEMPLATE.format(encodedname=_encode_yahoo_id(user.username))
		t_cookie = T_COOKIE_TEMPLATE.format(token=self.t_cookie_token)
 
		y_expiry = 0
		t_expiry = 0
 
		try:
			_, y_expiry = auth_service.create_token('ymsg/cookie', user.username, token=y_cookie, lifetime=misc.TOKEN_LIFETIME)
			_, t_expiry = auth_service.create_token('ymsg/cookie', self.bs, token=t_cookie, lifetime=misc.TOKEN_LIFETIME)
		except:
			return None
		
		return (
			y_cookie,
			t_cookie,
			_format_cookie_expiry(datetime.datetime.utcfromtimestamp(y_expiry)),
			_format_cookie_expiry(datetime.datetime.utcfromtimestamp(t_expiry))
		)
 
Y_COOKIE_TEMPLATE = 'v=1&n=&l={encodedname}&p=&r=&lg=&intl=&np='
T_COOKIE_TEMPLATE = 'z={token}&a=&sk={token}&ks={token}&kt=&ku=&d={token}' 
YAHOO_HELPER_MSG = settings.YAHOOHELPER_MSG
 
def _format_cookie_expiry(expiry: datetime.datetime) -> str:
	return expiry.strftime('%a, %d %b %Y %H:%M:%S GMT')
 
def _encode_yahoo_id(yahoo_id: str) -> str:
	return ''.join(
		YAHOO_ID_ENCODING.get(c) or c
		for c in yahoo_id
	)
 
YAHOO_ID_ENCODING = {
	'k': 'a',
	'l': 'b',
	'm': 'c',
	'n': 'd',
	'o': 'e',
	'p': 'f',
	'q': 'g',
	'r': 'h',
	's': 'i',
	't': 'j',
	'u': 'k',
	'v': 'l',
	'w': 'm',
	'x': 'n',
	'y': 'o',
	'z': 'p',
	'0': 'q',
	'1': 'r',
	'2': 's',
	'3': 't',
	'4': 'u',
	'5': 'v',
	'7': 'x',
	'8': 'y',
	'9': 'z',
	'6': 'w',
	'a': '0',
	'b': '1',
	'c': '2',
	'd': '3',
	'e': '4',
	'f': '5',
	'g': '6',
	'h': '7',
	'i': '8',
	'j': '9',
}
 
def add_contact_status_to_data(
	data: Any, status: UserStatus, contact: User, *,
	old_substatus: Substatus = Substatus.Offline, message: Optional[str] = None,
	exclude_psm: bool = False, sess_id: Optional[int] = None,
 ) -> None:
	is_offlineish = status.is_offlineish()
	# `static var YMSG_FLD_SESSION_ID = 11;`
	# Yahoo! was weird sometimes :p
	#if user_yahoo_id in PRE_SESSION_ID:
	#	key_11_val = binascii.hexlify(struct.pack('!I', PRE_SESSION_ID[user_yahoo_id])).decode().upper()
	#elif sess_id is not None:
	#	key_11_val = binascii.hexlify(struct.pack('!I', sess_id)).decode().upper()
	#else:
	#	key_11_val = '0'
	
	data.add(b'7', arbitrary_encode(contact.username))
	
	if not message:
		message = status.message
	
	if is_offlineish or not message or exclude_psm:
		data.add(b'10', str(int(YMSGStatus.Available if is_offlineish else YMSGStatus.FromSubstatus(status.substatus))).encode('utf-8'))
		#data.add(b'11', key_11_val.encode('utf-8'))
		data.add(b'11', b'0')
	else:
		data.add(b'10', str(int(YMSGStatus.Custom)).encode('utf-8'))
		#data.add(b'11', key_11_val.encode('utf-8'))
		data.add(b'11', b'0')
		data.add(b'19', arbitrary_encode(message))
		is_away_message = (status.substatus is not Substatus.Online)
		data.add(b'47', str(int(is_away_message)).encode('utf-8'))

	checksum = misc.yahoo_avatar_checksum(contact)
	if checksum is not None and not is_offlineish:
		data.add(b'213', b'2')
		data.add(b'192', checksum)
	data.add(b'17', b'0')
	data.add(b'13', (b'0' if is_offlineish else b'1'))

def add_contact_status_to_data_v16(data: Any, status: UserStatus, contact: User) -> None:
	is_offlineish = status.is_offlineish()
	
	data.add(b'241', b'0')
	data.add(b'302', b'315')
	data.add(b'300', b'315')
	data.add(b'7', arbitrary_encode(contact.username))
	data.add(b'241', b'0')
	
	if is_offlineish or not status.message:
		data.add(b'10', str(int(YMSGStatus.Available if is_offlineish else YMSGStatus.FromSubstatus(status.substatus))).encode('utf-8'))
		data.add(b'19', b'')
		data.add(b'47', b'0')
	else:
		data.add(b'10', str(int(YMSGStatus.Custom)).encode('utf-8'))
		data.add(b'19', arbitrary_encode(status.message))
		data.add(b'47', str(int(status.substatus is not Substatus.Online)).encode('utf-8'))
	
	data.add(b'187', b'0')
	data.add(b'283', b'0')
	data.add(b'60', b'0')
	data.add(b'244', b'3071031')
	
	checksum = misc.yahoo_avatar_checksum(contact)
	data.add(b'213', (b'2' if checksum is not None else b'0'))
	data.add(b'198', b'0')
	if checksum is not None:
		data.add(b'192', checksum)
	
	data.add(b'301', b'315')
	data.add(b'303', b'315')

class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('loop', 'ctrl', 'dialect', 'sess_id', 'bs')
	
	loop: asyncio.AbstractEventLoop
	ctrl: YMSGCtrlPager
	dialect: int
	sess_id: int
	bs: BackendSession
	
	def __init__(self, loop: asyncio.AbstractEventLoop, ctrl: YMSGCtrlPager) -> None:
		self.loop = loop
		self.ctrl = ctrl
		self.dialect = ctrl.dialect
		self.sess_id = ctrl.sess_id
	
	def on_maintenance_message(self, *args: Any, **kwargs: Any) -> None:
		if args[1] is not None and args[1] > 0:
			msg = """CrossTalk will be down for maintenance in around {} minute(s). \
 Now is a good time to wrap up any conversations.""".format(args[1])
		kvs = MultiDict([
			(b'14', msg.encode('utf-8')),
			(b'15', str(time.time()).encode('utf-8')),
		]) # type: MultiDict[bytes, bytes]
		self.ctrl.send_reply(YMSGService.SystemMessage, YMSGStatus.BRB, self.sess_id, kvs)
 
	def on_client_alert(self, alert: Alert) -> bool:
		msg = alert.plain_with_link()
		kvs = MultiDict([
			(b'14', msg.encode('utf-8')),
			(b'15', str(time.time()).encode('utf-8')),
		]) # type: MultiDict[bytes, bytes]
		self.ctrl.send_reply(YMSGService.SystemMessage, YMSGStatus.BRB, self.sess_id, kvs)
		return True
	
	def on_maintenance_boot(self) -> None:
		# No maintenance-specific booting packets known as of now. Use generic booting procedure.
		
		self.ctrl.send_reply(YMSGService.LogOff, YMSGStatus.Available, 0, None)
		self.on_close()
	
	def on_presence_notification(
		self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
		trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True,
		send_status_on_bl: bool = False, sess_id: Optional[int] = None, updated_phone_info: Optional[Dict[str, Any]] = None,
	) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if on_contact_add: return
		
		if update_status or update_info_other:
			if not ctc.lists & ContactList.FL: return
			
			if self.ctrl.dialect >= 16:
				if ctc.status.is_offlineish():
					if not old_substatus.is_offlineish():
						self.ctrl.send_reply(YMSGService.LogOff, YMSGStatus.BRB, self.sess_id, MultiDict([
							(b'7', arbitrary_encode(ctc.head.username)),
						]))
					return
				if old_substatus.is_offlineish():
					self.ctrl.send_reply(YMSGService.LogOn, YMSGStatus.BRB, self.sess_id, misc.build_user_login_v16(ctc))
				else:
					self.ctrl.send_reply(YMSGService.BuddyInfo, YMSGStatus.BRB, self.sess_id, misc.build_buddy_info_v16([ctc]))
				return
			
			if ctc.status.is_offlineish() and not old_substatus.is_offlineish():
				service = YMSGService.LogOff
			elif not old_substatus.is_offlineish() and ctc.status.substatus is Substatus.Online and not ctc.status.message:
				service = YMSGService.IsBack
			else:
				if self.ctrl.dialect < 15:
					service = YMSGService.IsAway
				else:
					service = YMSGService.StatusUpdate2
			
			if not (ctc.status.is_offlineish() and old_substatus.is_offlineish()):
				yahoo_data = MultiDict() # type: MultiDict[bytes, bytes]
				if service is not YMSGService.LogOff:
					yahoo_data.add(b'0', arbitrary_encode(user.username))
				
				if old_substatus.is_offlineish() and not ctc.status.is_offlineish():
					add_contact_status_to_data(yahoo_data, ctc.status, ctc.head, old_substatus = old_substatus, exclude_psm = True, sess_id = sess_id)
					self.ctrl.send_reply(YMSGService.LogOn, YMSGStatus.BRB, self.sess_id, yahoo_data)
					
					if ctc.status.message:
						message = ctc.status.message
						
						yahoo_data = MultiDict()
						yahoo_data.add(b'0', arbitrary_encode(user.username))
						add_contact_status_to_data(yahoo_data, ctc.status, ctc.head, old_substatus = old_substatus, message = message, sess_id = sess_id)
						self.ctrl.send_reply(YMSGService.IsAway, YMSGStatus.BRB, self.sess_id, yahoo_data)
				else:
					add_contact_status_to_data(yahoo_data, ctc.status, ctc.head, old_substatus = old_substatus, sess_id = sess_id)
					
					self.ctrl.send_reply(service, YMSGStatus.BRB, self.sess_id, yahoo_data)
	
	def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True, update_info: bool = True) -> None:
		pass
	
	def on_contact_request_denied(self, user_added: User, message: str, *, contact_id: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if self.ctrl.dialect >= 16:
			self.ctrl._send_authorize_response(user_added, False, message or '')
			return
		
		self.ctrl.send_reply(YMSGService.ContactNew, YMSGStatus.OnVacation, self.sess_id, MultiDict([
			(b'1', arbitrary_encode(user.username)),
			(b'3', arbitrary_encode(contact_id or user_added.username)),
			(b'14', arbitrary_encode(message)),
		]))
	
	def on_oim_sent(self, oim: 'OIM') -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		backend = bs.backend
	
		message_dict = MultiDict([
			(b'5', arbitrary_encode(user.username)),
			(b'4', arbitrary_encode(oim.from_username or oim.from_user_id)),
			(b'14', arbitrary_encode(oim.message or '')),
			(b'63', b';0'),
			(b'64', b'0'),
			(b'97', (b'1' if oim.utf8 else b'0')),
		])	# type: MultiDict[bytes, bytes]
	
		self.ctrl.send_reply(YMSGService.Message, YMSGStatus.BRB, self.ctrl.sess_id, message_dict)
	
		backend.user_service.delete_oim(user.uuid, oim.uuid)
	
	def ymsg_on_p2p_msg_request(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		for y in misc.build_p2p_msg_packet(self.bs, sess_id, yahoo_data):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_xfer_init(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		for y in misc.build_ft_packet(self.bs, sess_id, yahoo_data):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_upload_file_ft(self, recipient: str, message: str) -> None:
		self.ctrl.send_reply(YMSGService.FileTransfer, YMSGStatus.NotAtDesk, self.sess_id, MultiDict([
			(b'1', self.bs.user.username.encode('utf-8')),
			(b'5', arbitrary_encode(recipient)),
			(b'4', self.bs.user.username.encode('utf-8')),
			(b'14', arbitrary_encode(message)),
		]))
	
	def ymsg_on_sent_ft_http(self, yahoo_id_sender: str, url_path: str, upload_time: float, message: str) -> None:
		for y in misc.build_http_ft_packet(self.bs, yahoo_id_sender, url_path, upload_time, message):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def on_circle_created(self, circle: Circle) -> None:
		pass
	
	def on_circle_updated(self, circle: Circle) -> None:
		pass
	
	def on_left_circle(self, circle: Circle) -> None:
		pass
	
	def on_accepted_circle_invite(self, circle: Circle) -> None:
		pass
	
	def on_circle_invite_revoked(self, chat_id: str) -> None:
		pass
	
	def on_circle_role_updated(self, chat_id: str, role: CircleRole) -> None:
		pass
	
	def on_chat_invite(
		self, chat: Chat, inviter: User, *, circle: bool = False, inviter_id: Optional[str] = None, invite_msg: str = '',
	) -> None:
		bs = self.bs
		assert bs is not None
		
		if circle:
			return
 
		roster = list(chat.get_roster_single())
		
		if 'ymsg_twoway_only' not in chat.front_data and len(roster) == 2:
			chat.add_id('ymsg_twoway_only', chat.ids['main'])
		elif 'ymsg_twoway_only' in chat.front_data and len(roster) >= 3:
			del chat.front_data['ymsg_twoway_only']
			if 'ymsg/conf' not in chat.ids:
				chat.add_id('ymsg/conf', chat.ids['main'])
 
		if chat.front_data.get('ymsg_twoway_only') or len(roster) < 2:
			# A Yahoo! non-conference chat; auto-accepted invite
			evt = ChatEventHandler(self.loop, self.ctrl, self.bs)
			cs = chat.join('yahoo', self.bs, evt)
			chat.send_participant_joined(cs)
			self.bs.front_data['ymsg_private_chats'][inviter.uuid] = (cs, evt)
			return
		
		conf_invite_dict = MultiDict([
			(b'1', arbitrary_encode(self.bs.user.username)),
			(b'57', arbitrary_encode(chat.ids['ymsg/conf'])),
			(b'50', arbitrary_encode(inviter_id or inviter.username)),
			(b'58', arbitrary_encode(invite_msg)),
		])  # type: MultiDict[bytes, bytes]
	
		for cs in roster:
			if cs.user.uuid == inviter.uuid:
				continue
			conf_invite_dict.add(b'52', arbitrary_encode(cs.preferred_name or cs.user.username))
			conf_invite_dict.add(b'53', arbitrary_encode(cs.preferred_name or cs.user.username))
	
		conf_invite_dict.add(b'13', arbitrary_encode(chat.front_data.get('ymsg_voice_chat') or '0'))
	
		self.ctrl.send_reply(
			YMSGService.ConfAddInvite if len(roster) > 1 else YMSGService.ConfInvite,
			YMSGStatus.BRB, self.ctrl.sess_id, conf_invite_dict,
		)
	
	def on_declined_chat_invite(self, chat: Chat, circle: bool = False) -> None:
		pass
	
	def on_added_me(self, user: User, *, adder_id: Optional[str] = None, message: Optional[TextWithData] = None) -> None:
		bs = self.bs
		assert bs is not None
		user_me = bs.user
		detail = user_me.detail
		assert detail is not None
		
		ctc = detail.contacts.get(user.uuid)
		if ctc is not None:
			if ctc.lists & ContactList.BL: return
			if ctc.lists & ContactList.FL:
				self.ctrl._clear_pending(user_me, ctc)
				self.ctrl._send_authorize_response(user, True)
				return
		
		self.ctrl._send_contact_request(user, adder_id = adder_id, message = message)

	def ymsg_on_friend_icon(self, yahoo_id_sender: str, yahoo_id_receiver: str, checksum: bytes) -> None:
		self.ctrl.send_reply(YMSGService.FriendIcon, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(yahoo_id_sender)),
			(b'5', arbitrary_encode(yahoo_id_receiver)),
			(b'192', checksum),
		]))
	
	def ymsg_on_friend_icon_download(self, yahoo_id_sender: str, yahoo_id_receiver: str, url: str, checksum: bytes) -> None:
		self.ctrl.send_reply(YMSGService.FriendIconDownload, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(yahoo_id_sender)),
			(b'5', arbitrary_encode(yahoo_id_receiver)),
			(b'13', b'2'),
			(b'20', arbitrary_encode(url)),
			(b'192', checksum),
		]))
	
	def ymsg_on_friend_icon_file_transfer(self, yahoo_id_sender: str, yahoo_id_receiver: str, url: str, filename: str, ts: str) -> None:
		self.ctrl.send_reply(YMSGService.FriendIconFileTransfer, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'5', arbitrary_encode(yahoo_id_receiver)),
			(b'20', arbitrary_encode(url)),
			(b'27', arbitrary_encode(filename)),
			(b'38', arbitrary_encode(ts)),
		]))
	
	def ymsg_on_friend_icon_flag(self, yahoo_id_sender: str, yahoo_id_receiver: str, icon_flag: bytes) -> None:
		self.ctrl.send_reply(YMSGService.DisplayTypeChanged, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(yahoo_id_sender)),
			(b'5', arbitrary_encode(yahoo_id_receiver)),
			(b'206', icon_flag),
		]))
	
	def ymsg_on_audible(self, sender: str, receiver: str, audible_id: bytes, text: bytes, checksum: bytes) -> None:
		self.ctrl.send_reply(YMSGService.Audible, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'230', audible_id),
			(b'231', text),
			(b'232', checksum),
		]))
	
	def ymsg_on_im_panel_feature(self, sender: str, receiver: str, feature: bytes, state: bytes) -> None:
		self.ctrl.send_reply(YMSGService.IMPanelFeature, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'221', feature),
			(b'222', state),
		]))
	
	def ymsg_on_im_session(self, sender: str, receiver: str, flag: bytes) -> None:
		self.ctrl.send_reply(YMSGService.IMSession, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'13', flag),
		]))
	
	def ymsg_on_message_ack(self, sender: str, receiver: str, msg_id: bytes) -> None:
		self.ctrl._on_recipient_ack(msg_id)

	def ymsg_on_imvironment(self, sender: str, receiver: str, imv: bytes, state: bytes) -> None:
		self.ctrl.send_reply(YMSGService.P2PFileXfer, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'1', arbitrary_encode(receiver)),
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'49', b'IMVIRONMENT'),
			(b'63', imv),
		]))
	
	def ymsg_on_photo_add(
		self, sender: str, receiver: str, photo_id: bytes,
		name: bytes | None, thumbnail: bytes | None, url: bytes | None,
	) -> None:
		for y in misc.build_photo_notify_packet(sender, receiver, photo_id, name = name, thumbnail = thumbnail, url = url):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_photo_ack(self, sender: str, receiver: str, photo_id: bytes) -> None:
		self.ctrl.send_reply(YMSGService.PhotoAdd, YMSGStatus.Ack, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'245', photo_id),
		]))
	
	def ymsg_on_photo_select(self, sender: str, receiver: str, photo_id: bytes, action: bytes) -> None:
		self.ctrl.send_reply(YMSGService.PhotoSelect, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'245', photo_id),
			(b'194', action),
		]))
	
	def ymsg_on_photo_relay(
		self, sender: str, receiver: str, photo_id: bytes, token: bytes, *,
		relay_host: bytes, filesize: bytes | None, ack: bool,
	) -> None:
		status = YMSGStatus.Ack if ack else YMSGStatus.BRB
		for y in misc.build_photo_relay_packet(
			sender, receiver, photo_id, token, relay_host = relay_host, filesize = filesize, status = status,
		):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_ft_invite(self, sender: str, receiver: str, cookie: bytes, yahoo_data: MultiDict[bytes, bytes]) -> None:
		kvs = MultiDict([
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'265', cookie),
			(b'222', yahoo_data.get(b'222') or b'1'),
		]) # type: MultiDict[bytes, bytes]
		
		if (yahoo_data.get(b'222') or b'1') == b'1':
			kvs.add(b'266', yahoo_data.get(b'266') or b'1')
			kvs.add(b'302', b'268')
			kvs.add(b'300', b'268')
			if yahoo_data.get(b'27') is not None: kvs.add(b'27', yahoo_data.get(b'27') or b'')
			if yahoo_data.get(b'28') is not None: kvs.add(b'28', yahoo_data.get(b'28') or b'')
			kvs.add(b'301', b'268')
			kvs.add(b'303', b'268')
			if yahoo_data.get(b'267') is not None: kvs.add(b'267', yahoo_data.get(b'267') or b'')
		
		self.ctrl.send_reply(YMSGService.FileTransferInvite, YMSGStatus.BRB, self.sess_id, kvs)
	
	def ymsg_on_ft_setup(
		self, sender: str, receiver: str, cookie: bytes, *,
		filename: bytes, relay_host: bytes, peer_path: bytes, transfer_type: bytes,
	) -> None:
		self.ctrl.send_reply(YMSGService.PeerSetup, YMSGStatus.BRB, self.sess_id, MultiDict([
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'265', cookie),
			(b'27', filename),
			(b'249', transfer_type),
			(b'250', relay_host),
			(b'251', peer_path),
		]))
	
	def ymsg_on_ft_init(
		self, sender: str, receiver: str, cookie: bytes, yahoo_data: MultiDict[bytes, bytes], *, cancelled: bool = False,
	) -> None:
		kvs = MultiDict([
			(b'4', arbitrary_encode(sender)),
			(b'5', arbitrary_encode(receiver)),
			(b'265', cookie),
		]) # type: MultiDict[bytes, bytes]
		if cancelled:
			kvs.add(b'66', b'-1')
			self.ctrl.send_reply(YMSGService.PeerInit, YMSGStatus.LoginError, self.sess_id, kvs)
			return
		if yahoo_data.get(b'27') is not None: kvs.add(b'27', yahoo_data.get(b'27') or b'')
		if yahoo_data.get(b'249') is not None: kvs.add(b'249', yahoo_data.get(b'249') or b'3')
		if yahoo_data.get(b'251') is not None: kvs.add(b'251', yahoo_data.get(b'251') or b'')
		self.ctrl.send_reply(YMSGService.PeerInit, YMSGStatus.BRB, self.sess_id, kvs)

	def ymsg_on_buddy_response(self, buddy: User, accepted: bool, message: str = '') -> None:
		self.ctrl._send_authorize_response(buddy, accepted, message)
		
	def on_removed_me(self, user: User) -> None:
		pass
	
	def on_login_elsewhere(self, option: LoginOption) -> None:
		self.ctrl.send_reply(YMSGService.LogOff, YMSGStatus.LoginError, self.sess_id, None)
		self.ctrl.close()
	
	def on_close(self) -> None:
		self.ctrl.close()
 
class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('loop', 'ctrl', 'bs', 'cs')
	
	loop: asyncio.AbstractEventLoop
	ctrl: YMSGCtrlPager
	bs: BackendSession
	cs: ChatSession
	
	def __init__(self, loop: asyncio.AbstractEventLoop, ctrl: YMSGCtrlPager, bs: BackendSession) -> None:
		self.loop = loop
		self.ctrl = ctrl
		self.bs = bs
	
	def on_close(self) -> None:
		assert self.bs is not None
		self.bs.front_data['ymsg_chat_sessions'].pop(self.cs.chat, None)
	
	def on_participant_joined(self, cs_other: ChatSession, first_pop: bool, initial_join: bool) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if self.cs.chat.front_data.get('ymsg_twoway_only') or not first_pop:
			return
		else:
			if 'ymsg/conf' not in self.cs.chat.ids:
				self.cs.chat.add_id('ymsg/conf', self.cs.chat.ids['main'])
			self.ctrl.send_reply(YMSGService.ConfLogon, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
				(b'1', arbitrary_encode(user.username)),
				(b'57', arbitrary_encode(cs_other.chat.ids['ymsg/conf'])),
				(b'53', arbitrary_encode(cs_other.preferred_name or cs_other.user.username)),
			]))
	
	def on_participant_left(self, cs_other: ChatSession, last_pop: bool) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if 'ymsg/conf' not in cs_other.chat.ids:
			# Yahoo only receives this event in "conferences"
			return
		if not last_pop:
			return
		self.ctrl.send_reply(YMSGService.ConfLogoff, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			(b'1', arbitrary_encode(user.username)),
			(b'57', arbitrary_encode(cs_other.chat.ids['ymsg/conf'])),
			(b'56', arbitrary_encode(cs_other.preferred_name or cs_other.user.username)),
		]))
	
	def on_chat_invite_declined(
		self, chat: Chat, invitee: User, *, invitee_id: Optional[str] = None, message: Optional[str] = None, circle: bool = False,
	) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if circle: return
		self.ctrl.send_reply(YMSGService.ConfDecline, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			(b'1', user.username.encode('utf-8')),
			(b'57', arbitrary_encode(chat.ids['ymsg/conf'])),
			(b'54', arbitrary_encode(invitee_id or invitee.username)),
			(b'14', arbitrary_encode(message or '')),
		]))
	
	def on_chat_updated(self) -> None:
		pass
	
	def on_chat_roster_updated(self) -> None:
		pass
	
	def on_participant_status_updated(self, cs_other: ChatSession, first_pop: bool, initial: bool, old_substatus: Substatus) -> None:
		pass
	
	def on_message(self, data: MessageData) -> None:
		ctrl = self.ctrl
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		sender = data.sender
		yahoo_data = messagedata_to_ymsg(data)
		roster = list(self.cs.chat.get_roster_single()) 
		
		if data.type in (MessageType.Chat,MessageType.Nudge):
			if self.cs.chat.front_data.get('ymsg_twoway_only') or len(roster) <= 2:
				if self.ctrl.dialect >= 16:
					message_to_dict = MultiDict([
						(b'4', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
						(b'5', yahoo_data.get(b'5') or arbitrary_encode(user.username)),
						(b'97', yahoo_data.get(b'97') or b'1'),
						(b'63', yahoo_data.get(b'63') or b';0'),
						(b'64', yahoo_data.get(b'64') or b'0'),
						(b'206', yahoo_data.get(b'206') or b'2'),
						(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or '')),
					]) # type: MultiDict[bytes, bytes]
					if yahoo_data.get(b'429') is not None:
						message_to_dict.add(b'429', yahoo_data.get(b'429') or b'')
				else:
					message_to_dict = MultiDict([
						(b'5', yahoo_data.get(b'5') or arbitrary_encode(user.username)),
						(b'4', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
						(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or '')),
					])
					
					if yahoo_data.get(b'63') is not None:
						message_to_dict.add(b'63', yahoo_data.get(b'63') or b'')
					
					if yahoo_data.get(b'64') is not None:
						message_to_dict.add(b'64', yahoo_data.get(b'64') or b'')
					
					if yahoo_data.get(b'97') is not None:
						message_to_dict.add(b'97', yahoo_data.get(b'97') or b'')
				self.ctrl.send_reply(YMSGService.Message, YMSGStatus.BRB, self.ctrl.sess_id, message_to_dict)
			else:
				if data.type is not MessageType.Nudge:
					conf_message_dict = MultiDict([
						(b'1', arbitrary_encode(user.username)),
						(b'57', arbitrary_encode(self.cs.chat.ids['ymsg/conf'])),
						(b'3', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
						(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or '')),
					])
					
					if yahoo_data.get(b'97') is not None:
						conf_message_dict.add(b'97', yahoo_data.get(b'97') or b'')
					
					self.ctrl.send_reply(YMSGService.ConfMsg, YMSGStatus.BRB, self.ctrl.sess_id, conf_message_dict)
		elif data.type in (MessageType.Typing,MessageType.TypingDone):
			if self.cs.chat.front_data.get('ymsg_twoway_only') or len(roster) <= 2:
				typing_status = YMSGStatus.BRB if (self.ctrl.dialect <= 12 or self.ctrl.dialect >= 16) else YMSGStatus.Typing
				self.ctrl.send_reply(YMSGService.Notify, typing_status, self.ctrl.sess_id, MultiDict([
					(b'4', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
					(b'5', yahoo_data.get(b'5') or arbitrary_encode(user.username)),
					(b'13', yahoo_data.get(b'13') or (b'0' if data.type is MessageType.TypingDone else b'1')),
					(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or ' ')),
					(b'49', b'TYPING'),
				]))
		elif data.type is MessageType.Webcam:
			kvs = MultiDict([
				(b'5', yahoo_data.get(b'5') or arbitrary_encode(user.username)),
				(b'4', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
				(b'49', b'WEBCAMINVITE'),
				(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or ' ')),
			]) # type: MultiDict[bytes, bytes]
			self.ctrl.send_reply(YMSGService.Notify, YMSGStatus.BRB, self.ctrl.sess_id, kvs)
	
	def _send_when_user_joins(self, user_uuid: str, data: MessageData) -> None:
		# Send to everyone currently in chat
		self.cs.send_message_to_everyone(data)
		
		if self._user_in_chat(user_uuid):
			return
		
		# If `user_uuid` hasn't joined yet, send it later
		self.loop.create_task(self._send_delayed(user_uuid, data))
	
	async def _send_delayed(self, user_uuid: str, data: MessageData) -> None:
		delay = 0.1
		for _ in range(3):
			await asyncio.sleep(delay)
			delay *= 3
			if self._user_in_chat(user_uuid):
				self.cs.send_message_to_user(user_uuid, data)
				return
	
	def _user_in_chat(self, user_uuid: str) -> bool:
		for cs_other in self.cs.chat.get_roster():
			if cs_other.user.uuid == user_uuid:
				return True
		return False
 
def messagedata_from_ymsg(
	sender: User, data: MultiDict[bytes, bytes], *, notify_type: Optional[bytes] = None, typing_flag: Optional[str] = None,
 ) -> MessageData:
	text = arbitrary_decode(data.get(b'14') or b'')
	
	if notify_type is None:
		if text == '<ding>':
			type = MessageType.Nudge
			text = ''
		else:
			type = MessageType.Chat
	elif notify_type == b'TYPING':
		if typing_flag == '0':
			type = MessageType.TypingDone
		else:
			type = MessageType.Typing
	elif notify_type == b'WEBCAMINVITE':
		type = MessageType.Webcam
	else:
		# TODO: other `notify_type`s
		raise Exception("Unknown notify_type", notify_type)
	
	message = MessageData(sender = sender, type = type, text = text)
	message.front_cache['ymsg'] = data
	return message
 
def messagedata_to_ymsg(data: MessageData) -> MultiDict[bytes, bytes]:
	if 'ymsg' not in data.front_cache:
		data.front_cache['ymsg'] = MultiDict([
			(b'14', (b'<ding>' if data.type is MessageType.Nudge else arbitrary_encode(data.text or ''))),
			(b'63', b';0'),
			(b'64', b'0'),
			(b'97', b'1'),
			(b'206', b'2')
		])
	return data.front_cache['ymsg']
 
def me_status_update(bs: BackendSession, status_new: YMSGStatus, *, message: str = '', is_away_message: bool = False) -> None:
	bs.front_data['ymsg_status'] = status_new
	if status_new is YMSGStatus.Custom:
		substatus = (Substatus.Busy if is_away_message else Substatus.Online)
	else:
		substatus = YMSGStatus.ToSubstatus(status_new)
	bs.me_update({
		'message': message,
		'substatus': substatus,
		'notify_status': True,
		'notify_info': (True if message else False),
	})
 
def send_system_message(self, message):
	msg = f"{message}"
	kvs = MultiDict([
		(b'14', msg.encode('utf-8')),
		(b'15', str(time.time()).encode('utf-8')),
	]) # type: MultiDict[bytes, bytes]
	self.send_reply(YMSGService.SystemMessage, YMSGStatus.BRB, self.sess_id, kvs)
 
def generate_challenge_v1() -> bytes:
	from uuid import uuid4
	
	# Yahoo64-encode the raw 16 bytes of a UUID
	return Y64.Y64Encode(uuid4().bytes)