from typing import Dict, List, Set, Any, Tuple, Optional, Iterable, Callable
from abc import ABCMeta, abstractmethod
from datetime import datetime
import asyncio, traceback, settings, smtplib, pprint, re
from collections import defaultdict, deque
from enum import IntFlag

from util.misc import gen_uuid, first_in_iterable, run_loop, Runner, server_temp_cleanup

from .user import UserService
from .auth import AuthService, LoginAuthService, GenTokenStr
from .stats import Stats
from .client import Client
from .abuse import AbuseService, RATED_MESSAGE_TYPES
from .models import (
	User, UserDetail, Group, ContactList, OIM, Contact, ContactDetail, Circle, CircleRole, CircleState,
	CircleMembership, Chatroom, UserStatus, TextWithData, MessageData, MessageType, Substatus, LoginOption, _is_blocking,
)
from . import error, event
from .alerts import Alert

class Ack(IntFlag):
	Zero = 0
	NAK = 1
	ACK = 2
	Full = 3

class Backend:
	__slots__ = (
		'user_service', 'auth_service', 'login_auth_service', 'loop', 'notify_maintenance', 'maintenance_mode', 'maintenance_mins',  '_stats', '_sc',
		'_chats_by_id', '_cses_by_bs_by_circle_id', '_user_by_uuid', '_worklist_sync_db', '_worklist_sync_circles',
		'_worklist_notify', '_worklist_notify_self', '_runners', '_linked', '_dev', 'recent_alerts', 'on_user_deleted',
		'_watches', 'abuse',
	)
	
	user_service: UserService
	auth_service: AuthService
	login_auth_service: LoginAuthService
	loop: asyncio.AbstractEventLoop
	notify_maintenance: bool
	maintenance_mode: bool
	maintenance_mins: int
	_stats: Stats
	_sc: '_SessionCollection'
	_chats_by_id: Dict[Tuple[str, str], 'Chat']
	_cses_by_bs_by_circle_id: Dict[str, Dict['BackendSession', Optional['ChatSession']]]
	_user_by_uuid: Dict[str, User]
	_worklist_sync_db: Dict[User, UserDetail]
	_worklist_sync_circles: Dict[str, Circle]
	_worklist_notify: List[Tuple['BackendSession', Optional[int], bool, Substatus, Optional[Dict[str, Any]], bool, bool, bool]]
	_worklist_notify_self: List[Tuple['BackendSession', Substatus, bool, bool]]
	_runners: List[Runner]
	_linked: bool
	_dev: Optional[Any]
	recent_alerts: 'deque[Dict[str, Any]]'
	on_user_deleted: Optional[Callable[[str, str], None]]
	_watches: '_WatchRegistry'
	abuse: AbuseService

	def __init__(self,
		loop: asyncio.AbstractEventLoop, *,
		user_service: UserService, login_auth_service: LoginAuthService, auth_service: AuthService, stats_service: Stats,
	) -> None:
		self.user_service = user_service
		self.auth_service = auth_service
		self.login_auth_service = login_auth_service
		self.loop = loop
		self.notify_maintenance = False
		self.maintenance_mode = False
		self.maintenance_mins = 0
		self._stats = stats_service
		self._sc = _SessionCollection()
		self._chats_by_id = {}
		self._cses_by_bs_by_circle_id = {}
		self._user_by_uuid = {}
		self._worklist_sync_db = {}
		self._worklist_sync_circles = {}
		self._worklist_notify = []
		self._worklist_notify_self = []
		self._runners = []
		self._linked = False
		self._dev = None
		self.recent_alerts = deque(maxlen = 50)
		self.on_user_deleted = None
		self._watches = _WatchRegistry()
		self.abuse = AbuseService(self)

		server_temp_cleanup()
		for circle in self.user_service.get_all_circles():
			self.chat_create(circle = circle)
			print(f'[Circle] <Info> {circle.name} (ID: {circle.chat_id}) initalized')
		
		loop.create_task(self._worker_sync_db())
		loop.create_task(self._worker_remove_expired_login_tokens())
		loop.create_task(self._worker_sync_circles())
		loop.create_task(self._worker_clean_sessions())
		loop.create_task(self._worker_sync_stats())
		loop.create_task(self._worker_notify())
		loop.create_task(self._worker_notify_self())
		loop.create_task(self._worker_purge_suspended())

	def push_client_alert(self, alert: Alert) -> int:
		print(f"[Backend] Pushing system alert")
		delivered = 0
		for bs in self._sc.iter_sessions():
			if bs.evt.on_client_alert(alert):
				delivered += 1
		return delivered

	def push_maintenance_message(self, *args: Any, **kwargs: Any) -> None:
		print(f"[Backend] Server going down for maintenance in {args[1]} minutes. Pushing system alert")
		for bs in self._sc.iter_sessions():
			bs.evt.on_maintenance_message(*args, **kwargs)
		
		if isinstance(args[1], int) and args[1] >= 0:
			self.notify_maintenance = True
			self.maintenance_mins = args[1]
			self.loop.create_task(self._worker_set_server_maintenance())
	
	async def _worker_set_server_maintenance(self) -> None:
		while self.maintenance_mins > 0:
			await asyncio.sleep(60)
			self.maintenance_mins -= 1
		
		if self.maintenance_mins <= 0:
			self.notify_maintenance = False
			self.maintenance_mode = True
			for bs in self._sc._sessions.copy():
				bs.evt.on_maintenance_boot()
			server_temp_cleanup()
	
	def add_runner(self, runner: Runner) -> None:
		self._runners.append(runner)
	
	def run_forever(self) -> None:
		run_loop(self.loop, self._runners)
	
	def on_leave(self, sess: 'BackendSession', *, sess_id: Optional[int] = None) -> None:
		user = sess.user
		old_substatus = user.status.substatus
		self._stats.on_logout()
		self._sc.remove_session(sess)
		# a closed session's client-side buddy list goes with it
		self._watches.remove_session(sess)
		print(f"[Presence] <Info> BackendSession {str(id(sess))} belonging to {user.username} ({user.email}) has been closed")
		if self._sc.get_sessions_by_user(user):
			# There are still other people logged in as this user,
			# so don't send offline notifications.
			self._notify_contacts(sess, old_substatus, for_logout = False, update_status = False)
			self._notify_self(sess, old_substatus, update_status = False)
			return
		
		# User is offline, send notifications
		user.status.substatus = Substatus.Offline
		self._sync_contact_statuses(user)
		self._notify_contacts(sess, old_substatus, for_logout = True)
	
	def login(
		self, uuid: str, client: Client, evt: event.BackendEventHandler, *,
		option: Optional[LoginOption] = None, only_once: bool = False,
	) -> Optional['BackendSession']:
		user = self._load_user_record(uuid)
		if user is None: return None
		bs_others = self._sc.get_sessions_by_user(user)
		if only_once and bs_others:
			return None
		self.user_service.update_date_login(uuid)
		
		for bs_other in bs_others:
			try:
				if option:
					bs_other.evt.on_login_elsewhere(option)
				else:
					return None
			except:
				traceback.print_exc()
		
		bs = BackendSession(self, user, client, evt)
		bs.evt.bs = bs
		self._stats.on_login()
		self._stats.on_user_active(user, client)
		self._sc.add_session(bs)
		self._stats.on_online(self._sc.session_count())
		user.detail = self._load_detail(user)
		print(f"[Presence] <Info> {user.username} ({user.email}) has logged in with BackendSession ID {str(id(bs))}")
		print(f"[Presence] <Info> They are using {client.program.upper()} {client.version} via {client.via}")
		bs.evt.on_open()
		return bs
	
	def _load_user_record(self, uuid: str) -> Optional[User]:
		if uuid not in self._user_by_uuid:
			user = self.user_service.get(uuid)
			if user is None: return None
			self._user_by_uuid[uuid] = user
		return self._user_by_uuid[uuid]
	
	def _load_detail(self, user: User) -> UserDetail:
		if user.detail: return user.detail
		pending = self._worklist_sync_db.get(user)
		if pending is not None: return pending
		detail = self.user_service.get_detail(user.uuid)
		assert detail is not None
		return detail
	
	def chat_create(self, *, circle: Optional[Circle] = None) -> 'Chat':
		return Chat(self, self._stats, circle = circle)
	
	def chat_get(self, scope: str, id: str) -> Optional['Chat']:
		return self._chats_by_id.get((scope, id))
	
	def get_chats_by_scope(self, scope: str) -> Iterable['Chat']:
		return [chat for (scope_other, _), chat in self._chats_by_id.items() if scope_other is scope]
	
	def join_circle(
		self, chat_id: str, origin: str, bs: 'BackendSession', evt: event.ChatEventHandler, *, pop_id: Optional[str] = None,
	) -> Optional['ChatSession']:
		chat = self.chat_get('persistent', chat_id)
		
		if chat is None: return None
		
		cs = chat.join(origin, bs, evt, pop_id = pop_id)
		if chat_id not in self._cses_by_bs_by_circle_id:
			self._cses_by_bs_by_circle_id[chat_id] = {}
		self._cses_by_bs_by_circle_id[chat_id][bs] = cs
		
		return cs
	
	def get_circle_cs(self, chat_id: str, bs: 'BackendSession') -> Optional['ChatSession']:
		if chat_id not in self._cses_by_bs_by_circle_id: return None
		
		return self._cses_by_bs_by_circle_id[chat_id].get(bs)
	
	def _sync_contact_statuses(self, user: User) -> None:
		detail = user.detail
		if detail is None: return
		for ctc in detail.contacts.values():
			if ctc.lists & ContactList.FL:
				ctc.compute_visible_status(user)
			
			# If the contact lists ever become inconsistent (FL without matching RL),
			# the contact that's missing the RL will always see the other user as offline.
			# Because of this, and the fact that most contacts *are* two-way, and it
			# not being that much extra work, I'm leaving this line commented out.
			#if not ctc.lists & ContactList.RL: continue
			
			if ctc.head.detail is None: continue
			ctc_rev = ctc.head.detail.contacts.get(user.uuid)
			if ctc_rev is None: continue
			ctc_rev.compute_visible_status(ctc.head)
	
	def _notify_contacts(
		self, bs: 'BackendSession', old_substatus: Substatus, *, for_logout: bool = False, sess_id: Optional[int] = None,
		on_contact_add: bool = False, updated_phone_info: Optional[Dict[str, Any]] = None, update_status: bool = True,
		update_info_other: bool = True,
	) -> None:
		self._worklist_notify.append((
			bs, sess_id, on_contact_add, old_substatus, updated_phone_info, update_status, update_info_other, for_logout,
		))
	
	def _notify_self(self, bs: 'BackendSession', old_substatus: Substatus, *, update_status: bool = True, update_info: bool = True) -> None:
		self._worklist_notify_self.append((bs, old_substatus, update_status, update_info))
	
	def notify_whats_new(self, user: User) -> None:
		# `user` has a new "What's New" activity: their own places and every contact watching them get to refetch it
		for bs in self._sc.get_sessions_by_user(user):
			bs.evt.msn_on_whats_new(user)
		detail = self._load_detail(user)
		for ctc in detail.contacts.values():
			if ctc.lists & ContactList.BL: continue
			for bs_other in self._sc.get_sessions_by_user(ctc.head):
				detail_other = bs_other.user.detail
				if detail_other is None: continue
				ctc_me = detail_other.contacts.get(user.uuid)
				if ctc_me is None or not ctc_me.lists & ContactList.FL: continue
				bs_other.evt.msn_on_whats_new(user)
	
	def _mark_modified(self, user: User, *, detail: Optional[UserDetail] = None) -> None:
		ud = user.detail or detail
		if detail: assert ud is detail
		#assert ud is not None
		self._worklist_sync_db[user] = ud
	
	def _mark_circle_modified(self, circle: Circle) -> None:
		self._worklist_sync_circles[circle.chat_id] = circle
	
	def util_get_user_email(self, user: User) -> str:
		return self.user_service.get_user_email(user)

	def util_get_display_email(self, user: User) -> str:
		return self.user_service.get_display_email(user)

	def util_get_uuid_from_email(self, email: str) -> Optional[str]:
		return self.user_service.lookup_uuid_by_email(email)
	
	def util_get_uuid_from_username(self, username: str) -> Optional[str]:
		return self.user_service.get_uuid_username(username)

	def util_get_uuid_from_user_id(self, uid: int) -> Optional[str]:
		return self.user_service.get_uuid_user_id(uid)

	def util_get_uuid_from_uin(self, uin: int) -> Optional[str]:
		return self.user_service.get_uuid_uin(uin)

	def util_get_uuid_from_screenname(self, name: str) -> Optional[str]:
		# OSCAR and ICQ name an account by its screen name or by its UIN; an all-digit name is tried as a UIN first,
		# falling back to a screen name that happens to be all digits
		name = name.replace(' ', '')
		if _UIN_RE.match(name) is not None:
			uuid = self.util_get_uuid_from_uin(int(name))
			if uuid is not None:
				return uuid
		return self.util_get_uuid_from_username(name)

	def util_get_uuids_for_login(self, name: str) -> List[str]:
		# every account a login name could mean, so a numeric screen name and someone else's UIN can both still sign on
		name = name.replace(' ', '')
		uuids = [] # type: List[str]
		if _UIN_RE.match(name) is not None:
			uuid = self.util_get_uuid_from_uin(int(name))
			if uuid is not None:
				uuids.append(uuid)
		uuid = self.util_get_uuid_from_username(name)
		if uuid is not None and uuid not in uuids:
			uuids.append(uuid)
		return uuids

	def util_watch(self, bs: 'BackendSession', uuid: str) -> None:
		# a session-only interest in someone's presence (OSCAR's client-side buddy list), kept out of the stored contact list
		self._watches.add(bs, uuid)

	def util_unwatch(self, bs: 'BackendSession', uuid: str) -> None:
		self._watches.remove(bs, uuid)

	def util_unwatch_all(self, bs: 'BackendSession') -> None:
		self._watches.remove_session(bs)

	def util_get_watched(self, bs: 'BackendSession') -> Set[str]:
		return self._watches.watched_by(bs)

	def util_get_watchers(self, uuid: str) -> List['BackendSession']:
		return self._watches.watchers_of(uuid)

	def util_message_allowed(self, user: User, data: MessageData) -> bool:
		if data.type not in RATED_MESSAGE_TYPES: return True
		if 'abuse_allowed' not in data.front_cache:
			data.front_cache['abuse_allowed'] = self.abuse.allow_message(user)
		return bool(data.front_cache['abuse_allowed'])

	def util_set_sess_token(self, sess: 'BackendSession', token: str) -> None:
		self._sc.set_nc_by_token(sess, token)
	
	def util_get_sess_by_token(self, token: str) -> Optional['BackendSession']:
		return self._sc.get_nc_by_token(token)
	
	def util_get_sessions_by_user(self, user: User) -> List['BackendSession']:
		return self._sc.get_sessions_by_user(user)
	
	def util_contact_groups(self, user: User) -> List[Group]:
		detail = self._load_detail(user)
		return sorted(detail._groups_by_id.values(), key = lambda group: (not group.is_favorite, group.name.lower()))

	def util_add_contact(
		self, user: User, contact_uuid: str, *, group_id: Optional[str] = None, new_group: Optional[str] = None,
	) -> Tuple[bool, Optional[Group]]:
		detail = self._load_detail(user)
		group = None
		if group_id is not None:
			group = detail.get_group_by_id(group_id)
			if group is None:
				raise error.GroupDoesNotExist()
		old_ctc = detail.contacts.get(contact_uuid)
		already = old_ctc is not None and bool(old_ctc.lists & ContactList.FL) and bool(old_ctc.lists & ContactList.AL)
		if group is not None and old_ctc is not None and old_ctc.lists & ContactList.FL and old_ctc.group_in_entry(group):
			group = None
		if already and group is None and new_group is None:
			return False, None
		sessions = self._sc.get_sessions_by_user(user)
		if sessions:
			session = sessions[0] # type: Any
		else:
			session = _OfflineSessionShim(self, user)
			user.detail = detail
		try:
			if new_group is not None:
				group = BackendSession.me_group_add(session, new_group)
			if not already:
				BackendSession.me_contact_add(session, contact_uuid, ContactList.FL | ContactList.AL, needs_notify = True)
			if group is not None:
				BackendSession.me_group_contact_add(session, group.id, contact_uuid)
		finally:
			if not sessions:
				user.detail = None
		for bs in sessions:
			bs.evt.msn_on_notify_ab()
		return not already, group
	
	def util_add_group(self, user: User, name: str) -> Group:
		detail = self._load_detail(user)
		sessions = self._sc.get_sessions_by_user(user)
		if sessions:
			session = sessions[0] # type: Any
		else:
			session = _OfflineSessionShim(self, user)
			user.detail = detail
		try:
			group = BackendSession.me_group_add(session, name)
		finally:
			if not sessions:
				user.detail = None
		for bs in sessions:
			bs.evt.msn_on_notify_ab()
		return group
	
	def util_contact_states(self, user: User, uuids: Iterable[str]) -> Dict[str, str]:
		detail = self._load_detail(user)
		states: dict[str, str] = {}
		for uuid in uuids:
			if uuid == user.uuid:
				states[uuid] = 'self'
				continue
			ctc = detail.contacts.get(uuid)
			if ctc is None or not ctc.lists & ContactList.FL:
				states[uuid] = 'none'
			elif ctc.lists & ContactList.BL:
				states[uuid] = 'blocked'
			else:
				states[uuid] = 'contact'
		return states
	
	def util_delete_circle(self, circle: Circle) -> List[User]:
		members = [membership.head for membership in circle.memberships.values() if membership.state != CircleState.Empty]
		chat = self.chat_get('persistent', circle.chat_id)
		if chat is not None:
			for cs in list(chat.get_roster()):
				cs.close()
			for scope, chat_id in list(chat.ids.items()):
				self._chats_by_id.pop((scope, chat_id), None)
		self._cses_by_bs_by_circle_id.pop(circle.chat_id, None)
		self._worklist_sync_circles.pop(circle.chat_id, None)
		self.user_service.delete_circle(circle.chat_id)
		for user in members:
			for bs in self.util_get_sessions_by_user(user):
				bs.evt.on_left_circle(circle)
		print(f'[Circle] <Info> {circle.name} (ID: {circle.chat_id}) has been deleted')
		return members
	
	def util_delete_user(self, uuid: str) -> Optional[User]:
		user = self._load_user_record(uuid)
		if user is None:
			return None
		for bs in self.util_get_sessions_by_user(user):
			try:
				bs.close()
			except Exception:
				traceback.print_exc()
		for other in list(self._user_by_uuid.values()):
			if other is not user and other.detail is not None:
				other.detail.contacts.pop(uuid, None)
		for pending in self._worklist_sync_db.values():
			if pending is not None:
				pending.contacts.pop(uuid, None)
		self._worklist_sync_db.pop(user, None)
		
		new_owners: dict[str, Circle] = {}
		for circle in self.user_service.get_all_circles():
			membership = circle.memberships.get(uuid)
			if membership is None and circle.owner_uuid != uuid:
				continue
			others = sorted((
				m for m in circle.memberships.values()
				if m.head.uuid != uuid and m.state == CircleState.Accepted and CircleRole.Admin <= m.role <= CircleRole.Member
			), key = lambda m: int(m.role))
			admins_left = [m for m in others if m.role == CircleRole.Admin]
			was_admin = membership is not None and membership.role == CircleRole.Admin and membership.state != CircleState.Empty
			if circle.owner_uuid == uuid or (was_admin and not admins_left):
				if not others:
					self.util_delete_circle(circle)
					continue
				successor = others[0]
				successor.role = CircleRole.Admin
				if circle.owner_uuid == uuid:
					circle.owner_id = successor.head.id
					circle.owner_uuid = successor.head.uuid
					circle.owner_friendly = successor.head.status.name or successor.head.email
					new_owners[circle.chat_id] = circle
				print(f"[Circle] <Info> {successor.head.username} ({successor.head.email}) now runs {circle.name} (ID: {circle.chat_id})")
			circle.memberships.pop(uuid, None)
			chat = self.chat_get('persistent', circle.chat_id)
			if chat is not None:
				for cs_other in chat.get_roster():
					if cs_other.user is not user:
						cs_other.bs.evt.on_circle_updated(circle)
			self._mark_circle_modified(circle)
		
		if not self.user_service.delete_user(uuid, new_owners):
			return None
		self._user_by_uuid.pop(uuid, None)
		return user
	
	def util_purge_suspended(self, now: Optional[datetime] = None) -> List[str]:
		days = getattr(settings, 'SUSPENDED_ACCOUNT_DAYS', None)
		if days is None:
			return []
		deleted = []
		for uuid in self.user_service.expired_suspensions(int(days), now):
			try:
				user = self.util_delete_user(uuid)
			except Exception:
				traceback.print_exc()
				continue
			if user is None:
				continue
			print(f"[Backend] <Info> {user.username} ({user.email}) was suspended over {days} days ago and has been deleted")
			deleted.append(uuid)
			if self.on_user_deleted is not None:
				self.on_user_deleted(uuid, 'suspended')
		return deleted
	
	def util_contact_state(self, user: User, contact: User) -> str:
		if user.uuid == contact.uuid:
			return 'self'
		ctc = self._load_detail(user).contacts.get(contact.uuid)
		if ctc is None or not ctc.lists & ContactList.FL:
			return 'none'
		if ctc.lists & ContactList.BL:
			return 'blocked'
		return 'contact'
	
	def util_get_circle_memberships_by_role(self, circle: Circle, role: CircleRole) -> Iterable[CircleMembership]:
		return [membership for membership in circle.memberships.values() if membership.role == role]
	
	def util_user_online_in_circle(self, circle: Circle, user: User) -> bool:
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = self.chat_get('persistent', circle.chat_id)
		if chat is None: return False
		
		for cs in chat.get_roster_single():
			if cs.user is user: return True
		return False
	
	def util_accept_circle_invite(self, circle: Circle, user: User) -> None:
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = self.chat_get('persistent', circle.chat_id)
		membership = circle.memberships[user.uuid]
		
		if not (membership.role == CircleRole.StatePendingOutbound and membership.state == CircleState.WaitingResponse):
			if membership.state == CircleState.Rejected or membership.state == CircleState.Empty:
				raise error.MemberNotInCircle()
			raise error.MemberAlreadyInCircle()
		
		membership.role = CircleRole.Member
		membership.state = CircleState.Accepted
		
		if membership.invite_message is not None:
			membership.invite_message = None
		
		self._mark_circle_modified(circle)
		
		if chat is not None:
			print(f"[Circle] <Info> {user.username} ({user.email}) has joined {circle.name} (ID: {circle.chat_id})")
			for bs_other in self.util_get_sessions_by_user(user):
				bs_other.evt.on_circle_role_updated(circle.chat_id, CircleRole.Member)
			
			for cs_other in chat.get_roster():
				if cs_other is user: continue
				cs_other.bs.evt.on_circle_updated(circle)
	
	def util_decline_circle_invite(self, circle: Circle, user: User) -> None:
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = self.chat_get('persistent', circle.chat_id)
		
		membership = circle.memberships[user.uuid]
		if not (membership.role == CircleRole.StatePendingOutbound and membership.state == CircleState.WaitingResponse):
			if membership.state == CircleState.Rejected or membership.state == CircleState.Empty:
				raise error.MemberNotInCircle()
			raise error.MemberAlreadyInCircle()
		
		membership.role = CircleRole.Member
		membership.state = CircleState.Rejected
		
		self._mark_circle_modified(circle)
		
		if chat is not None:
			for bs_other in self.util_get_sessions_by_user(user):
				print(f"[Circle] <Info> {user.username} ({user.email}) has declined their invitation to {circle.name} (ID: {circle.chat_id})")
				bs_other.evt.on_declined_chat_invite(chat, circle = True)
			
			chat.send_participant_declined(user, circle = True)
	
	def util_revoke_circle_invite(self, circle: Circle, user: User) -> None:
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = self.chat_get('persistent', circle.chat_id)
		
		membership = circle.memberships[user.uuid]
		if not (membership.role == CircleRole.StatePendingOutbound and membership.state == CircleState.WaitingResponse):
			if membership.state == CircleState.Rejected or membership.state == CircleState.Empty:
				raise error.MemberNotInCircle()
			raise error.MemberAlreadyInCircle()
		
		membership.role = CircleRole.Member
		membership.state = CircleState.Empty
		
		membership_inviter_email = membership.inviter_email
		if membership.inviter_uuid is not None:
			membership.inviter_uuid = None
		if membership.inviter_email is not None:
			membership.inviter_email = None
		if membership.inviter_name is not None:
			membership.inviter_name = None
		
		self._mark_circle_modified(circle)
		
		for bs_other in self.util_get_sessions_by_user(user):
			print(f"[Circle] <Info> {user.username} ({user.email})'s invitation to {circle.name} (ID: {circle.chat_id}) has been revoked")
			if membership_inviter_email is not None: print(f"[Circle] <Info> It was sent by {membership_inviter_email}")
			bs_other.evt.on_circle_invite_revoked(circle.chat_id)
		
		if chat is not None:
			for cs_other in chat.get_roster():
				cs_other.bs.evt.on_circle_updated(circle)
	
	def util_change_circle_membership_role(self, circle: Circle, user_other: User, role: CircleRole, user_self: Optional[User]) -> None:
		if user_other.uuid not in circle.memberships or (user_self is not None and user_self.uuid not in circle.memberships): raise error.MemberNotInCircle()
		
		chat = self.chat_get('persistent', circle.chat_id)
		
		membership = circle.memberships[user_other.uuid]
		membership_self = None
		
		if user_self is not None:
			assert role is CircleRole.Admin
			membership_self = circle.memberships[user_self.uuid]
		
		old_role = membership.role
		if old_role == CircleRole.StatePendingOutbound:
			raise error.CircleMemberIsPending()
		if membership_self is not None:
			if membership_self.role != CircleRole.Admin or old_role == CircleRole.Admin:
				raise error.MemberDoesntHaveSufficientCircleRole()
		membership.role = role
		if membership_self is not None:
			membership_self.role = CircleRole.Member
		
		if old_role is not membership.role:
			self._mark_circle_modified(circle)
			
			if chat is not None:
				for cs_other in chat.get_roster():
					if cs_other.user is user_other or (user_self is not None and cs_other.user is user_self):
						role_user = None
						if (user_self is not None and cs_other.user is user_self) and membership_self is not None:
							role_user = membership_self.role
						elif cs_other.user is user_other:
							role_user = membership.role
						if role_user is not None:
							cs_other.bs.evt.on_circle_role_updated(circle.chat_id, role_user)
						print(f"[Circle] <Info> {user_other.username} ({user_other.email})'s role in {circle.name} (ID: {circle.chat_id}) is now {membership.role}")
						print(f"[Circle] <Info> {user_other.username} ({user_other.email})'s state in {circle.name} (ID: {circle.chat_id}) is now {membership.state}")
					else:
						cs_other.bs.evt.on_circle_updated(circle)
	
	def util_remove_user_from_circle(self, circle: Circle, user: User) -> None:
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = self.chat_get('persistent', circle.chat_id)
		
		membership = circle.memberships[user.uuid]
		if membership.state == CircleState.Empty: raise error.MemberNotInCircle()
		
		if membership.role == CircleRole.Admin and len(list(self.util_get_circle_memberships_by_role(circle, CircleRole.Admin))) < 2:
			raise error.CantLeaveCircle()
		
		membership.role = CircleRole.Member
		membership.state = CircleState.Empty
		
		if membership.inviter_uuid is not None:
			membership.inviter_uuid = None
		if membership.inviter_email is not None:
			membership.inviter_email = None
		if membership.inviter_name is not None:
			membership.inviter_name = None
		
		self._mark_circle_modified(circle)
		
		for bs_other in self.util_get_sessions_by_user(user):
			print(f"[Circle] <Info> {user.username} ({user.email}) has been removed from {circle.name} (ID: {circle.chat_id})")
			bs_other.evt.on_left_circle(circle)
		
		if chat is not None:
			if circle.chat_id in self._cses_by_bs_by_circle_id:
				for bs, cs in list(self._cses_by_bs_by_circle_id[circle.chat_id].items()):
					if cs is not None and cs.user is user:
						cs.close()
						del self._cses_by_bs_by_circle_id[circle.chat_id][bs]
			
			for cs_other in chat.get_roster():
				if cs_other.user is not user:
					cs_other.bs.evt.on_circle_updated(circle)
	
	def dev_connect(self, obj: object) -> None:
		if self._dev is None: return
		self._dev.connect(obj)
	
	def dev_disconnect(self, obj: object) -> None:
		if self._dev is None: return
		self._dev.disconnect(obj)
	
	async def _worker_sync_db(self) -> None:
		while True:
			await asyncio.sleep(0.04)
			self._sync_db_impl()
	
	def _sync_db_impl(self) -> None:
		if not self._worklist_sync_db: return
		try:
			users = list(self._worklist_sync_db.keys())[:100]
			batch = []
			for user in users:
				detail = self._worklist_sync_db.pop(user, None)
				if detail is None: continue
				batch.append((user, detail))
			self.user_service.save_batch(batch)
		except:
			traceback.print_exc()
	
	async def _worker_remove_expired_login_tokens(self) -> None:
		while True:
			await asyncio.sleep(0.04)
			self._remove_expired_login_tokens()
	
	def _remove_expired_login_tokens(self) -> None:
		try:
			self.login_auth_service.remove_expired()
		except:
			traceback.print_exc()
	
	async def _worker_purge_suspended(self) -> None:
		await asyncio.sleep(60)
		while True:
			try:
				self.util_purge_suspended()
			except Exception:
				traceback.print_exc()
			await asyncio.sleep(3600)
	
	async def _worker_sync_circles(self) -> None:
		while True:
			await asyncio.sleep(0.04)
			self._sync_circle_impl()
	
	def _sync_circle_impl(self) -> None:
		if not self._worklist_sync_circles: return
		try:
			chat_ids = list(self._worklist_sync_circles.keys())[:100]
			batch = []
			for chat_id in chat_ids:
				circle = self._worklist_sync_circles.pop(chat_id, None)
				if circle is None: continue
				batch.append((chat_id, circle))
			self.user_service.save_circle_batch(batch)
		except:
			traceback.print_exc()
	
	async def _worker_clean_sessions(self) -> None:
		while True:
			await asyncio.sleep(0.04)
			closed = []
			
			try:
				for sess in self._sc.iter_sessions():
					if sess.closed:
						closed.append(sess)
			except:
				traceback.print_exc()
			
			for sess in closed:
				self._sc.remove_session(sess)
	
	async def _worker_sync_stats(self) -> None:
		while True:
			await asyncio.sleep(60)
			try:
				self._stats.flush(online = self._sc.session_count())
			except:
				traceback.print_exc()
	
	async def _worker_notify(self) -> None:
		# Notify relevant `BackendSession`s of status, name, message, media, etc. changes
		while True:
			await asyncio.sleep(0.04)
			try:
				self._handle_worklist_notify()
			except:
				traceback.print_exc()
			self._worklist_notify.clear()
	
	def _handle_worklist_notify(self) -> None:
		worklist = self._worklist_notify
		for bs, sess_id, on_contact_add, old_substatus, updated_phone_info, update_status, update_info_other, for_logout in worklist:
			user = bs.user
			detail = user.detail
			for ctc in (detail.contacts.values() if detail is not None else ()):
				for bs_other in self._sc.get_sessions_by_user(ctc.head):
					if bs_other.user is user: continue
					detail_other = bs_other.user.detail
					if detail_other is None: continue
					ctc_me = detail_other.contacts.get(user.uuid)
					# This shouldn't be `None`, since every contact should have
					# an `RL` contact on the other users' list (at the very least).
					if ctc_me is None: continue
					if not ctc_me.lists & ContactList.FL or _is_blocking(user, ctc.head): continue
					bs_other.evt.on_presence_notification(
						ctc_me, on_contact_add, old_substatus, sess_id = sess_id, updated_phone_info = updated_phone_info,
						update_status = update_status, update_info_other = update_info_other,
					)
			# sessions that only watch `user` through a client-side buddy list, and weren't told above
			for bs_other in self._watches.watchers_of(user.uuid):
				if bs_other.user is user: continue
				if detail is not None:
					if _sees_through_list(user, detail, bs_other.user) or _is_blocking(user, bs_other.user): continue
				bs_other.evt.on_presence_notification(
					_watch_contact(user, bs_other.user), on_contact_add, old_substatus, sess_id = sess_id,
					updated_phone_info = updated_phone_info, update_status = update_status, update_info_other = update_info_other,
				)
			for circle in self.user_service.get_circle_batch(user):
				if circle.chat_id not in self._cses_by_bs_by_circle_id: continue
				if bs not in self._cses_by_bs_by_circle_id[circle.chat_id]: continue
				cs = self._cses_by_bs_by_circle_id[circle.chat_id][bs]
				assert cs is not None
				cs.chat.send_participant_status_updated(cs, old_substatus)
			if not self._sc.is_session_in_collection(bs):
				for cs_dict in self._cses_by_bs_by_circle_id.values():
					cs = cs_dict.pop(bs, None)
					if cs is not None:
						cs.close()
			if for_logout:
				if not self._sc.get_sessions_by_user(user): user.detail = None
	
	async def _worker_notify_self(self) -> None:
		# Notify relevant `BackendSession`s of status, name, message, media, etc. changes
		worklist = self._worklist_notify_self
		while True:
			await asyncio.sleep(0.04)
			try:
				for bs, old_substatus, update_status, update_info in worklist:
					user = bs.user
					for bs_other in self._sc.get_sessions_by_user(user):
						bs_other.evt.on_presence_self_notification(old_substatus, update_status = update_status, update_info = update_info)
			except:
				traceback.print_exc()
			worklist.clear()

class Session(metaclass = ABCMeta):
	__slots__ = ('closed',)
	
	closed: bool
	
	def __init__(self) -> None:
		self.closed = False
	
	def close(self, **kwargs: Any) -> None:
		if self.closed:
			return
		self.closed = True
		self._on_close(**kwargs)
	
	@abstractmethod
	def _on_close(self, **kwargs: Any) -> None: pass

class _OfflineSessionShim:
	__slots__ = ('backend', 'user')

	backend: Backend
	user: User

	def __init__(self, backend: Backend, user: User) -> None:
		self.backend = backend
		self.user = user

	def _add_to_list(self, *args: Any, **kwargs: Any) -> Contact:
		return BackendSession._add_to_list(self, *args, **kwargs) # type: ignore

class BackendSession(Session):
	__slots__ = ('backend', 'user', 'client', 'chat_enabled', 'evt', 'front_data')
	
	backend: Backend
	user: User
	client: Client
	chat_enabled: bool
	evt: event.BackendEventHandler
	front_data: Dict[str, Any]
	
	def __init__(self, backend: Backend, user: User, client: Client, evt: event.BackendEventHandler) -> None:
		super().__init__()
		self.backend = backend
		self.user = user
		self.client = client
		self.chat_enabled = True
		self.evt = evt
		self.front_data = {}
	
	def _on_close(self, **kwargs: Any) -> None:
		if not kwargs.get('passthrough'): self.evt.on_close()
		self.backend.on_leave(self, sess_id = kwargs.get('sess_id'))
	
	def me_update(self, fields: Dict[str, Any]) -> None:
		user = self.user
		
		needs_mark_modified = False
		needs_notify = False
		notify_status = False
		notify_info_other = False
		notify_self = False
		updated_phone_info = {}
		
		old_substatus = user.status.substatus
		
		if 'message' in fields:
			if fields['message'] is not None:
				user.status.message = fields['message']
				needs_notify = True
				notify_info_other = True
		if 'media' in fields:
			if fields['media'] is not None:
				user.status.media = fields['media']
				needs_notify = True
				notify_info_other = True
		if 'name' in fields:
			old_name = user.status.name
			if fields['name'] != old_name:
				user.status.name = fields['name']
				needs_mark_modified = True
				needs_notify = True
				notify_status = True
		if 'home_phone' in fields:
			if fields['home_phone'] is None and 'PHH' in user.settings:
				del user.settings['PHH']
			else:
				user.settings['PHH'] = fields['home_phone']
			needs_mark_modified = True
			needs_notify = True
			
			updated_phone_info['PHH'] = fields['home_phone']
		if 'work_phone' in fields:
			if fields['work_phone'] is None and 'PHW' in user.settings:
				del user.settings['PHW']
			else:
				user.settings['PHW'] = fields['work_phone']
			needs_mark_modified = True
			needs_notify = True
			
			updated_phone_info['PHW'] = fields['work_phone']
		if 'mobile_phone' in fields:
			if fields['mobile_phone'] is None and 'PHM' in user.settings:
				del user.settings['PHM']
			else:
				user.settings['PHM'] = fields['mobile_phone']
			needs_mark_modified = True
			needs_notify = True
			
			updated_phone_info['PHM'] = fields['mobile_phone']
		if 'blp' in fields:
			user.settings['BLP'] = fields['blp']
			needs_mark_modified = True
			needs_notify = True
			notify_status = True
		if 'mob' in fields:
			user.settings['MOB'] = fields['mob']
			needs_mark_modified = True
			needs_notify = True
			
			updated_phone_info['MOB'] = fields['mob']
		if 'mbe' in fields:
			user.settings['MBE'] = fields['mbe']
			needs_mark_modified = True
			needs_notify = True
			
			updated_phone_info['MBE'] = fields['mbe']
		if 'substatus' in fields:
			if old_substatus is not fields['substatus']:
				user.status.substatus = fields['substatus']
				needs_notify = True
				notify_status = True
		if 'needs_notify' in fields:
			needs_notify = fields['needs_notify']
		if 'notify_self' in fields:
			notify_self = fields['notify_self']
		if 'notify_status' in fields:
			notify_status = fields['notify_status']
		if 'notify_info' in fields:
			notify_info_other = fields['notify_info']
		if 'gtc' in fields:
			user.settings['GTC'] = fields['gtc']
			needs_mark_modified = True
		if 'rlp' in fields:
			user.settings['RLP'] = fields['rlp']
			needs_mark_modified = True
		if 'mpop' in fields:
			user.settings['MPOP'] = fields['mpop']
			needs_mark_modified = True
		
		print(f"[Presence] <Info> {user.username} ({user.email})'s status updated: {user.status.substatus}")
		if user.status.name: print(f"[Presence] <Info> Nickname: {user.status.name}")
		if user.status.media: print(f"[Presence] <Info> Media: {user.status.media}")
		if user.status.message: print(f"[Presence] <Info> Personal Status Message: {user.status.message}")

		if needs_mark_modified:
			self.backend._mark_modified(user)
		if needs_notify and not user.status.substatus is Substatus.Offline:
			self.backend._sync_contact_statuses(user)
			self.backend._notify_contacts(
				self, old_substatus, updated_phone_info = updated_phone_info,
				update_status = notify_status, update_info_other = notify_info_other,
			)
		if notify_self:
			self.backend._notify_self(self, old_substatus, update_status = notify_status, update_info = notify_info_other)

	def me_visibility_snapshot(self) -> Dict[str, bool]:
		# which of the contacts that have us on their list can currently see us
		user = self.user
		detail = user.detail
		if detail is None: return {}
		snapshot = {} # type: Dict[str, bool]
		for ctc in detail.contacts.values():
			if not ctc.lists & ContactList.RL: continue
			snapshot[ctc.head.uuid] = not _is_blocking(user, ctc.head)
		# client-side buddy lists can see us too, without any list linking us
		for bs_other in self.backend._watches.watchers_of(user.uuid):
			if bs_other.user is user or bs_other.user.uuid in snapshot: continue
			snapshot[bs_other.user.uuid] = not _is_blocking(user, bs_other.user)
		return snapshot
	
	def me_visibility_changed(self, before: Dict[str, bool]) -> None:
		# push an arrival/departure to every contact whose view of us changed since `before` was taken
		backend = self.backend
		user = self.user
		detail = user.detail
		if detail is None or user.status.substatus is Substatus.Offline: return
		after = self.me_visibility_snapshot()
		backend._sync_contact_statuses(user)
		for uuid, visible in after.items():
			if before.get(uuid) == visible: continue
			ctc = detail.contacts.get(uuid)
			if ctc is not None:
				for sess_other in backend._sc.get_sessions_by_user(ctc.head):
					detail_other = sess_other.user.detail
					if detail_other is None: continue
					ctc_me = detail_other.contacts.get(user.uuid)
					if ctc_me is None or not ctc_me.lists & ContactList.FL: continue
					sess_other.evt.on_presence_notification(ctc_me, False, user.status.substatus)
			for sess_other in backend._watches.watchers_of(user.uuid):
				if sess_other.user.uuid != uuid or _sees_through_list(user, detail, sess_other.user): continue
				sess_other.evt.on_presence_notification(_watch_contact(user, sess_other.user), False, user.status.substatus)
				
	def me_group_add(self, name: str, *, is_favorite: Optional[bool] = None) -> Group:
		if len(name) > MAX_GROUP_NAME_LENGTH:
			raise error.GroupNameTooLong()
		user = self.user
		detail = user.detail
		assert detail is not None
		if name == '(No Group)':
			raise error.GroupAlreadyExists()
		groups = detail.get_groups_by_name(name)
		if groups:
			raise error.GroupAlreadyExists()
		group = Group(_gen_group_id(detail), gen_uuid(), name, is_favorite or False)
		detail.insert_group(group)
		print(f'[Contacts] <Info> {user.username} ({user.email}) has created group {name} (ID: {group.id})')
		self.backend._mark_modified(user)
		return group
	
	def me_group_remove(self, group_id: str) -> None:
		if group_id == '0':
			raise error.CannotRemoveSpecialGroup()
		user = self.user
		detail = user.detail
		assert detail is not None
		group = detail.get_group_by_id(group_id)
		if group is None:
			raise error.GroupDoesNotExist()
		detail.delete_group(group)
		for ctc in detail.contacts.values():
			ctc.remove_from_group(group)
		print(f'[Contacts] <Info> {user.username} ({user.email}) has deleted group {group.name} (ID: {group_id})')
		self.backend._mark_modified(user)
	
	def me_group_edit(self, group_id: str, *, new_name: Optional[str] = None, is_favorite: Optional[bool] = None) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		g = detail.get_group_by_id(group_id)
		if g is None:
			raise error.GroupDoesNotExist()
		print(f'[Contacts] <Info> {user.username} ({user.email}) has modified group {g.name} (ID: {g.id})')
		if new_name is not None:
			if new_name == '(No Group)':
				raise error.GroupAlreadyExists()
			if len(new_name) > MAX_GROUP_NAME_LENGTH:
				raise error.GroupNameTooLong()
			groups = detail.get_groups_by_name(new_name)
			for group in groups:
				if group.name == new_name and group.id != g.id:
					raise error.GroupAlreadyExists()
			g.name = new_name
			print(f'[Contacts] <Info> New name: {new_name}')
		if is_favorite is not None:
			g.is_favorite = is_favorite
			print(f'[Contacts] <Info> Is favorites')
		self.backend._mark_modified(user)
	
	def me_group_contact_add(self, group_id: str, contact_uuid: str) -> None:
		if group_id == '0': return
		user = self.user
		detail = user.detail
		assert detail is not None
		group = detail.get_group_by_id(group_id)
		if group is None:
			raise error.GroupDoesNotExist()
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if ctc.group_in_entry(group):
			raise error.ContactAlreadyOnContactList()
		ctc.add_group_to_entry(group)
		print(f'[Contacts] <Info> {user.username} ({user.email}) has added {ctc.head.username} ({ctc.head.email}) to group {group.name} (ID: {group_id})')
		self.backend._mark_modified(user)
	
	def me_group_contact_remove(self, group_id: str, contact_uuid: str) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if group_id != '0':
			group = detail.get_group_by_id(group_id)
			if group is None:
				raise error.GroupDoesNotExist()
			ctc.remove_from_group(group)
			print(f'[Contacts] <Info> {user.username} ({user.email}) has removed {ctc.head.username} ({ctc.head.email}) from group {group.name} (ID: {group_id})')
			self.backend._mark_modified(user)
	
	def me_contact_add(
		self, contact_uuid: str, lst: ContactList, *, trid: Optional[str] = None, name: Optional[str] = None,
		nickname: Optional[str] = None, message: Optional[TextWithData] = None, group_id: Optional[str] = None,
		adder_id: Optional[str] = None, needs_notify: bool = False,
	) -> Tuple[Contact, User]:
		assert not lst & ContactList.PL
		backend = self.backend
		user = self.user
		detail = user.detail
		assert detail is not None
		old_lists = None
		ctc_head = backend._load_user_record(contact_uuid)
		if ctc_head is None:
			raise error.UserDoesNotExist()
		user = self.user
		old_ctc = detail.contacts.get(ctc_head.uuid)
		if old_ctc is not None:
			old_lists = old_ctc.lists
			for lst2 in [ContactList.FL, ContactList.AL, ContactList.BL]:
				if old_lists & lst2:
					if len(detail.get_contacts_by_list(lst2)) >= LST_LIMITS[lst2]:
						raise error.ContactListIsFull()
		ctc = self._add_to_list(user, ctc_head, lst, name, group_id, nickname = nickname)
		if lst & ContactList.FL:
			# FL needs a matching RL on the contact
			ctc_me = self._add_to_list(ctc_head, user, ContactList.RL, user.email, None) # type: Optional[Contact]
			# `ctc_head` was added to `user`'s RL
			for sess_added in backend._sc.get_sessions_by_user(ctc_head):
				#if sess_added is self: continue
				if old_ctc is None or (old_lists is not None and not old_lists & ContactList.FL):
					sess_added.evt.on_added_me(user, message = message, adder_id = adder_id)
		else:
			ctc_detail = backend._load_detail(ctc_head)
			ctc_me = ctc_detail.contacts.get(user.uuid)
		if ((lst & ContactList.AL or lst & ContactList.BL) and ctc.lists & ContactList.RL) or needs_notify:
			for sess_added in backend._sc.get_sessions_by_user(ctc_head):
				if sess_added is self: continue
				if not ctc_me: continue
				if not (ctc_me.lists & ContactList.FL): continue
				backend._sync_contact_statuses(ctc_head)
				sess_added.evt.on_presence_notification(
					ctc_me, False, user.status.substatus, send_status_on_bl = (True if lst & ContactList.BL else False),
					updated_phone_info = {
						'PHH': user.settings.get('PHH'),
						'PHW': user.settings.get('PHW'),
						'PHM': user.settings.get('PHM'),
						'MOB': user.settings.get('MOB'),
					},
				)
		print(f'[Contacts] <Info> {user.username} ({user.email}) has added {ctc.head.username} ({ctc.head.email}) to their contact list')

		return ctc, ctc_head
	
	def me_contact_rename(self, contact_uuid: str, new_name: str) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		
		if len(new_name) > 387:
			raise error.NicknameExceedsLengthLimit()
		
		ctc.status.name = new_name
		print(f"[Contacts] <Info> {user.username} ({user.email}) has changed {ctc.head.username} ({ctc.head.email})'s friend nickname to {new_name}")
		self.backend._mark_modified(user)
	
	def me_contact_remove(self, contact_uuid: str, lst: ContactList, *, group_id: Optional[str] = None) -> None:
		backend = self.backend
		user = self.user
		detail = user.detail
		assert detail is not None
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None: 
			raise error.ContactDoesNotExist()
		assert not lst & ContactList.RL
		try:
			print(f'[Contacts] <Info> {user.username} ({user.email}) has removed {ctc.head.username} ({ctc.head.email}) from their contact list')
			ctc_new = self._remove_from_list(user, ctc.head, lst, group_id)
		except Exception as ex:
			raise ex
		if lst & ContactList.FL:
			# Remove matching RL
			self._remove_from_list(ctc.head, user, ContactList.RL, None)
			for sess_added in backend._sc.get_sessions_by_user(ctc.head):
				sess_added.evt.on_removed_me(user)
		if lst & ContactList.BL:
			ctc_detail = backend._load_detail(ctc.head)
			ctc_me = ctc_detail.contacts.get(user.uuid)
			for sess_added in backend._sc.get_sessions_by_user(ctc.head):
				if sess_added is self: continue
				if ctc_me:
					if ctc_me.lists & ContactList.FL:
						sess_added.evt.on_presence_notification(ctc_me, False, Substatus.Offline, updated_phone_info = {
							'PHH': user.settings.get('PHH'),
							'PHW': user.settings.get('PHW'),
							'PHM': user.settings.get('PHM'),
							'MOB': user.settings.get('MOB'),
						})
	
	def me_contact_deny(self, adder_uuid: str, deny_message: Optional[str], *, addee_id: Optional[str] = None) -> None:
		user_adder = self.backend._load_user_record(adder_uuid)
		if user_adder is None:
			raise error.UserDoesNotExist()
		user = self.user

		print(f"[Contacts] <Info> {user.username} ({user.email}) has denied {user_adder.username} ({user_adder.email})'s friend request")
		print(f"Attached message: {deny_message}")

		for sess_adder in self.backend._sc.get_sessions_by_user(user_adder):
			sess_adder.evt.on_contact_request_denied(user, deny_message or '', contact_id = addee_id)
	
	def _add_to_list(
		self, user: User, ctc_head: User, lst: ContactList, name: Optional[str], group_id: Optional[str], *,
		nickname: Optional[str] = None,
	) -> Contact:
		# Add `ctc` to `user`'s `lst`
		detail = self.backend._load_detail(user)
		contacts = detail.contacts
		
		updated = False
		
		if ctc_head.uuid not in contacts:
			contacts[ctc_head.uuid] = Contact(ctc_head, set(), ContactList.Empty, UserStatus(name or ctc_head.email), ContactDetail(_gen_contact_id(detail)))
			updated = True
		ctc = contacts[ctc_head.uuid]
		
		if (ctc.lists & lst) != lst:
			ctc.lists |= lst
			if lst == ContactList.RL:
				ctc.pending = True
			updated = True
		else:
			if lst == ContactList.FL and group_id is not None:
				if ctc.is_in_group_id(group_id):
					raise error.ContactAlreadyOnContactList()
		
		orig_name = ctc.status.name
		if name is not None and (ctc.status.name is None or orig_name != name):
			ctc.status.name = name
			updated = True
		
		orig_nick = ctc.detail.nickname
		if nickname is not None and (ctc.detail.nickname is None or orig_nick != nickname):
			ctc.detail.nickname = nickname
			updated = True
		
		if lst == ContactList.FL:
			if group_id is not None:
				try:
					self.me_group_contact_add(group_id, ctc_head.uuid)
				except Exception as ex:
					raise ex
		
		if updated:
			self.backend._mark_modified(user, detail = detail)
			self.backend._sync_contact_statuses(user)
		
		return ctc
	
	def _remove_from_list(self, user: User, ctc_head: User, lst: ContactList, group_id: Optional[str]) -> Optional[Contact]:
		# Remove `ctc_head` from `user`'s `lst`
		detail = self.backend._load_detail(user)
		contacts = detail.contacts
		ctc = contacts.get(ctc_head.uuid)
		if ctc is None: raise error.ContactDoesNotExist()
		
		updated = False
		if ctc.lists & lst:
			if lst == ContactList.FL and group_id is not None:
				try:
					self.me_group_contact_remove(group_id, ctc.head.uuid)
				except Exception as ex:
					raise ex
				updated = True
				
			if (lst == ContactList.FL and group_id is None) or not lst & ContactList.FL:
				ctc.lists &= ~lst
				if lst == ContactList.FL:
					ctc._groups = set()
				if lst == ContactList.RL and ctc.pending:
					ctc.pending = False
				updated = True
		elif lst == ContactList.PL and ctc.pending:
			ctc.pending = False
			updated = True
		else:
			raise error.ContactNotOnContactList()
		
		if not ctc.lists:
			del contacts[ctc_head.uuid]
			ctc = None
			updated = True
		
		if updated:
			self.backend._mark_modified(user, detail = detail)
			self.backend._sync_contact_statuses(user)
		
		return ctc
	
	def me_contact_notify_oim(self, uuid: str, oim: OIM) -> None:
		ctc_head = self.backend._load_user_record(uuid)
		if ctc_head is None:
			raise error.UserDoesNotExist()
		
		for sess_notify in self.backend._sc.get_sessions_by_user(ctc_head):
			if sess_notify is self: continue
			sess_notify.evt.on_oim_sent(oim)

	def send_invitation_email(self, email, sender_email, sender_name, message) -> None:
		if (uuid := self.backend.util_get_uuid_from_email(email)) is None:
			if sender_name:
				sender_info = f"{sender_name} ({sender_email})"
			else:
				sender_info = sender_email
	
			invite_msg = f"""\
Subject: {sender_email} wants to talk to you using CrossTalk!
To: {email}
From: CrossTalk network administration <administration@ugnet.xyz>

This e-mail was sent to you because {sender_info} wants to chat with you using the CrossTalk service, and you don't have an account.

CrossTalk is a chat service that supports many messaging clients, and allows them to seamlessly interoperate.

You can learn more here: https://crosstalk.im

Create an account here: https://crosstalk.im/register
		"""
			if message:
				invite_msg += f"""\

They've attached this message, as well:
"{message.decode('utf-8')}"
			"""
			print(f"[Mailer] <Info> {sender_email} has sent an e-mail invitation to {email}")
			print(f"[Mailer] <Info> Attached message: {invite_msg}")
			if settings.DEBUG:
				print(invite_msg)
			with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
				server.starttls()
				server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
				server.sendmail("administration@ugnet.xyz", email, invite_msg)
		else:
			print(f"[Mailer] <Info> {sender_email} already has an account. Not sending an invitation e-mail.")
			

	
	def me_create_circle(self, name: str, owner_friendly: str, membership_access: int) -> Circle:
		user = self.user
		backend = self.backend
		
		chat_id = backend.user_service.create_circle(user, name, owner_friendly, membership_access)
		circle = backend.user_service.get_circle(chat_id)
		assert circle is not None
		
		backend.chat_create(circle = circle)
		
		print(f"[Circle] <Info> {user.username} ({user.email}) has created a new Circle '{circle.name} (ID: {circle.chat_id})'")
		return circle
	
	def me_add_user_to_circle(self, circle: Circle, user_other: User) -> None:
		user = self.user
		
		if user_other.uuid in circle.memberships: raise error.MemberAlreadyInCircle()
		circle.memberships[user_other.uuid] = CircleMembership(
			circle.chat_id, user_other,
			CircleRole.Empty, CircleState.Empty,
		)
		
		print(f"[Circle] <Info> {user.username} ({user.email}) has added {user_other.username} ({user_other.email}) to {circle.name} (ID: {circle.chat_id})")
		self.backend._mark_circle_modified(circle)
	
	def me_invite_user_to_circle(self, circle: Circle, invitee: User, *, invite_message: Optional[str] = None) -> None:
		backend = self.backend
		inviter = self.user
		
		if invitee.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		membership = circle.memberships[invitee.uuid]
		
		chat = backend.chat_get('persistent', circle.chat_id)
		if chat is None: raise error.CircleDoesNotExist()
		
		if membership.state not in (CircleState.Rejected,CircleState.Empty): raise error.MemberAlreadyInvitedToCircle()
		
		membership.role = CircleRole.StatePendingOutbound
		membership.state = CircleState.WaitingResponse
		membership.inviter_uuid = inviter.uuid
		membership.inviter_email = inviter.email
		membership.inviter_name = inviter.status.name or inviter.email
		membership.invite_message = invite_message
		
		self.backend._mark_circle_modified(circle)

		print(f"[Circle] <Info> {inviter.username} ({inviter.email}) has invited {invitee.username} ({invitee.email}) to {circle.name} (ID: {circle.chat_id})")
		if invite_message:
			print(f"[Circle] <Info> Invitation message: {invite_message}")
		
		for bs in backend.util_get_sessions_by_user(invitee):
			bs.evt.on_chat_invite(chat, inviter, circle = True)
		
		for cs in chat.get_roster():
			cs.bs.evt.on_circle_updated(circle)
	
	def me_change_circle_membership(
		self, circle: Circle, user_other: User, *,
		role: Optional[CircleRole] = None, state: Optional[CircleState] = None,
	) -> None:
		user = self.user
		
		if user_other.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = self.backend.chat_get('persistent', circle.chat_id)
		if chat is None: raise error.CircleDoesNotExist()
		
		membership = circle.memberships[user_other.uuid]
		
		old_role = membership.role
		old_state = membership.state
		if role is not None:
			membership.role = role
		if state is not None:
			membership.state = state
		
		if old_role is not membership.role or old_state is not membership.state:
			self.backend._mark_circle_modified(circle)
	
	def me_accept_circle_invite(self, circle: Circle, *, send_events: bool = True) -> None:
		user = self.user
		backend = self.backend
		
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = self.backend.chat_get('persistent', circle.chat_id)
		if chat is None: raise error.CircleDoesNotExist()
		
		membership = circle.memberships[user.uuid]
		
		if not (membership.role == CircleRole.StatePendingOutbound and membership.state == CircleState.WaitingResponse):
			if membership.state == CircleState.Rejected or membership.state == CircleState.Empty:
				raise error.MemberNotInCircle()
			raise error.MemberAlreadyInCircle()
		
		membership.role = CircleRole.Member
		membership.state = CircleState.Accepted
		
		if membership.invite_message is not None:
			membership.invite_message = None
		
		self.backend._mark_circle_modified(circle)
		
		if send_events:
			for bs_other in backend.util_get_sessions_by_user(user):
				if bs_other is self: continue
				bs_other.evt.on_accepted_circle_invite(circle)
		
		for cs_other in chat.get_roster():
			if cs_other is user: continue
			cs_other.bs.evt.on_circle_updated(circle)
	
	def me_decline_circle_invite(self, circle: Circle, *, send_events: bool = True) -> None:
		user = self.user
		backend = self.backend
		
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = self.backend.chat_get('persistent', circle.chat_id)
		if chat is None: raise error.CircleDoesNotExist()
		
		membership = circle.memberships[user.uuid]
		if not (membership.role == CircleRole.StatePendingOutbound and membership.state == CircleState.WaitingResponse):
			if membership.state == CircleState.Rejected or membership.state == CircleState.Empty:
				raise error.MemberNotInCircle()
			raise error.MemberAlreadyInCircle()
		
		membership.role = CircleRole.Member
		membership.state = CircleState.Rejected
		
		self.backend._mark_circle_modified(circle)
		
		if send_events:
			for bs_other in backend.util_get_sessions_by_user(user):
				if bs_other is self: continue
				bs_other.evt.on_declined_chat_invite(chat, circle = True)
		
		chat.send_participant_declined(user, circle = True)
	
	def me_leave_circle(self, circle: Circle) -> None:
		user = self.user
		backend = self.backend
		
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		chat = backend.chat_get('persistent', circle.chat_id)
		if chat is None: raise error.CircleDoesNotExist()
		
		membership = circle.memberships[user.uuid]
		if membership.state == CircleState.Empty: raise error.MemberNotInCircle()
		
		other_owners = False
		
		if membership.role == CircleRole.Admin:
			memberships = backend.util_get_circle_memberships_by_role(circle, CircleRole.Admin)
			if len(list(memberships)) < 2:
				raise error.CantLeaveCircle()
		
		membership.role = CircleRole.Member
		membership.state = CircleState.Empty
		
		if membership.inviter_uuid is not None:
			membership.inviter_uuid = None
		if membership.inviter_email is not None:
			membership.inviter_email = None
		if membership.inviter_name is not None:
			membership.inviter_name = None
		
		backend._mark_circle_modified(circle)
		
		if circle.chat_id in backend._cses_by_bs_by_circle_id:
			for bs, cs in list(backend._cses_by_bs_by_circle_id[circle.chat_id].items()):
				if cs is not None and cs.user is user:
					cs.close()
					del backend._cses_by_bs_by_circle_id[circle.chat_id][bs]
		
		for cs_other in chat.get_roster():
			if cs_other.user is not user:
				cs_other.bs.evt.on_circle_updated(circle)
	
	def me_block_circle(self, circle: Circle) -> None:
		user = self.user
		
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		if not circle.memberships[user.uuid].blocking:
			circle.memberships[user.uuid].blocking = True
			self.backend._mark_circle_modified(circle)
			
			sess = first_in_iterable(self.backend.util_get_sessions_by_user(user))
			if sess is None: return
			cs = self.backend.get_circle_cs(circle.chat_id, sess)
			if cs is None: return
			cs.chat.send_participant_status_updated(cs, user.status.substatus, send_on_bl = True)
	
	def me_unblock_circle(self, circle: Circle) -> None:
		user = self.user
		
		if user.uuid not in circle.memberships: raise error.MemberNotInCircle()
		
		if circle.memberships[user.uuid].blocking:
			circle.memberships[user.uuid].blocking = False
			self.backend._mark_circle_modified(circle)

class _SessionCollection:
	__slots__ = ('_sessions', '_sessions_by_user', '_sess_by_token', '_tokens_by_sess')
	
	_sessions: Set[BackendSession]
	_sessions_by_user: Dict[User, List[BackendSession]]
	_sess_by_token: Dict[str, BackendSession]
	_tokens_by_sess: Dict[BackendSession, Set[str]]
	
	def __init__(self) -> None:
		self._sessions = set()
		self._sessions_by_user = defaultdict(list)
		self._sess_by_token = {}
		self._tokens_by_sess = defaultdict(set)
	
	def get_sessions_by_user(self, user: User) -> List[BackendSession]:
		if user not in self._sessions_by_user:
			return []
		return self._sessions_by_user[user]
	
	def is_session_in_collection(self, sess: BackendSession) -> bool:
		return sess in self._sessions
	
	def iter_sessions(self) -> Iterable[BackendSession]:
		yield from self._sessions
	
	def session_count(self) -> int:
		return len(self._sessions)
	
	def set_nc_by_token(self, sess: BackendSession, token: str) -> None:
		self._sess_by_token[token] = sess
		self._tokens_by_sess[sess].add(token)
		self._sessions.add(sess)
	
	def get_nc_by_token(self, token: str) -> Optional[BackendSession]:
		return self._sess_by_token.get(token)
	
	def add_session(self, sess: BackendSession) -> None:
		if sess.user:
			self._sessions_by_user[sess.user].append(sess)
		self._sessions.add(sess)
	
	def remove_session(self, sess: BackendSession) -> None:
		if sess in self._tokens_by_sess:
			tokens = self._tokens_by_sess.pop(sess)
			for token in tokens:
				self._sess_by_token.pop(token, None)
		self._sessions.discard(sess)
		if sess.user in self._sessions_by_user:
			self._sessions_by_user[sess.user].remove(sess)

class Chat:
	__slots__ = ('ids', 'backend', 'circle', 'front_data', '_users_by_sess', '_stats')
	
	ids: Dict[str, str]
	backend: Backend
	circle: Optional[Circle]
	# TODO: implement the meat of chatrooms
	chatroom: Optional[Chatroom] 
	front_data: Dict[str, Any]
	_users_by_sess: Dict['ChatSession', Tuple[User, Optional[str]]]
	_stats: Any
	
	def __init__(self, backend: Backend, stats: Any, *, circle: Optional[Circle] = None, chatroom: Optional[Chatroom] = None) -> None:
		super().__init__()
		self.ids = {}
		self.backend = backend
		self.circle = circle
		self.front_data = {}
		self._users_by_sess = {}
		self._stats = stats
		
		# 31 characters is all WLM 2009 will allow for chat IDs (RNG); otherwise the receiving end won't have the sender's messages display
		self.add_id('main', GenTokenStr(trim = 31))
		if self.circle is None: return
		
		assert circle is not None
		self.add_id('persistent', circle.chat_id)
	
	def add_id(self, scope: str, id: str) -> None:
		assert id not in self.backend._chats_by_id
		self.ids[scope] = id
		self.backend._chats_by_id[(scope, id)] = self
	
	def join(
		self, origin: str, bs: BackendSession, evt: event.ChatEventHandler, *,
		preferred_name: Optional[str] = None, pop_id: Optional[str] = None,
	) -> 'ChatSession':
		primary_pop = True
		
		if self.circle is not None:
			if bs.user.uuid not in self.circle.memberships: raise error.NotAllowedToJoinCircle()
		
		for user_other, pop_id_other in self._users_by_sess.values():
			if bs.user is user_other:
				if pop_id_other is not None:
					if (pop_id is not None and pop_id_other.lower() == pop_id.lower()): raise error.AuthFail()
				else:
					if pop_id is not None: raise error.AuthFail()
		for other_cs in self.get_roster():
			primary_pop = True
			if other_cs.user is bs.user and other_cs.primary_pop:
				primary_pop = False
		cs = ChatSession(origin, bs, self, evt, primary_pop, preferred_name = preferred_name)
		cs.evt.cs = cs
		self._users_by_sess[cs] = (cs.user, pop_id)
		cs.evt.on_open()
		return cs

	def add_session(self, cs: 'ChatSession', pop_id: Optional[str] = None) -> None:
		self._users_by_sess[cs] = (cs.user, pop_id)
	
	def get_roster(self) -> Iterable['ChatSession']:
		return self._users_by_sess.keys()
	
	def get_roster_single(self) -> Iterable['ChatSession']:
		sess_per_user = [] # type: List[ChatSession]
		
		for cs in self._users_by_sess.keys():
			already_in_roster = False
			for sess1 in sess_per_user:
				if cs.primary_pop:
					if sess1.user is cs.user:
						already_in_roster = True
					break
			if not already_in_roster:
				sess_per_user.append(cs)
		
		return sess_per_user
	
	def send_update(self) -> None:
		for cs in self.get_roster():
			cs.evt.on_chat_updated()
	
	def send_participant_joined(self, cs: 'ChatSession', *, initial_join: bool = False) -> None:
		tmp = []
		
		for cs_self in self.get_roster():
			if cs_self.user is cs.user and cs_self is not cs:
				tmp.append(cs_self)
		
		if len(tmp) > 0:
			first_pop = False
		else:
			first_pop = True
		
		if initial_join and self.circle is not None:
			for cs_single in self.get_roster_single():
				if cs_single is cs: continue
				cs.evt.on_participant_joined(cs_single, cs_single.primary_pop, initial_join)
		
		for cs_other in self.get_roster():
			if self.circle is not None:
				if self.circle.memberships[cs.user.uuid].blocking and cs_other.user is not cs.user: continue
			if cs_other == cs and cs.origin == 'yahoo': continue
			cs_other.evt.on_participant_joined(cs, first_pop, initial_join)
	
	def send_participant_declined(
		self, user: User, *, user_id: Optional[str] = None, message: Optional[str] = None, circle: bool = False,
	) -> None:
		for cs_other in self.get_roster():
			cs_other.evt.on_chat_invite_declined(self, user, invitee_id = user_id, message = message, circle = circle)
	
	def send_participant_status_updated(
		self, cs: 'ChatSession', old_substatus: Substatus, *, initial: bool = False, send_on_bl: bool = False,
	) -> None:
		tmp = []
		
		for cs_self in self.get_roster():
			if cs_self.user is cs.user and cs_self is not cs:
				tmp.append(cs_self)
		
		if len(tmp) > 0:
			first_pop = False
		else:
			first_pop = True
		
		for cs_other in self.get_roster():
			if cs_other == cs and cs.origin == 'yahoo': continue
			if self.circle is not None:
				if self.circle.memberships[cs.user.uuid].blocking and cs_other.user is not cs.user and not send_on_bl: continue
			if cs.bs.user.status.substatus is Substatus.Offline and cs_other.user is cs.user: continue
			cs_other.evt.on_participant_status_updated(cs, first_pop, initial, old_substatus)
	
	def on_leave(self, sess: 'ChatSession') -> None:
		su = self._users_by_sess.pop(sess, None)
		if su is None:
			return
		
		last_pop = False
		
		sess_others = [sess_other for sess_other in self._users_by_sess.keys() if sess_other.user is su[0]]
		
		if sess_others:
			no_primary_pop = True
			for sess_other in sess_others:
				if sess_other.primary_pop:
					no_primary_pop = False
					break
			if no_primary_pop:
				sess_others[-1].primary_pop = True
		else:
			# `sess` was the user's last place in the chat: they've left it (every frontend tells its clients then; with MPoP,
			# the places before it leaving are only for the clients that show places)
			last_pop = True
		
		# Notify others that `sess` has left
		for sess1, _ in self._users_by_sess.items():
			if sess1 is sess:
				continue
			sess1.evt.on_participant_left(sess, last_pop)
				
class ChatSession(Session):
	__slots__ = ('origin', 'user', 'chat', 'bs', 'evt', 'primary_pop', 'front_data', 'preferred_name')
	
	origin: Optional[str]
	user: User
	chat: Chat
	bs: BackendSession
	evt: event.ChatEventHandler
	primary_pop: bool
	front_data: Dict[str, Any]
	preferred_name: Optional[str]
	
	def __init__(
		self, origin: str, bs: BackendSession, chat: Chat, evt: event.ChatEventHandler, primary_pop: bool, *,
		preferred_name: Optional[str] = None,
	) -> None:
		super().__init__()
		self.origin = origin
		self.user = bs.user
		self.chat = chat
		self.bs = bs
		self.evt = evt
		self.primary_pop = primary_pop
		self.front_data = {}
		self.preferred_name = preferred_name
	
	def _on_close(self, **kwargs: Any) -> None:
		self.evt.on_close()
		self.chat.on_leave(self)
	
	def invite(self, invitee: User, *, invite_msg: Optional[str] = None) -> None:
		already_invited_sessions = [] # type: List[BackendSession]
		disabled_sessions = [] # type: List[BackendSession]
		
		ctc_sessions = self.bs.backend.util_get_sessions_by_user(invitee)
		roster = list(self.chat.get_roster())
		for cs_other in roster:
			if cs_other.bs in already_invited_sessions: continue
			for ctc_sess in ctc_sessions:
				if cs_other.bs == ctc_sess and self.origin != 'yahoo':
					already_invited_sessions.append(ctc_sess)
		for ctc_sess in ctc_sessions:
			if ctc_sess in already_invited_sessions: continue
			if not ctc_sess.chat_enabled:
				disabled_sessions.append(ctc_sess)
				continue
			print(f"[Chat] <Info> {self.user.username} ({self.user.email}) has invited {invitee.username} ({invitee.email}) to chat session '{self.chat.ids}' from origin {self.origin}")
			if invite_msg is not None: print(f"[Chat] <Info> Invite message: {invite_msg}")
			ctc_sess.evt.on_chat_invite(self.chat, self.user, invite_msg = invite_msg or '')
		
		if len(ctc_sessions) == len(disabled_sessions): raise error.ContactNotOnline()
		if len(ctc_sessions) == len(already_invited_sessions): raise error.ContactAlreadyOnContactList()
	
	def send_message_to_everyone(self, data: MessageData) -> bool:
		stats = self.chat._stats
		client = self.bs.client
		backend = self.bs.backend

		if client.program not in _UNRATED_PROGRAMS and not backend.util_message_allowed(self.user, data): return False

		if stats and data.type in _STATS_MESSAGE_TYPES:
			stats.on_message_sent(self.user, client)
			stats.on_user_active(self.user, client)

		tracked: Set[str] = set()
		for cs_other in list(self.chat._users_by_sess.keys()):
			if cs_other is self: continue
			if self.chat.circle is not None and self.chat.circle.memberships[cs_other.user.uuid].blocking: continue
			cs_other.evt.on_message(data)
			print(f"[Chat] <Info> {self.user.username} ({self.user.email}) has sent a messasge to {cs_other.user.username} ({cs_other.user.email}) of type {data.type}")
			if stats:
				stats.on_message_received(cs_other.user, client)
			if data.type in RATED_MESSAGE_TYPES and cs_other.user.uuid not in tracked and 'abuse_tracked' not in data.front_cache:
				tracked.add(cs_other.user.uuid)
				backend.abuse.track_message(self.user, cs_other.user)
		if tracked:
			data.front_cache['abuse_tracked'] = True
		return True

	def send_message_to_user(self, user_uuid: str, data: MessageData) -> bool:
		stats = self.chat._stats
		client = self.bs.client
		backend = self.bs.backend

		if client.program not in _UNRATED_PROGRAMS and not backend.util_message_allowed(self.user, data): return False

		if stats and data.type in _STATS_MESSAGE_TYPES:
			stats.on_message_sent(self.user, client)
			stats.on_user_active(self.user, client)

		tracked = False
		for cs_other in list(self.chat._users_by_sess.keys()):
			if cs_other is self: continue
			if cs_other.user.uuid != user_uuid: continue
			print(f"[Chat] <Info> {self.user.username} ({self.user.email}) has sent a messasge to {cs_other.user.username} ({cs_other.user.email}) of type {data.type}")
			cs_other.evt.on_message(data)
			if stats and data.type in _STATS_MESSAGE_TYPES:
				stats.on_message_received(cs_other.user, client)
			if data.type in RATED_MESSAGE_TYPES and not tracked and 'abuse_tracked' not in data.front_cache:
				tracked = True
				backend.abuse.track_message(self.user, cs_other.user)
		if tracked:
			data.front_cache['abuse_tracked'] = True
		return True

def _gen_group_id(detail: UserDetail) -> str:
	id = 1
	s = str(id)
	while s in detail._groups_by_id:
		id += 1
		s = str(id)
	return s

def _gen_contact_id(detail: UserDetail) -> str:
	id = 2
	for i, _ in enumerate(detail.contacts.values()):
		if i+2 == id:
			id += 1
			continue
	s = str(id)
	
	return s

MAX_GROUP_NAME_LENGTH = 61

_STATS_MESSAGE_TYPES = (MessageType.Chat, MessageType.Nudge, MessageType.Emoticon, MessageType.Ink)


# TODO: PL
LST_LIMITS = {
	ContactList.FL: 1000,
	ContactList.AL: 1500,
	ContactList.BL: 1200,
	ContactList.RL: 1500,
}
_UIN_RE = re.compile(r'^[0-9]{1,10}$')

class _WatchRegistry:
	__slots__ = ('_watchers_by_uuid', '_watched_by_sess')
	
	_watchers_by_uuid: Dict[str, Set['BackendSession']]
	_watched_by_sess: Dict['BackendSession', Set[str]]
	
	def __init__(self) -> None:
		self._watchers_by_uuid = {}
		self._watched_by_sess = {}
	
	def add(self, bs: 'BackendSession', uuid: str) -> None:
		self._watchers_by_uuid.setdefault(uuid, set()).add(bs)
		self._watched_by_sess.setdefault(bs, set()).add(uuid)
	
	def remove(self, bs: 'BackendSession', uuid: str) -> None:
		watchers = self._watchers_by_uuid.get(uuid)
		if watchers is not None:
			watchers.discard(bs)
			if not watchers:
				del self._watchers_by_uuid[uuid]
		watched = self._watched_by_sess.get(bs)
		if watched is not None:
			watched.discard(uuid)
			if not watched:
				del self._watched_by_sess[bs]
	
	def remove_session(self, bs: 'BackendSession') -> None:
		for uuid in list(self._watched_by_sess.get(bs, ())):
			self.remove(bs, uuid)
	
	def watched_by(self, bs: 'BackendSession') -> Set[str]:
		return set(self._watched_by_sess.get(bs, ()))
	
	def watchers_of(self, uuid: str) -> List['BackendSession']:
		return [bs for bs in self._watchers_by_uuid.get(uuid, ()) if not bs.closed]

def _sees_through_list(user: User, detail: UserDetail, other: User) -> bool:
	if other.uuid not in detail.contacts: return False
	detail_other = other.detail
	if detail_other is None: return False
	ctc_me = detail_other.contacts.get(user.uuid)
	return ctc_me is not None and bool(ctc_me.lists & ContactList.FL)

def _watch_contact(user: User, viewer: User) -> Contact:
	ctc = Contact(user, set(), ContactList.Empty, UserStatus(user.status.name), ContactDetail('0'))
	ctc.compute_visible_status(viewer)
	return ctc
