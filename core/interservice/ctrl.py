from typing import Tuple, Optional, Iterable, List, Any, Callable, Dict, Coroutine
from disposable_email_domains import blocklist as disposable_emails
from datetime import datetime, timedelta
from enum import Enum
import asyncio, io, hashlib, base64, json, re, traceback, secrets, time
import emoji
import sqlalchemy as sa
from sqlalchemy.orm.attributes import flag_modified

from core.backend import Backend, BackendSession
from core.alerts import Alert, AlertError
from core.models import CircleRole, CircleState, ActivityType, ContactList, User, Activity, Circle
from core import error
from core.user import beacon_enabled, directory_online_visible
from core.stats import collect_snapshot
import core.db as db

from util import misc, hash
from util.avatar import get_img_type, store_avatar_file, store_photo_file

import settings

from .crypto import SecureChannel, ServerKeys, ClientHello, verify_challenge, ed25519_public, INSCryptoError, CHALLENGE_IDN, CHALLENGE_CHK
from .registry import ClientRegistry, ClientRecord

PROTOCOL_VERSION = 'INS2'
LINE_COMMANDS = frozenset(('HLO', 'IDN', 'PRV', 'HBT', 'END'))
JSON_COMMANDS = frozenset((
	'SGN', 'INF', 'WCH', 'ALR', 'MNT', 'ANC', 'MKU', 'EDU', 'RMU', 'GTU', 'LSU', 'LSS', 'GTS', 'KLS', 'CIR', 'CTA', 'CTQ', 'GRP',
	'PRF', 'BFD', 'BST', 'BPH', 'BDL', 'BRX', 'BCM', 'STA',
))
PRE_AUTH_COMMANDS = LINE_COMMANDS
def twemoji_key(chars: str) -> str:
	points = [ord(char) for char in chars]
	if 0x200d not in points:
		points = [point for point in points if point != 0xfe0f]
	return '-'.join('{:x}'.format(point) for point in points)

REACTIONS = frozenset(twemoji_key(chars) for chars, data in emoji.EMOJI_DATA.items() if data['status'] <= emoji.STATUS['fully_qualified'])
LANGUAGE_TAG = re.compile(r'[a-z]{2,3}(-[a-z0-9]{2,8})*', re.I)
MAX_PROFILE_LANGUAGES = 10
PREFS = { 'beacon': 'beacon_off', 'dir_online': 'dir_hide_online' }
LEGACY_PREFS = { 'beacon': ('konekt_off',) }
NFY_EVENTS = frozenset((
	'user.created', 'user.updated', 'user.deleted', 'session.killed', 'maintenance', 'alert', 'announcement', 'activity', 'link',
	'password.reset', 'circle.deleted', 'alert.email',
))
ALERT_NETWORKS = ('msn', 'ymsg', 'aim', 'icq', 'irc')
MAX_LINE = 4096
MAX_PAYLOAD_PRE_AUTH = 4096
MAX_PAYLOAD = 16 * 1024 * 1024
PHOTO_MAX_SIZE = 10 * 1024 * 1024
AVATAR_MAX_SIZE = 2 * 1024 * 1024
USER_TRAITS = ('show_in_dir', 'is_tester', 'is_mvp', 'account_verified', 'verified_to_login', 'alias_active', 'suspended')
PREF_TRAITS = ('beacon', 'dir_online')
CACHED_USER_FIELDS = ('email', 'username', 'uin', 'first_name', 'last_name') + USER_TRAITS
SOFT_USER_FIELDS = ('show_in_dir', 'is_tester', 'is_mvp', 'account_verified', 'is_admin')

class INSFail(Exception):
	code: int
	detail: Dict[str, Any]
	
	def __init__(self, code: int, message: str | None = None, **detail: Any) -> None:
		super().__init__(message or str(code))
		self.code = code
		self.detail = detail
		if message:
			self.detail['error'] = message

class INSProtocolError(Exception):
	too_large: bool
	
	def __init__(self, message: str, *, too_large: bool = False) -> None:
		super().__init__(message)
		self.too_large = too_large

class INSCtrl:
	__slots__ = (
		'logger', 'reader', 'writer', 'peername', 'close_callback', 'closed', 'transport',
		'authenticated', 'current_challenge', 'backend', #'alive', 'alive_task',
		'channel', 'raw_transport', 'link_id', 'identifier', 'client_info', 'version_ok', 'auth_nonce', 'pending_identifier',
		'connected_at', 'last_activity', 'challenge_sent_at', 'next_challenge_at', 'watchdog', 'subscriptions', 'tasks', 'client_record',
	)
	
	logger: misc.Logger
	reader: 'INSReader'
	writer: 'INSWriter'
	peername: Tuple[str, int]
	close_callback: Optional[Callable[[], None]]
	closed: bool
	transport: Optional[asyncio.WriteTransport]
	authenticated: bool
	current_challenge: Optional[str]
	#alive: bool
	#alive_task: Optional[misc.VoidTaskType]
	backend: Backend
	channel: SecureChannel
	raw_transport: asyncio.WriteTransport | None
	link_id: str
	identifier: str | None
	client_info: Dict[str, str]
	version_ok: bool
	auth_nonce: bytes | None
	pending_identifier: str | None
	connected_at: float
	last_activity: float
	challenge_sent_at: float
	next_challenge_at: float
	watchdog: 'asyncio.Task[None] | None'
	subscriptions: set[str]
	tasks: 'set[asyncio.Task[None]]'
	client_record: ClientRecord | None
	
	_keys: ServerKeys | None = None
	_registry: ClientRegistry | None = None
	_links: Dict[str, 'INSCtrl'] = {}
	
	def __init__(self, logger: misc.Logger, via: str, backend: Backend) -> None:
		self.logger = logger
		self.reader = INSReader(logger)
		self.writer = INSWriter(logger)
		self.peername = ('0.0.0.0', 4309)
		self.close_callback = None
		self.closed = False
		self.transport = None
		
		self.authenticated = False
		self.current_challenge = None
		#self.alive = True
		#self.alive_task = None
		self.backend = backend
		
		keys = INSCtrl._keys
		assert keys is not None and INSCtrl._registry is not None, "InterService keys not loaded, call `INSCtrl.configure` first"
		self.channel = SecureChannel.server(keys.host, self._resolve_client)
		self.client_record = None
		self.raw_transport = None
		self.link_id = secrets.token_hex(8)
		self.identifier = None
		self.client_info = {}
		self.version_ok = False
		self.auth_nonce = None
		self.pending_identifier = None
		self.connected_at = time.monotonic()
		self.last_activity = self.connected_at
		self.challenge_sent_at = 0.0
		self.next_challenge_at = 0.0
		self.watchdog = None
		self.subscriptions = set()
		self.tasks = set()
	
	@classmethod
	def configure(cls, keys: ServerKeys, registry: ClientRegistry) -> None:
		cls._keys = keys
		cls._registry = registry
		registry.on_revoke = cls._client_revoked
	
	@classmethod
	def attach(cls, backend: Backend) -> None:
		backend.on_user_deleted = lambda uuid, reason: cls.broadcast('user.deleted', { 'uuid': uuid, 'reason': reason })
	
	@classmethod
	def _client_revoked(cls, record: ClientRecord) -> None:
		for link in list(cls._links.values()):
			if link.client_record is not None and link.client_record.id == record.id:
				link.logger.info(f'InterService link {link.identifier} closed, its key was revoked')
				link.close('REV')
	
	def _resolve_client(self, hello: ClientHello) -> ClientRecord:
		registry = INSCtrl._registry
		assert registry is not None
		record = registry.resolve(hello, self.peername[0] if self.peername else '', self.logger)
		self.client_record = record
		return record
	
	def connection_made(self, transport: asyncio.WriteTransport) -> None:
		self.raw_transport = transport
		self.peername = transport.get_extra_info('peername')
		self.watchdog = self.backend.loop.create_task(self._watchdog())
	
	def _m_hlo(self, trid: str, *args: str) -> None:
		if not args or args[0] != PROTOCOL_VERSION:
			self.send_reply('HLO', trid, '-')
			self.close()
			return
		self.version_ok = True
		if len(args) >= 3:
			self.client_info = { 'program': args[1][:32], 'version': args[2][:32] }
		self.send_reply('HLO', trid, PROTOCOL_VERSION, 'azul', settings.VERSION)
	
	def _m_idn(self, trid: str, *args: str) -> None:
		if self.authenticated:
			raise INSFail(Err.AlreadyAuthenticated)
		if not self.version_ok:
			raise INSFail(Err.ProtocolVersionUnsupported, 'HLO must come first')
		if len(args) < 1:
			raise INSFail(Err.TooFewArguments)
		identifier_dec = args[0]
		valid_identifiers = settings.INS_IDENTIFIERS
		if identifier_dec not in valid_identifiers:
			self.logger.info(f'InterService identification failed, invalid identifier "{identifier_dec}".')
			self.send_numeric(Err.AuthenticationFailed, trid)
			self.close()
			return
		record = self.client_record
		if record is None or record.revoked or record.identifier != identifier_dec:
			self.logger.info(f'InterService identification failed, "{identifier_dec}" does not match the key\'s enrollment')
			self.send_numeric(Err.AuthenticationFailed, trid)
			self.close()
			return
		self.pending_identifier = identifier_dec
		self.auth_nonce = secrets.token_bytes(32)
		self.send_reply('IDN', trid, base64.b64encode(self.auth_nonce).decode('ascii'))
	
	def _m_prv(self, trid: str, *args: str) -> None:
		if self.authenticated:
			raise INSFail(Err.AlreadyAuthenticated)
		nonce = self.auth_nonce
		identifier_dec = self.pending_identifier
		record = self.client_record
		self.auth_nonce = None
		if nonce is None or identifier_dec is None or record is None or record.revoked or not args or not verify_challenge(
			ed25519_public(record.auth_public), args[0], CHALLENGE_IDN, nonce, self.channel.binding, identifier_dec,
		):
			self.logger.info(f'InterService authentication failed for identifier "{identifier_dec}", bad challenge response')
			self.send_numeric(Err.AuthenticationFailed, trid)
			self.close()
			return
		
		backend = self.backend
		self.authenticated = True
		self.identifier = identifier_dec
		self.reader.max_payload = MAX_PAYLOAD
		INSCtrl._links[self.link_id] = self
		backend._linked = True
		# TODO: Re-implement in V2
		#self.alive_task = backend.loop.create_task(self._ping_conn())
		if settings.INS_CHALLENGE_INTERVAL > 0:
			self.next_challenge_at = time.monotonic() + settings.INS_CHALLENGE_INTERVAL
		registry = INSCtrl._registry
		if registry is not None:
			registry.seen(record, self.peername[0] if self.peername else '')
		self.logger.info(f'New InterService session established (identifier: {identifier_dec}, client: "{record.label}", key: {record.fingerprint}, enrolled now: {self.channel.enrolled}, post-quantum: {self.channel.post_quantum})')
		self.send_reply('PRV', trid, identifier_dec, self.link_id)
		INSCtrl.broadcast('link', { 'state': 'up', 'identifier': identifier_dec, 'link': self.link_id }, exclude = self)
	
	#def _m_pong(self, challenge: str) -> None:
	#	if self.alive: return
	#	if not self.current_challenge or challenge != self.current_challenge:
	#		self.close()
	#		return
	#	self.alive = True
	#	self.current_challenge = None
	
	def _m_hbt(self) -> None:
		self.send_reply('HBT', str(settings.INS_PING_INTERVAL))
	
	def _m_end(self) -> None:
		self.send_reply('END')
		self.close()
	
	def _m_sgn(self, trid: str, data: Dict[str, Any]) -> None:
		record = self.client_record
		challenge = self.current_challenge
		if challenge is None:
			raise INSFail(Err.InvalidArgument, 'no challenge pending')
		self.current_challenge = None
		if record is None or record.revoked or not verify_challenge(
			ed25519_public(record.auth_public), str(data.get('signature') or ''), CHALLENGE_CHK, base64.b64decode(challenge), self.channel.binding, self.identifier or '',
		):
			self.logger.info(f'InterService link {self.identifier} failed its challenge')
			self.send_numeric(Err.ChallengeFailed, trid)
			self.close('CHL')
			return
		self.next_challenge_at = time.monotonic() + settings.INS_CHALLENGE_INTERVAL
		self.send_payload('SGN', trid, None)
	
	def _m_inf(self, trid: str, data: Dict[str, Any]) -> None:
		backend = self.backend
		sessions = list(backend._sc.iter_sessions())
		self.send_payload('INF', trid, {
			'server': 'azul', 'version': settings.VERSION, 'protocol': PROTOCOL_VERSION,
			'link': self.link_id, 'identifier': self.identifier,
			'maintenance': {
				'active': backend.maintenance_mode, 'pending': backend.notify_maintenance, 'minutes': backend.maintenance_mins,
			},
			'sessions': len(sessions),
			'users_online': len({ bs.user.uuid for bs in sessions }),
			'links': [
				{
					'link': link.link_id, 'identifier': link.identifier, 'client': link.client_info, 'peer': link.peername[0] if link.peername else None,
					'label': link.client_record.label if link.client_record else None,
					'key': link.client_record.fingerprint if link.client_record else None,
				}
				for link in INSCtrl._links.values()
			],
			'commands': sorted(JSON_COMMANDS | LINE_COMMANDS),
			'post_quantum': self.channel.post_quantum,
			'events': sorted(NFY_EVENTS),
			'ping_interval': settings.INS_PING_INTERVAL,
			'challenge_interval': settings.INS_CHALLENGE_INTERVAL,
			'started': backend._stats.snapshot_started(),
			'uptime': backend._stats.uptime(),
			'services': _services(backend),
		})
	
	def _m_sta(self, trid: str, data: Dict[str, Any]) -> None:
		self.send_payload('STA', trid, collect_snapshot(self.backend))
	
	def _m_wch(self, trid: str, data: Dict[str, Any]) -> None:
		events = data.get('events')
		if not isinstance(events, list):
			raise INSFail(Err.InvalidArgument, 'events must be a list')
		wanted = { str(e) for e in events }
		unknown = wanted - NFY_EVENTS - { '*' }
		if unknown:
			raise INSFail(Err.InvalidArgument, 'unknown events', events = sorted(unknown))
		self.subscriptions = wanted
		self.send_payload('WCH', trid, { 'events': sorted(wanted) })
	
	def _m_cir(self, trid: str, data: Dict[str, Any]) -> None:
		backend = self.backend
		action = _req_str(data, 'action').upper()
		
		if action == 'LIST':
			self.send_payload('CIR', trid, { 'circles': [_circle_info(circle, members = False) for circle in backend.user_service.get_all_circles()] })
			return
		
		chat_id = _req_str(data, 'chat_id')
		circle = backend.user_service.get_circle(chat_id)
		
		if circle is None:
			raise INSFail(Err.CircleDoesNotExist)
		
		if action == 'INFO':
			self.send_payload('CIR', trid, _circle_info(circle, members = True, backend = backend))
			return
		
		if action == 'DELETE':
			if data.get('uuid') or data.get('email'):
				owner = self._user_from(data)
				membership = circle.memberships.get(owner.uuid)
				if membership is None or membership.role is not CircleRole.Admin or membership.state is not CircleState.Accepted:
					raise INSFail(Err.DoesntHaveSufficientPermissions)
			members = backend.util_delete_circle(circle)
			self.logger.info(f'Circle {circle.name} ({chat_id}) deleted, {len(members)} members dropped')
			self.send_payload('CIR', trid, { 'chat_id': chat_id, 'action': action, 'members': len(members), 'status': StatusCode.CircleActionSuccessful })
			INSCtrl.broadcast('circle.deleted', { 'chat_id': chat_id }, exclude = self)
			return
		
		user = self._user_from(data)
		
		if action == 'INCHAT':
			try:
				in_chat = backend.util_user_online_in_circle(circle, user)
			except error.MemberNotInCircle:
				raise INSFail(Err.CircleMemberInvalid)
			self.send_payload('CIR', trid, { 'chat_id': chat_id, 'uuid': user.uuid, 'in_chat': in_chat })
			return
		elif action == 'ACCEPT':
			try:
				backend.util_accept_circle_invite(circle, user)
			except error.MemberNotInCircle:
				raise INSFail(Err.CircleMemberInvalid)
			except error.MemberAlreadyInCircle:
				raise INSFail(Err.MemberAlreadyInCircle)
		elif action == 'DECLINE':
			try:
				backend.util_decline_circle_invite(circle, user)
			except error.MemberNotInCircle:
				raise INSFail(Err.CircleMemberInvalid)
			except error.MemberAlreadyInCircle:
				raise INSFail(Err.MemberAlreadyInCircle)
		elif action == 'REVOKE':
			try:
				backend.util_revoke_circle_invite(circle, user)
			except error.MemberNotInCircle:
				raise INSFail(Err.CircleMemberInvalid)
			except error.MemberAlreadyInCircle:
				raise INSFail(Err.MemberAlreadyInCircle)
		elif action == 'ROLE':
			user_self = None
			if data.get('uuid_self') or data.get('email_self'):
				user_self = self._user_from({ 'uuid': data.get('uuid_self'), 'email': data.get('email_self') })
			
			try:
				role = CircleRole(int(data.get('role')))
				if user_self is not None and role is not CircleRole.Admin: raise ValueError()
				
				backend.util_change_circle_membership_role(circle, user, role, user_self)
			except (ValueError, TypeError):
				raise INSFail(Err.CircleRoleInvalid)
			except error.MemberNotInCircle:
				raise INSFail(Err.CircleMemberInvalid)
			except error.CircleMemberIsPending:
				raise INSFail(Err.CircleMemberIsPending)
			except error.MemberDoesntHaveSufficientCircleRole:
				raise INSFail(Err.DoesntHaveSufficientPermissions)
		elif action == 'REMOVE':
			try:
				backend.util_remove_user_from_circle(circle, user)
			except error.MemberNotInCircle:
				raise INSFail(Err.CircleMemberInvalid)
			except error.CantLeaveCircle:
				raise INSFail(Err.CantLeaveCircle)
		else:
			raise INSFail(Err.InvalidArgument, 'unknown circle action')
		
		self.send_payload('CIR', trid, { 'chat_id': chat_id, 'uuid': user.uuid, 'action': action, 'status': StatusCode.CircleActionSuccessful })
	
	def _m_alr(self, trid: str, data: Dict[str, Any]) -> None:
		backend = self.backend
		if str(data.get('action') or '').upper() == 'LIST':
			self.send_payload('ALR', trid, { 'alerts': list(reversed(backend.recent_alerts)) })
			return
		
		def number(key: str, default: int) -> int:
			value = data.get(key)
			if value in (None, ''):
				return default
			try:
				return int(value)
			except (TypeError, ValueError):
				raise INSFail(Err.InvalidArgument, '{} must be a number'.format(key), field = key)
		
		targets = data.get('targets', 'all')
		if isinstance(targets, str):
			targets = [t.strip() for t in targets.split(',') if t.strip()]
		if not isinstance(targets, list):
			raise INSFail(Err.InvalidArgument, 'targets must be "all" or a list', field = 'targets')
		targets = [str(t).strip() for t in targets if str(t).strip()]
		everyone = not targets or targets == ['all']
		networks = data.get('networks') or list(ALERT_NETWORKS)
		if not isinstance(networks, list) or not networks or any(n not in ALERT_NETWORKS for n in networks):
			raise INSFail(Err.InvalidArgument, 'networks is a list of {}'.format(', '.join(ALERT_NETWORKS)), field = 'networks')
		email = bool(data.get('email'))
		if email and everyone:
			raise INSFail(Err.InvalidArgument, 'alerts are only e-mailed to the people named in targets', field = 'email')
		kind = str(data.get('kind') or 'bell')
		
		try:
			alert = Alert(
				str(data.get('text') or data.get('message') or ''), rich = str(data.get('rich') or '') or None,
				align = str(data.get('align') or 'left'), url = str(data.get('url') or ''), subscr_url = str(data.get('subscr_url') or ''),
				icon = str(data.get('icon') or ''), kind = kind, lang = number('lang', 1033), priority = number('priority', 1),
				message_id = number('message_id', 0), via = str(data.get('via') or '') or None,
				email_text = (str(data.get('email_text') or '').strip() or None) if email else None,
			)
			if email and not alert.email_text:
				alert.email_text = alert.plain_with_link()
			alert.check(emailed = email)
		except AlertError as ex:
			raise INSFail(Err.InvalidArgument, str(ex), field = ex.field)
		
		sessions = set()
		recipients: dict[str, User] = {}
		if everyone:
			sessions = set(backend._sc.iter_sessions())
		else:
			for t in targets:
				uuid = (backend.util_get_uuid_from_email(t) if '@' in t else None) or backend.util_get_uuid_from_username(t) or t
				user = backend._load_user_record(uuid)
				if user:
					recipients[user.uuid] = user
					for s in backend.util_get_sessions_by_user(user):
						sessions.add(s)
					continue
				for bs in backend._sc.iter_sessions():
					if str(id(bs)) == t:
						sessions.add(bs)
		
		counts: dict[str, int] = { network: 0 for network in networks }
		skipped = 0
		for bs in sessions:
			program = bs.client.program
			if program not in networks:
				continue
			if bs.evt.on_client_alert(alert):
				counts[program] += 1
			else:
				skipped += 1
		delivered = sum(counts.values())
		
		emailed = 0
		if email and recipients:
			emailed = len(recipients)
			INSCtrl.broadcast('alert.email', {
				'id': alert.id, 'subject': (alert.plain().split('\n', 1)[0])[:100], 'text': alert.email_text, 'url': alert.url,
				'recipients': [{ 'uuid': user.uuid, 'email': user.email, 'username': user.username } for user in recipients.values()],
			})
		
		summary = { 'id': alert.id, 'delivered': delivered, 'networks': counts, 'skipped': skipped, 'emailed': emailed }
		backend.recent_alerts.append({
			**alert.summary(), 'date': datetime.utcnow().isoformat() + 'Z', 'by': getattr(self, 'actor', None) or self.identifier,
			'targets': 'all' if everyone else targets, **summary,
		})
		self.send_payload('ALR', trid, summary)
		INSCtrl.broadcast('alert', summary, exclude = self)
	
	def _m_mnt(self, trid: str, data: Dict[str, Any]) -> None:
		try:
			mt_mins = int(data.get('minutes'))
		except (ValueError, TypeError):
			raise INSFail(Err.TooFewArguments, 'minutes is required')
		if mt_mins < 0:
			raise INSFail(Err.InvalidArgument, 'minutes must not be negative')
		if self.backend.maintenance_mode or self.backend.notify_maintenance:
			raise INSFail(Err.ServerInModeAlready)
		self.backend.push_maintenance_message(1, mt_mins)
		self.send_payload('MNT', trid, None)
		INSCtrl.broadcast('maintenance', { 'minutes': mt_mins }, exclude = self)
	
	def _m_anc(self, trid: str, data: Dict[str, Any]) -> None:
		title = str(data.get('title') or '').strip()
		content = str(data.get('text') or '').strip()
		url = str(data.get('url') or '').strip()
		
		if not title or not content:
			raise INSFail(Err.InvalidArgument, 'title and text are required')
		
		self.backend.user_service.add_activity(None, ActivityType.Announcement, title = title, text = content, url = url or None)
		self.send_payload('ANC', trid, None)
		INSCtrl.broadcast('announcement', { 'title': title }, exclude = self)
	
	def _m_mku(self, trid: str, data: Dict[str, Any]) -> None:
		email = _req_str(data, 'email')
		username = _req_str(data, 'username')
		first_name = str(data.get('first_name') or '')
		last_name = str(data.get('last_name') or '')
		try:
			uin = int(data.get('uin') or 0)
		except (ValueError, TypeError):
			raise INSFail(Err.InvalidArgument, 'uin must be a number')
		password = _req_str(data, 'password')
		flags = _client_flags(data)
		if len(username) > 32:
			raise INSFail(Err.TooManyCharactersUsername)
		if len(email) > 254:
			raise INSFail(Err.TooManyCharactersEmail)
		if username and not username.isalnum():
			raise INSFail(Err.InvalidArgument, 'username must be alphanumeric')
		try:
			with db.Session() as sess:
				user_row = sess.query(db.User).filter_by(email=email).one_or_none()
				if user_row is not None:
					raise INSFail(Err.EmailTaken)
				with open('config/restricted-usernames.json', 'r') as file:
					restricted_usernames = json.load(file)
					if username.lower() in restricted_usernames:
						raise INSFail(Err.RestrictedUseranme)
				with open('config/restricted-emails.json', 'r') as file:
					restricted_emails = json.load(file)
					email_domain = email.lower().split('@')[-1] if '@' in email else ''
					if email_domain in restricted_emails:
						raise INSFail(Err.RestrictedEmail)
				if email_domain in disposable_emails:
					raise INSFail(Err.RestrictedEmail)
				username_conflict = sess.query(db.User).filter_by(username=username).one_or_none()
				email_conflict = sess.query(db.User).filter_by(email=email).one_or_none()
				if username_conflict:
					raise INSFail(Err.UsernameTaken)
				elif email_conflict:
					raise INSFail(Err.EmailTaken)
				if uin and sess.query(db.User).filter_by(uin=uin).first() is not None:
					raise INSFail(Err.UinTaken)
				new_user = db.User(
					uuid=misc.gen_uuid(),
					email=email,
					first_name=first_name,
					last_name=last_name,
					username=username,
					uin=uin,
					verified_to_login=False,
					account_verified=False,
					alias_active=False,
					friendly_name=email,
					groups={},
					settings={},
					suspended=False,
					is_tester=False,
					is_mvp=False,
					show_in_dir=False
				)
				_set_passwords_and_prune(new_user, password, flags)
				sess.add(new_user)
				self.logger.info(f"New user created")
				self.logger.info(f"UUID: {new_user.uuid}")
				self.logger.info(f"Username: {new_user.username}")
				self.logger.info(f"E-mail: {new_user.email}")
				self.logger.info(f"UIN: {new_user.uin}")
				self.logger.info(f"Flags: {flags}")
				sess.commit()
				created_uuid = new_user.uuid
		except INSFail:
			raise
		except Exception as e:
			self.logger.error(e)
			raise INSFail(Err.UserCreationFailed)
		try:
			domain_user = self.backend._load_user_record(created_uuid)
			if domain_user is not None:
				try:
					detail = self.backend._load_detail(domain_user)
				except Exception:
					detail = None
				self.backend._mark_modified(domain_user, detail=detail)
		except Exception as e:
			self.logger.error(e)
			self.logger.info("post-create backend processing failed")
		
		self.send_payload('MKU', trid, { 'uuid': created_uuid })
		INSCtrl.broadcast('user.created', { 'uuid': created_uuid }, exclude = self)
	
	def _m_edu(self, trid: str, data: Dict[str, Any]) -> None:
		uuid = _req_str(data, 'uuid')
		fields = data.get('fields')
		if not isinstance(fields, dict) or not fields:
			raise INSFail(Err.TooFewArguments, 'fields must be a non-empty object')
		updated = self._user_update(uuid, { str(k): v for k, v in fields.items() }, _client_flags(data))
		self.send_payload('EDU', trid, { 'uuid': uuid, 'updated': updated })
		INSCtrl.broadcast('user.updated', { 'uuid': uuid, 'fields': updated }, exclude = self)
	
	def _user_update(self, uuid: str, fields: Dict[str, Any], flags: List[str]) -> List[str]:
		values = { field: _value_to_str(value) for field, value in fields.items() }
		if 'alias_active' in values:
			try:
				self.backend._handle_worklist_notify()
				self.backend._worklist_notify.clear()
			except Exception:
				traceback.print_exc()
		_avatar_md5 = None
		avatar_old = None
		try:
			with db.Session() as sess:
				user_row = sess.query(db.User).filter_by(uuid=uuid).one_or_none()
				if user_row is None:
					raise INSFail(Err.UserNotInDB)
				avatar_old = user_row.avatar
				for field, new_raw_value in values.items():
					md5 = self._user_update_field(sess, user_row, uuid, field, new_raw_value, flags)
					if md5 is not None:
						_avatar_md5 = md5
		except INSFail:
			raise
		except Exception:
			traceback.print_exc()
			raise INSFail(Err.ServerUnknownError)
		
		try:
			domain_user = self.backend._load_user_record(uuid)
		except Exception:
			domain_user = None
		if domain_user is not None:
			for field, new_raw_value in values.items():
				if field not in CACHED_USER_FIELDS or not hasattr(domain_user, field):
					continue
				try:
					setattr(domain_user, field, _parse_value_for_column(db.User.__table__.columns[field], new_raw_value))
				except Exception as e:
					self.logger.error(e)
					self.logger.info(f"Failed to update cached {field}")
			if _avatar_md5:
				try:
					domain_user.avatar = _avatar_md5
				except Exception as e:
					self.logger.error(e)
					self.logger.info("Failed to update cached avatar")
			if any(not (field in SOFT_USER_FIELDS or field.startswith('profile.')) for field in values):
				for bs in self.backend.util_get_sessions_by_user(domain_user):
					try:
						bs.close()
					except Exception:
						pass
			try:
				try:
					detail = self.backend._load_detail(domain_user)
				except Exception:
					detail = None
				self.backend._mark_modified(domain_user, detail=detail)
			except Exception as e:
				self.logger.error(e)
				self.logger.info("Failed while post-processing USER UPDATE")
			if _avatar_md5 and _avatar_md5 != avatar_old:
				if self.backend.user_service.add_activity(domain_user, ActivityType.DisplayPicture, text = _avatar_md5):
					self.backend.notify_whats_new(domain_user)
		
		for field, new_raw_value in values.items():
			output_value = "[REDACTED]" if field == "password" else ("[IMAGE]" if field == 'avatar_b64' else new_raw_value)
			if domain_user is not None:
				self.logger.info(f"{domain_user.username} ({domain_user.email}) has changed user attribute {field} to {output_value}")
			else:
				self.logger.info(f"User with UUID {uuid} (unresolved) has changed user attribute {field} to {output_value}")
		return list(values)
	
	def _user_update_field(self, sess: Any, user_row: Any, uuid: str, field: str, new_raw_value: str, flags: List[str]) -> str | None:
		try:
			return self._user_update_field_impl(sess, user_row, uuid, field, new_raw_value, flags)
		except INSFail as ex:
			ex.detail.setdefault('field', field)
			raise
	
	def _user_update_field_impl(self, sess: Any, user_row: Any, uuid: str, field: str, new_raw_value: str, flags: List[str]) -> str | None:
		if field == 'is_admin':
			if not getattr(self, 'privileged', False):
				raise INSFail(Err.InvalidArgument, 'is_admin can only be changed from the admin panel')
			user_row.is_admin = _parse_value_for_column(user_row.__table__.columns['is_admin'], new_raw_value)
			sess.add(user_row)
			return None
		if field == 'password':
			if not new_raw_value:
				raise INSFail(Err.TooFewArguments)
			_set_passwords_and_prune(user_row, new_raw_value, flags)
			sess.add(user_row)
			try:
				self.backend._user_by_uuid.pop(uuid, None)
			except Exception as e:
				self.logger.error(e)
				self.logger.info("Failed to nuke stale user cache")
		#elif field not in ('account_verified', 'verified_to_login') and not user_row.verified_to_login:
		#	return self.send_numeric(Err.EmailNotVerified, ts)
		elif field == 'alias_active' and not user_row.account_verified:
			raise INSFail(Err.EmailNotVerified)
		elif field in ('show_in_dir', 'alias_active', 'account_verified', 'verified_to_login', 'suspended', 'is_tester', 'is_mvp'):
			col = user_row.__table__.columns[field]
			parsed_val = _parse_value_for_column(col, new_raw_value)
			if field == 'suspended':
				if parsed_val and not user_row.suspended:
					user_row.suspended_at = datetime.utcnow()
				elif not parsed_val:
					user_row.suspended_at = None
			setattr(user_row, field, parsed_val)
			sess.add(user_row)
		elif field == 'avatar_b64':
			try:
				img_data = base64.b64decode(new_raw_value)
			except Exception:
				raise INSFail(Err.InvalidArgument)
			ext = get_img_type(img_data)
			if ext is None:
				raise INSFail(Err.ImageInvalid)
			if len(img_data) > AVATAR_MAX_SIZE:
				raise INSFail(Err.PayloadTooLarge)
			try:
				_avatar_md5 = store_avatar_file(uuid, img_data, ext)
			except Exception:
				traceback.print_exc()
				raise INSFail(Err.ServerUnknownError)
			user_row.avatar = _avatar_md5
			sess.add(user_row)
			return _avatar_md5
		elif field.startswith('profile.'):
			prof_field = field.split('.', 1)[1]
			profile = sess.query(db.UserProfile).filter_by(user_id=user_row.id).one_or_none()
			if not profile:
				profile = db.UserProfile(user_id=user_row.id)
				sess.add(profile)
				sess.flush()
			if prof_field == 'interests':
				try:
					interests_json = json.loads(new_raw_value)
					if not isinstance(interests_json, list):
						raise INSFail(Err.InvalidArgument)
					total_len = 0
					for item in interests_json:
						if not isinstance(item, str):
							raise INSFail(Err.InvalidArgument)
						if len(item) > 50:
							raise INSFail(Err.InvalidArgument)
						total_len += len(item)
					if total_len > 200:
						raise INSFail(Err.InvalidArgument)
					profile.interests = interests_json
				except json.JSONDecodeError:
					raise INSFail(Err.InvalidArgument)
			elif prof_field == 'pronouns':
				if len(new_raw_value) > 16:
					raise INSFail(Err.InvalidArgument)
				col = profile.__table__.columns[prof_field]
				val = _parse_value_for_column(col, new_raw_value)
				setattr(profile, prof_field, val)
			elif prof_field == 'website':
				if len(new_raw_value) > 75:
					raise INSFail(Err.InvalidArgument)
				col = profile.__table__.columns[prof_field]
				val = _parse_value_for_column(col, new_raw_value)
				setattr(profile, prof_field, val)
			elif prof_field == 'bio':
				new_raw_value = new_raw_value.replace('\\n', '\n')
				if len(new_raw_value) > 200:
					raise INSFail(Err.InvalidArgument)
				col = profile.__table__.columns[prof_field]
				val = _parse_value_for_column(col, new_raw_value)
				setattr(profile, prof_field, val)
			elif prof_field == 'visibility':
				if new_raw_value not in ('public', 'members_only'):
					raise INSFail(Err.InvalidArgument)
				profile.visibility = new_raw_value
			elif prof_field == 'language':
				try:
					languages = json.loads(new_raw_value)
				except json.JSONDecodeError:
					raise INSFail(Err.InvalidArgument)
				if not isinstance(languages, list) or len(languages) > MAX_PROFILE_LANGUAGES:
					raise INSFail(Err.InvalidArgument)
				for item in languages:
					if not isinstance(item, str) or not LANGUAGE_TAG.fullmatch(item):
						raise INSFail(Err.InvalidArgument)
				profile.language = list(dict.fromkeys(item.lower() for item in languages))
			elif prof_field not in profile.__table__.columns or prof_field == 'user_id':
				raise INSFail(Err.InvalidArgument)
			else:
				col = profile.__table__.columns[prof_field]
				val = _parse_value_for_column(col, new_raw_value)
				setattr(profile, prof_field, val)
			sess.add(profile)
		else:
			if field.endswith('_uuid') or field in ('id', 'uuid', 'password', 'avatar', 'date_created', 'suspended_at'):
				raise INSFail(Err.InvalidArgument)
			if '.' in field:
				top, sub = field.split('.', 1)
				if top not in user_row.__table__.columns:
					raise INSFail(Err.InvalidArgument)
				col = user_row.__table__.columns[top]
				tname = col.type.__class__.__name__.lower()
				if 'json' in tname or 'json' in str(col.type).lower():
					orig = dict(getattr(user_row, top) or {})
					try:
						subval = json.loads(new_raw_value)
					except Exception:
						subval = new_raw_value
					orig[sub] = subval
					setattr(user_row, top, orig)
					flag_modified(user_row, top)
					sess.add(user_row)
				else:
					raise INSFail(Err.InvalidArgument)
			else:
				if field not in user_row.__table__.columns:
					raise INSFail(Err.InvalidArgument)
				if field == 'username' and len(new_raw_value) > 32:
					raise INSFail(Err.TooManyCharactersUsername)
				if field == 'email' and len(new_raw_value) > 254:
					raise INSFail(Err.TooManyCharactersEmail)
				if field == 'username' and new_raw_value and not new_raw_value.isalnum():
					raise INSFail(Err.InvalidArgument)
				if field == 'username' and sess.query(db.User).filter(db.User.username == new_raw_value, db.User.uuid != uuid).first() is not None:
					raise INSFail(Err.UsernameTaken)
				if field == 'email' and sess.query(db.User).filter(db.User.email == new_raw_value, db.User.uuid != uuid).first() is not None:
					raise INSFail(Err.EmailTaken)
				if field == 'uin' and new_raw_value and sess.query(db.User).filter(db.User.uin == new_raw_value, db.User.uuid != uuid).first() is not None:
					raise INSFail(Err.UinTaken)
				if field == 'username':
					with open('config/restricted-usernames.json', 'r') as file:
						restricted_usernames = json.load(file)
						if new_raw_value.lower() in restricted_usernames:
							raise INSFail(Err.RestrictedUseranme)
				if field == 'email':
					with open('config/restricted-emails.json', 'r') as file:
						restricted_emails = json.load(file)
						email_domain = new_raw_value.lower().split('@')[-1] if '@' in new_raw_value else ''
						if email_domain in restricted_emails:
							raise INSFail(Err.RestrictedEmail)
					if email_domain in disposable_emails:
						raise INSFail(Err.RestrictedEmail)
				col = user_row.__table__.columns[field]
				val = _parse_value_for_column(col, new_raw_value)
				setattr(user_row, field, val)
				sess.add(user_row)
		return None
	
	def _m_rmu(self, trid: str, data: Dict[str, Any]) -> None:
		uuid = _req_str(data, 'uuid')
		backend = self.backend
		try:
			domain_user = backend.util_delete_user(uuid)
		except Exception as e:
			self.logger.error(e)
			self.logger.info("USER DELETE failed")
			raise INSFail(Err.ServerUnknownError)
		if domain_user is None:
			raise INSFail(Err.UserNotInDB)
		self.logger.info(f"{domain_user.username} ({domain_user.email}) has deleted their account")
		self.send_payload('RMU', trid, None)
		INSCtrl.broadcast('user.deleted', { 'uuid': uuid, 'reason': 'removed' }, exclude = self)
	
	def _m_gtu(self, trid: str, data: Dict[str, Any]) -> None:
		user = self._user_from(data)
		info = self._user_info(user, full = True)
		with db.Session() as sess:
			row = sess.query(db.User).filter_by(uuid = user.uuid).one_or_none()
			if row is not None:
				front = row._front_data or {}
				info['clients'] = [flag for flag, key in (('oldmsn', 'msn'), ('yahoo', 'ymsg'), ('oldaim', 'aim'), ('msim', 'msim')) if key in front]
				if getattr(self, 'privileged', False):
					info['is_admin'] = bool(row.is_admin)
				if row.suspended:
					info.update(_suspension(row))
		self.send_payload('GTU', trid, info)
	
	def _m_lsu(self, trid: str, data: Dict[str, Any]) -> None:
		try:
			since = int(data.get('since') or 60)
		except (ValueError, TypeError):
			raise INSFail(Err.InvalidArgument, 'since must be a number of minutes')
		online_since = datetime.utcnow() - timedelta(minutes = since)
		try:
			limit = max(0, min(200, int(data.get('limit') or 0)))
			offset = max(0, int(data.get('offset') or 0))
		except (ValueError, TypeError):
			raise INSFail(Err.InvalidArgument, 'limit and offset must be numbers')
		query = str(data.get('query') or '').strip()
		trait = str(data.get('trait') or '').strip()
		negate = trait.startswith('!')
		trait = trait.lstrip('!')
		traits = USER_TRAITS + ('online',) + (('is_admin',) if getattr(self, 'privileged', False) else ())
		if trait and trait not in traits:
			raise INSFail(Err.InvalidArgument, 'trait must be one of {}'.format(', '.join(traits)), field = 'trait')
		online_uuids = { bs.user.uuid for bs in self.backend._sc.iter_sessions() }
		with db.Session() as sess:
			total = sess.query(sa.func.count(db.User.id)).scalar() or 0
			recent = sess.query(sa.func.count(db.User.id)).filter(db.User.date_login >= online_since).scalar() or 0
			emails = ([email for (email,) in sess.query(db.User.email).order_by(db.User.email)] if data.get('verbose') else None)
			users: list[dict[str, Any]] | None = None
			matched = None # type: Optional[int]
			if limit:
				rows = sess.query(db.User)
				if query:
					like = '%{}%'.format(query.replace('%', '').replace('_', ''))
					rows = rows.filter(sa.or_(db.User.username.ilike(like), db.User.email.ilike(like), db.User.uuid == query))
				if trait == 'online':
					signed_in = db.User.uuid.in_(online_uuids) if online_uuids else sa.false()
					rows = rows.filter(sa.not_(signed_in) if negate else signed_in)
				elif trait:
					column = getattr(db.User, trait)
					rows = rows.filter(sa.or_(column.is_(None), column == sa.false()) if negate else column == sa.true())
				matched = rows.with_entities(sa.func.count(db.User.id)).scalar() or 0
				users = [
					{
						'uuid': row.uuid, 'username': row.username, 'email': row.email, 'uin': row.uin,
						'date_created': _iso(row.date_created), 'date_login': _iso(row.date_login), 'online': row.uuid in online_uuids,
						**{ trait: bool(getattr(row, trait, False)) for trait in USER_TRAITS },
						**({ 'is_admin': bool(row.is_admin) } if getattr(self, 'privileged', False) else {}),
						**(_suspension(row) if row.suspended else {}),
					}
					for row in rows.order_by(db.User.id.desc()).offset(offset).limit(limit)
				]
		result = {
			'total': total, 'since': since, 'logged_in_since': recent,
			'online': len(online_uuids),
		} # type: Dict[str, Any]
		if emails is not None:
			result['emails'] = emails
		if users is not None:
			result['users'] = users
			result['matched'] = matched
		self.send_payload('LSU', trid, result)
	
	def _m_lss(self, trid: str, data: Dict[str, Any]) -> None:
		# TODO: make this a payload command
		flt = data.get('filter') or {}
		if not isinstance(flt, dict):
			raise INSFail(Err.InvalidArgument, 'filter must be an object')
		group = str(data.get('group') or 'session').lower()
		if group not in ('session', 'user'):
			raise INSFail(Err.InvalidArgument, 'group must be session or user')
		try:
			limit = max(0, int(data.get('limit') or 0))
			offset = max(0, int(data.get('offset') or 0))
		except (ValueError, TypeError):
			raise INSFail(Err.InvalidArgument, 'limit and offset must be numbers')
		
		matched = [bs for bs in self.backend._sc.iter_sessions() if _session_matches(bs, flt)]
		
		if group == 'user':
			users: dict[str, dict[str, Any]] = {}
			for bs in matched:
				entry = users.get(bs.user.uuid)
				if entry is None:
					entry = self._user_info(bs.user)
					entry['clients'] = []
					users[bs.user.uuid] = entry
				entry['clients'].append(bs.client.ToJSON(bs.client))
			items = list(users.values())
			key = 'users'
		else:
			items = [_session_info(bs) for bs in matched]
			key = 'sessions'
		total = len(items)
		items = items[offset:offset + limit] if limit else items[offset:]
		self.send_payload('LSS', trid, { 'count': total, key: items })
	
	def _m_gts(self, trid: str, data: Dict[str, Any]) -> None:
		target = self._find_session(_req_str(data, 'id'))
		info = _session_info(target)
		info.update(self._user_info(target.user))
		self.send_payload('GTS', trid, info)
	
	def _m_kls(self, trid: str, data: Dict[str, Any]) -> None:
		if data.get('id'):
			sess_id = str(data['id'])
			targets = [self._find_session(sess_id)]
			for target in targets:
				target.close(sess_id=sess_id)
		elif data.get('uuid') or data.get('email') or data.get('username'):
			targets = list(self.backend.util_get_sessions_by_user(self._user_from(data)))
			for target in targets:
				target.close()
		else:
			raise INSFail(Err.TooFewArguments, 'id or uuid is required')
		self.send_payload('KLS', trid, { 'killed': len(targets) })
		INSCtrl.broadcast('session.killed', { 'count': len(targets) }, exclude = self)
	
	def _m_bfd(self, trid: str, data: Dict[str, Any]) -> None:
		backend = self.backend
		action = str(data.get('action') or 'FEED').upper()
		try:
			count = min(100, max(1, int(data.get('count') or 20)))
			before_id = (int(data['before']) if data.get('before') is not None else None)
			after_id = (int(data['after']) if data.get('after') is not None else None)
			types = [_activity_type(t) for t in (data.get('types') or [])]
		except (ValueError, TypeError, KeyError):
			raise INSFail(Err.InvalidArgument, 'invalid count, cursor or type')
		
		if action == 'FEED':
			user = self._user_from(data)
			if not beacon_enabled(user):
				raise INSFail(Err.BeaconDisabled)
			viewer = user
			detail = backend._load_detail(user)
			publishers = [user] + [
				ctc.head for ctc in detail.contacts.values() if ctc.lists & ContactList.FL and not ctc.lists & ContactList.BL
			]
			activities = backend.user_service.get_activities(
				[head.uuid for head in publishers], count, announcements = bool(data.get('announcements', True)),
				before_id = before_id, after_id = after_id, types = types or None,
			)
		elif action == 'USER':
			target = self._user_from(data)
			viewer = (self._user_from({ 'uuid': data['viewer'] }) if data.get('viewer') else None)
			if viewer is not None and not beacon_enabled(viewer):
				raise INSFail(Err.BeaconDisabled)
			if not self._can_view_activity(viewer, target):
				raise INSFail(Err.ActivityNotPermitted)
			activities = backend.user_service.get_activities(
				[target.uuid], count, before_id = before_id, after_id = after_id, types = types or None,
			)
		elif action == 'ANNOUNCEMENTS':
			viewer = (self._user_from({ 'uuid': data['viewer'] }) if data.get('viewer') else None)
			activities = backend.user_service.get_activities([], count, announcements = True, before_id = before_id, after_id = after_id)
		elif action == 'GET':
			try:
				activity = backend.user_service.get_activity(int(data.get('id')))
			except (ValueError, TypeError):
				raise INSFail(Err.InvalidArgument, 'id must be a number')
			if activity is None:
				raise INSFail(Err.ActivityDoesNotExist)
			if activity.user is not None:
				viewer = (self._user_from({ 'uuid': data['viewer'] }) if data.get('viewer') else None)
				if not self._can_view_activity(viewer, activity.user):
					raise INSFail(Err.ActivityNotPermitted)
			self.send_payload('BFD', trid, self._social([activity], viewer)[0])
			return
		else:
			raise INSFail(Err.InvalidArgument, 'unknown activity action')
		
		self.send_payload('BFD', trid, {
			'activities': self._social(activities, viewer),
			'more': len(activities) >= count,
		})
	
	def _social(self, activities: List[Activity], viewer: User | None) -> List[Dict[str, Any]]:
		service = self.backend.user_service
		ids = [activity.id for activity in activities]
		reactions = service.get_reactions(ids)
		comments = service.get_comments(ids)
		result = []
		for activity in activities:
			info = _activity_info(activity)
			info['reactions'] = []
			for name, uuids in reactions.get(activity.id, {}).items():
				people = [u for u in (self._beacon_user(uuid) for uuid in uuids) if u is not None]
				if people:
					info['reactions'].append({
						'name': name, 'count': len(people), 'mine': viewer is not None and any(u.uuid == viewer.uuid for u in people),
						'users': [u.username for u in people[:8]],
					})
			shown = []
			for comment_id, uuid, text, date in comments.get(activity.id, []):
				author = self._beacon_user(uuid)
				if author is None:
					continue
				shown.append({
					'id': comment_id, 'text': text, 'date': _iso(date), 'user': _user_brief(author),
					'can_delete': viewer is not None and (author.uuid == viewer.uuid or (activity.user is not None and activity.user.uuid == viewer.uuid)),
				})
			info['comment_count'] = len(shown)
			info['comments'] = shown[-50:]
			info['can_comment'] = activity.user is not None
			result.append(info)
		return result
	
	def _beacon_user(self, uuid: str) -> User | None:
		user = self.backend._load_user_record(uuid)
		return (user if user is not None and beacon_enabled(user) else None)
	
	def _visible_activity(self, data: Dict[str, Any], viewer: User) -> Activity:
		try:
			activity = self.backend.user_service.get_activity(int(data.get('id')))
		except (ValueError, TypeError):
			raise INSFail(Err.InvalidArgument, 'id must be a number')
		if activity is None or (activity.user is not None and not beacon_enabled(activity.user)):
			raise INSFail(Err.ActivityDoesNotExist)
		if activity.user is not None and not self._can_view_activity(viewer, activity.user):
			raise INSFail(Err.ActivityNotPermitted)
		return activity
	
	def _m_bdl(self, trid: str, data: Dict[str, Any]) -> None:
		try:
			activity_id = int(data.get('id'))
		except (ValueError, TypeError):
			raise INSFail(Err.InvalidArgument, 'id must be a number')
		user = (self._user_from(data) if data.get('uuid') or data.get('email') or data.get('username') else None)
		if not self.backend.user_service.delete_activity(activity_id, user.uuid if user is not None else None):
			raise INSFail(Err.ActivityDoesNotExist)
		if user is not None:
			self.backend.notify_whats_new(user)
		self.send_payload('BDL', trid, { 'deleted': activity_id })
		INSCtrl.broadcast('activity', { 'deleted': activity_id, 'uuid': user.uuid if user is not None else None }, exclude = self)
	
	def _m_brx(self, trid: str, data: Dict[str, Any]) -> None:
		user = self._user_from(data)
		if not beacon_enabled(user):
			raise INSFail(Err.BeaconDisabled)
		name = str(data.get('reaction') or '').strip().lower()
		if name not in REACTIONS:
			raise INSFail(Err.ReactionInvalid, 'reaction must be a Twemoji code point sequence, like 1f44d')
		activity = self._visible_activity(data, user)
		now_set = self.backend.user_service.toggle_reaction(activity.id, user.uuid, name)
		info = self._social([activity], user)[0]
		self.send_payload('BRX', trid, { 'id': activity.id, 'reaction': name, 'set': now_set, 'reactions': info['reactions'] })
		INSCtrl.broadcast('activity', { 'id': activity.id, 'reaction': name }, exclude = self)
	
	def _m_bcm(self, trid: str, data: Dict[str, Any]) -> None:
		user = self._user_from(data)
		if not beacon_enabled(user):
			raise INSFail(Err.BeaconDisabled)
		action = str(data.get('action') or 'ADD').upper()
		service = self.backend.user_service
		if action == 'DEL':
			try:
				comment_id = int(data.get('comment'))
			except (ValueError, TypeError):
				raise INSFail(Err.InvalidArgument, 'comment must be a number')
			if not service.delete_comment(comment_id, user.uuid):
				raise INSFail(Err.CommentDoesNotExist)
			self.send_payload('BCM', trid, { 'deleted': comment_id })
			return
		if action != 'ADD':
			raise INSFail(Err.InvalidArgument, 'action must be ADD or DEL')
		activity = self._visible_activity(data, user)
		if activity.user is None:
			raise INSFail(Err.ActivityNotPermitted, 'announcements only take reactions')
		text = ' '.join(str(data.get('text') or '').split())
		if not text or len(text) > 255:
			raise INSFail(Err.InvalidArgument, 'comments are 1 to 255 characters')
		comment_id = service.add_comment(activity.id, user.uuid, text)
		info = self._social([activity], user)[0]
		self.send_payload('BCM', trid, { 'id': comment_id, 'activity': activity.id, 'comments': info['comments'], 'comment_count': info['comment_count'] })
		INSCtrl.broadcast('activity', { 'id': activity.id, 'comment': comment_id }, exclude = self)
	
	def _contact_pair(self, data: Dict[str, Any]) -> Tuple[User, User]:
		user = self._user_from(data)
		if not data.get('target'):
			raise INSFail(Err.TooFewArguments, 'target is required')
		return user, self._user_from({ 'uuid': data['target'] })
	
	def _m_cta(self, trid: str, data: Dict[str, Any]) -> None:
		user, target = self._contact_pair(data)
		if user.uuid == target.uuid:
			raise INSFail(Err.ContactInvalid, 'you cannot add yourself')
		group_id = data.get('group')
		if group_id is not None and (not isinstance(group_id, str) or not group_id or len(group_id) > 64):
			raise INSFail(Err.InvalidArgument, 'group must be a group ID')
		new_group = data.get('new_group')
		if new_group is not None:
			if group_id is not None:
				raise INSFail(Err.InvalidArgument, 'group and new_group cannot both be given')
			new_group = _group_name(new_group)
		try:
			added, group = self.backend.util_add_contact(user, target.uuid, group_id = group_id, new_group = new_group)
		except error.ContactListIsFull:
			raise INSFail(Err.ContactInvalid, 'contact list is full')
		except error.GroupDoesNotExist:
			raise INSFail(Err.GroupDoesNotExist, 'no such contact group')
		except error.GroupAlreadyExists:
			raise INSFail(Err.GroupNameInvalid, 'you already have a group with that name')
		except error.GroupNameTooLong:
			raise INSFail(Err.GroupNameInvalid, 'that group name is too long')
		self.send_payload('CTA', trid, {
			'added': added, 'grouped': group is not None, 'group': ({ 'id': group.id, 'name': group.name } if group else None),
			'state': self.backend.util_contact_state(user, target),
		})

	def _m_ctq(self, trid: str, data: Dict[str, Any]) -> None:
		if data.get('targets') is not None:
			user = self._user_from(data)
			targets = data['targets']
			if not isinstance(targets, list) or len(targets) > 500 or not all(isinstance(t, str) for t in targets):
				raise INSFail(Err.InvalidArgument, 'targets must be a list of at most 500 UUIDs')
			self.send_payload('CTQ', trid, { 'states': self.backend.util_contact_states(user, targets) })
			return
		user, target = self._contact_pair(data)
		self.send_payload('CTQ', trid, { 'state': self.backend.util_contact_state(user, target) })

	def _m_grp(self, trid: str, data: Dict[str, Any]) -> None:
		user = self._user_from(data)
		action = str(data.get('action') or 'LIST').upper()
		created = None
		if action == 'ADD':
			try:
				created = self.backend.util_add_group(user, _group_name(data.get('name')))
			except error.GroupAlreadyExists:
				raise INSFail(Err.GroupNameInvalid, 'you already have a group with that name')
			except error.GroupNameTooLong:
				raise INSFail(Err.GroupNameInvalid, 'that group name is too long')
		elif action != 'LIST':
			raise INSFail(Err.InvalidArgument, 'action must be LIST or ADD')
		reply = { 'groups': [
			{ 'id': group.id, 'uuid': group.uuid, 'name': group.name, 'favorite': group.is_favorite }
			for group in self.backend.util_contact_groups(user)
		] } # type: Dict[str, Any]
		if created is not None:
			reply['created'] = { 'id': created.id, 'uuid': created.uuid, 'name': created.name, 'favorite': created.is_favorite }
		self.send_payload('GRP', trid, reply)
	
	def _m_prf(self, trid: str, data: Dict[str, Any]) -> None:
		user = self._user_from(data)
		changes = data.get('set') or {}
		if not isinstance(changes, dict) or any(key not in PREFS or not isinstance(value, bool) for key, value in changes.items()):
			raise INSFail(Err.InvalidArgument, 'set takes ' + ', '.join(PREFS) + ' as booleans')
		if changes.get('beacon') and not user.account_verified:
			raise INSFail(Err.EmailNotVerified, 'verify your e-mail address to use CrossTalk Beacon', field = 'beacon')
		if changes:
			with db.Session() as sess:
				row = sess.query(db.User).filter_by(uuid=user.uuid).one_or_none()
				if row is None:
					raise INSFail(Err.UserNotInDB)
				stored = dict(row.settings or {})
				for key, value in changes.items():
					for legacy in LEGACY_PREFS.get(key, ()):
						stored.pop(legacy, None)
					if value:
						stored.pop(PREFS[key], None)
					else:
						stored[PREFS[key]] = True
				row.settings = stored
				flag_modified(row, 'settings')
			if user.settings is None:
				user.settings = {}
			for key, value in changes.items():
				for legacy in LEGACY_PREFS.get(key, ()):
					user.settings.pop(legacy, None)
				if value:
					user.settings.pop(PREFS[key], None)
				else:
					user.settings[PREFS[key]] = True
			INSCtrl.broadcast('user.updated', { 'uuid': user.uuid, 'fields': ['prefs.' + key for key in changes] }, exclude = self)
		self.send_payload('PRF', trid, _prefs(user))
	
	def _can_view_activity(self, viewer: User | None, target: User) -> bool:
		if viewer is None:
			return False
		if viewer.uuid == target.uuid:
			return True
		ctc = self.backend._load_detail(viewer).contacts.get(target.uuid)
		if ctc is None or not ctc.lists & ContactList.FL or ctc.lists & ContactList.BL:
			return False
		ctc_rev = self.backend._load_detail(target).contacts.get(viewer.uuid)
		if ctc_rev is not None and ctc_rev.lists & ContactList.BL:
			return False
		return True
	
	def _m_bst(self, trid: str, data: Dict[str, Any]) -> None:
		backend = self.backend
		user = self._user_from(data)
		message = ' '.join(str(data.get('message') or '').split())
		if len(message) > 255:
			raise INSFail(Err.InvalidArgument, 'message is longer than 255 characters')
		activity_added = backend.user_service.save_single_roaming(user, { 'message': message })
		sessions = backend.util_get_sessions_by_user(user)
		if sessions and message != user.status.message:
			sessions[0].me_update({ 'message': message, 'notify_self': True })
		if activity_added:
			backend.notify_whats_new(user)
		self.send_payload('BST', trid, { 'uuid': user.uuid, 'activity': activity_added })
		if activity_added:
			INSCtrl.broadcast('activity', { 'uuid': user.uuid, 'type': ActivityType.StatusMessage.name }, exclude = self)
	
	async def _m_bph(self, trid: str, data: Dict[str, Any]) -> None:
		backend = self.backend
		user = self._user_from(data)
		if not beacon_enabled(user):
			raise INSFail(Err.BeaconDisabled)
		title = str(data.get('title') or '').strip()
		summary = str(data.get('summary') or '').strip()
		if len(title) > 100 or len(summary) > 255:
			raise INSFail(Err.InvalidArgument, 'title or summary too long')
		try:
			img_data = base64.b64decode(str(data.get('data') or ''), validate = True)
		except ValueError:
			raise INSFail(Err.ImageInvalid)
		if not img_data:
			raise INSFail(Err.TooFewArguments, 'data is required')
		if len(img_data) > PHOTO_MAX_SIZE:
			raise INSFail(Err.PayloadTooLarge)
		ext = get_img_type(img_data)
		if ext is None:
			raise INSFail(Err.ImageInvalid)
		name = await backend.loop.run_in_executor(None, store_photo_file, user.uuid, img_data, ext)
		media_url = 'https://{}/photos/{}/{}'.format(settings.USERSTORAGE_HOST, user.uuid, name)
		activity_added = backend.user_service.add_activity(user, ActivityType.Photo, title = title, text = summary, url = media_url)
		if activity_added:
			backend.notify_whats_new(user)
			INSCtrl.broadcast('activity', { 'uuid': user.uuid, 'type': ActivityType.Photo.name }, exclude = self)
		self.send_payload('BPH', trid, { 'url': media_url, 'activity': activity_added })
	
	def _user_from(self, data: Dict[str, Any]) -> User:
		backend = self.backend
		uuid = data.get('uuid')
		if not uuid and data.get('email'):
			uuid = backend.util_get_uuid_from_email(str(data['email']))
		elif not uuid and data.get('username'):
			uuid = backend.util_get_uuid_from_username(str(data['username']))
		elif not uuid:
			raise INSFail(Err.TooFewArguments, 'uuid is required')
		user = (backend._load_user_record(str(uuid)) if uuid else None)
		if user is None:
			raise INSFail(Err.UserNotInDB)
		return user
	
	def _user_info(self, user: User, *, full: bool = False) -> Dict[str, Any]:
		sessions = self.backend.util_get_sessions_by_user(user)
		substatus = user.status.substatus
		info = {
			'uuid': user.uuid, 'username': user.username, 'email': user.email, 'uin': user.uin,
			'status': substatus.name, 'online': bool(sessions) and not substatus.is_offlineish(), 'sessions': len(sessions),
		} # type: Dict[str, Any]
		for trait in USER_TRAITS:
			info[trait] = getattr(user, trait, None)
		info.update(_prefs(user))
		if full:
			info.update({
				'name': user.status.name, 'message': user.status.message, 'avatar': getattr(user, 'avatar', None),
				'date_created': _iso(user.date_created), 'date_login': _iso(user.date_login),
			})
		return info
	
	def _find_session(self, sess_id: str) -> BackendSession:
		for bs in self.backend._sc.iter_sessions():
			if str(id(bs)) == sess_id:
				return bs
		raise INSFail(Err.SessionDoesNotExist)
	
	#async def _ping_conn(self) -> None:
	#	while True:
	#		await asyncio.sleep(60)
	#		if self.closed or not self.alive:
	#			if not self.alive:
	#				self.close()
	#			break
	#		self.alive = False
	#		self.current_challenge = hash.gen_salt()
	#		self.send_reply('PING', ':{}'.format(self.current_challenge))
	
	async def _watchdog(self) -> None:
		while not self.closed:
			await asyncio.sleep(1)
			now = time.monotonic()
			if not self.authenticated:
				if now - self.connected_at > settings.INS_AUTH_TIMEOUT:
					self.logger.info('InterService link did not authenticate in time')
					self.close('TMO')
					return
				continue
			if now - self.last_activity > settings.INS_IDLE_TIMEOUT:
				self.logger.info(f'InterService link {self.identifier} idle for too long')
				self.close('TMO')
				return
			if self.current_challenge is not None:
				if now - self.challenge_sent_at > settings.INS_CHALLENGE_TIMEOUT:
					self.logger.info(f'InterService link {self.identifier} did not answer its challenge')
					self.send_numeric(Err.ChallengeFailed)
					self.close('CHL')
					return
			elif settings.INS_CHALLENGE_INTERVAL > 0 and now >= self.next_challenge_at:
				self.current_challenge = base64.b64encode(secrets.token_bytes(32)).decode('ascii')
				self.challenge_sent_at = now
				self.send_reply('CHK', '0', self.current_challenge)
	
	def data_received(self, transport: asyncio.BaseTransport, data: bytes) -> None:
		self.peername = transport.get_extra_info('peername')
		if self.closed: return
		self.last_activity = time.monotonic()
		try:
			chunks = self.channel.receive(data)
		except INSCryptoError as ex:
			self.logger.info(f'Dropping InterService link from {self.peername}: {ex}')
			self.close()
			return
		for chunk in chunks:
			try:
				for m, payload in self.reader.data_received(chunk):
					self._dispatch(m, payload)
					if self.closed: return
			except INSProtocolError as ex:
				self.logger.info(f'InterService protocol error from {self.identifier or self.peername}: {ex}')
				self.send_numeric(Err.PayloadTooLarge if ex.too_large else Err.InvalidArgument)
				self.close()
				return
	
	def _dispatch(self, m: List[str], payload: Optional[bytes]) -> None:
		cmd = m[0].upper()
		if cmd == 'HBT':
			self._m_hbt()
			return
		if cmd == 'END':
			self._m_end()
			return
		trid = (m[1] if len(m) > 1 else '0')
		if not trid.isdigit():
			self.send_numeric(Err.InvalidArgument)
			return
		if not self.authenticated and cmd not in PRE_AUTH_COMMANDS:
			self.send_numeric(Err.NotAuthenticated, trid)
			self.close()
			return
		if cmd not in JSON_COMMANDS and cmd not in LINE_COMMANDS:
			self.send_numeric(Err.UnknownCommand, trid)
			return
		f = getattr(self, '_m_{}'.format(cmd.lower()))
		try:
			if cmd in JSON_COMMANDS:
				result = f(trid, _decode_payload(payload))
			else:
				result = f(trid, *m[2:])
			if asyncio.iscoroutine(result):
				task = self.backend.loop.create_task(self._run_async(trid, result))
				self.tasks.add(task)
				task.add_done_callback(self.tasks.discard)
		except INSFail as ex:
			self.send_numeric(ex.code, trid, ex.detail or None)
		except Exception as ex:
			traceback.print_exc()
			self.logger.error(ex)
			self.send_numeric(Err.ServerUnknownError, trid)
	
	async def _run_async(self, trid: str, coro: Coroutine[Any, Any, None]) -> None:
		try:
			await coro
		except INSFail as ex:
			self.send_numeric(ex.code, trid, ex.detail or None)
		except asyncio.CancelledError:
			raise
		except Exception as ex:
			traceback.print_exc()
			self.logger.error(ex)
			self.send_numeric(Err.ServerUnknownError, trid)
	
	@classmethod
	def listeners(cls, event: str) -> List['INSCtrl']:
		return [link for link in cls._links.values() if not link.closed and (event in link.subscriptions or '*' in link.subscriptions)]
	
	@classmethod
	def broadcast(cls, event: str, data: Dict[str, Any], *, exclude: Optional['INSCtrl'] = None) -> None:
		for link in list(cls._links.values()):
			if link is exclude or link.closed:
				continue
			if event not in link.subscriptions and '*' not in link.subscriptions:
				continue
			link.send_payload('EVT', '0', { 'event': event, **data })
	
	def send_numeric(self, n: int, trid: str = '0', detail: Optional[Dict[str, Any]] = None) -> None:
		self.send_payload('{:03}'.format(n), trid, detail)
	
	def send_reply(self, *m: str) -> None:
		self.writer.write(m)
		transport = self.transport
		if transport is not None:
			transport.write(self.flush())
	
	def send_payload(self, cmd: str, trid: str, obj: Any) -> None:
		payload = (b'' if obj is None else json.dumps(obj, separators = (',', ':'), default = str).encode('utf-8'))
		self.writer.write_payload((cmd, trid), payload)
		if settings.DEBUG_FULL:
			print(payload)
		transport = self.transport
		if transport is not None:
			transport.write(self.flush())
	
	def flush(self) -> bytes:
		data = self.writer.flush()
		if data:
			try:
				self.channel.send(data)
			except INSCryptoError:
				pass
		return self.channel.drain()
	
	def close(self, reason: Optional[str] = None) -> None:
		if self.closed: return
		if reason is not None:
			self.send_reply('END', reason)
		self.closed = True
		#if self.alive_task is not None and not self.alive_task.cancelled:
		#	self.alive_task.cancel()
		if self.watchdog is not None:
			self.watchdog.cancel()
		for task in list(self.tasks):
			task.cancel()
		if INSCtrl._links.pop(self.link_id, None) is not None:
			INSCtrl.broadcast('link', { 'state': 'down', 'identifier': self.identifier, 'link': self.link_id })
		if self.authenticated:
			self.backend._linked = bool(INSCtrl._links)
		raw_transport = self.raw_transport
		if raw_transport is not None:
			try:
				raw_transport.write(self.flush())
			except Exception:
				pass
		if self.close_callback:
			self.close_callback()

def _req_str(data: Dict[str, Any], key: str) -> str:
	value = data.get(key)
	if value is None or value == '':
		raise INSFail(Err.TooFewArguments, f'{key} is required')
	if not isinstance(value, (str, int)):
		raise INSFail(Err.InvalidArgument, f'{key} must be a string')
	return str(value)

def _client_flags(data: Dict[str, Any]) -> List[str]:
	clients = data.get('clients') or []
	if not isinstance(clients, list):
		raise INSFail(Err.InvalidArgument, 'clients must be a list')
	return [str(c).lower() for c in clients]

def _value_to_str(value: Any) -> str:
	if isinstance(value, bool):
		return 'true' if value else 'false'
	if value is None:
		return ''
	if isinstance(value, (list, dict)):
		return json.dumps(value, separators = (',', ':'))
	return str(value)

def _decode_payload(payload: Optional[bytes]) -> Dict[str, Any]:
	if not payload:
		return {}
	try:
		data = json.loads(payload.decode('utf-8'))
	except (UnicodeDecodeError, json.JSONDecodeError):
		raise INSFail(Err.InvalidArgument, 'payload is not JSON')
	if not isinstance(data, dict):
		raise INSFail(Err.InvalidArgument, 'payload must be a JSON object')
	return data

def _iso(dt: Optional[datetime]) -> Optional[str]:
	if dt is None:
		return None
	return dt.replace(microsecond = 0).isoformat() + ('Z' if dt.tzinfo is None else '')

def _suspension(row: db.User) -> Dict[str, Optional[str]]:
	days = getattr(settings, 'SUSPENDED_ACCOUNT_DAYS', None)
	deleted_at: datetime | None = None
	if days is not None:
		deleted_at = row.suspended_at + timedelta(days = int(days)) if row.suspended_at else datetime.utcnow()
	return { 'suspended_at': _iso(row.suspended_at), 'deleted_at': _iso(deleted_at) }

def _enum_int(value: Any) -> Any:
	if isinstance(value, Enum):
		return value.value if isinstance(value.value, int) else value.name
	return value

def _activity_type(value: Any) -> ActivityType:
	if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
		return ActivityType(int(value))
	return ActivityType[str(value)]

def _activity_info(activity: Activity) -> Dict[str, Any]:
	user = activity.user
	return {
		'id': activity.id, 'type': activity.type.name, 'title': activity.title, 'text': activity.text, 'url': activity.url,
		'date': _iso(activity.date_created),
		'user': None if user is None else _user_brief(user),
	}

def _services(backend: Backend) -> List[Dict[str, Any]]:
	services: dict[str, list[int]] = {}
	for runner in backend._runners:
		ports = services.setdefault(runner.service, [])
		if runner.port not in ports:
			ports.append(runner.port)
	return [{ 'name': name, 'ports': sorted(ports) } for name, ports in services.items()]

def _user_brief(user: User) -> Dict[str, Any]:
	return {
		'uuid': user.uuid, 'username': user.username, 'name': user.status.name, 'avatar': getattr(user, 'avatar', None),
		'show_in_dir': bool(getattr(user, 'show_in_dir', False)),
	}

def _prefs(user: User) -> Dict[str, bool]:
	return { 'beacon': beacon_enabled(user), 'dir_online': directory_online_visible(user) }

def _circle_info(circle: Circle, *, members: bool, backend: Optional[Backend] = None) -> Dict[str, Any]:
	info = {
		'chat_id': circle.chat_id, 'name': circle.name, 'owner_uuid': circle.owner_uuid, 'owner_friendly': circle.owner_friendly,
		'membership_access': circle.membership_access, 'members_count': len(circle.memberships),
	} # type: Dict[str, Any]
	if members:
		in_chat: set[str] = set()
		chat = backend.chat_get('persistent', circle.chat_id) if backend is not None else None
		if chat is not None:
			in_chat = { cs.user.uuid for cs in chat.get_roster() }
		info['members'] = [
			{
				'uuid': uuid, 'role': _enum_int(getattr(m, 'role', None)), 'state': _enum_int(getattr(m, 'state', None)),
				'username': m.head.username, 'email': m.head.email, 'name': m.head.status.name,
				'in_chat': uuid in in_chat,
				'online': backend is not None and bool(backend.util_get_sessions_by_user(m.head)) and not m.head.status.substatus.is_offlineish(),
				'inviter_email': m.inviter_email, 'invite_message': m.invite_message,
			}
			for uuid, m in circle.memberships.items()
		]
	return info

def _group_name(value: Any) -> str:
	name = ' '.join(str(value or '').split())
	if not name:
		raise INSFail(Err.TooFewArguments, 'a group name is required')
	if name.lower() in ('(no group)', 'no group'):
		raise INSFail(Err.GroupNameInvalid, 'that group name is reserved')
	return name

def _session_info(bs: BackendSession) -> Dict[str, Any]:
	user = bs.user
	return {
		'id': str(id(bs)), 'uuid': user.uuid, 'username': user.username, 'email': user.email, 'uin': user.uin,
		'client': bs.client.ToJSON(bs.client), 'status': user.status.substatus.name,
		'visible': not user.status.substatus.is_offlineish(), 'chat_enabled': bs.chat_enabled,
	}

def _match(actual: Any, expected: Any) -> bool:
	if isinstance(expected, list):
		return any(_match(actual, e) for e in expected)
	if isinstance(actual, bool) or isinstance(expected, bool):
		return bool(actual) == (expected if isinstance(expected, bool) else str(expected).lower() in ('1', 'true', 'yes', 'on'))
	if isinstance(actual, str) or isinstance(expected, str):
		return str(actual).lower() == str(expected).lower()
	return actual == expected

def _session_matches(bs: BackendSession, flt: Dict[str, Any]) -> bool:
	user = bs.user
	for key, expected in flt.items():
		if key in USER_TRAITS or key in ('uuid', 'email', 'username', 'uin'):
			actual = getattr(user, key, None)
		elif key in ('program', 'version', 'via'):
			actual = getattr(bs.client, key)
		elif key == 'status':
			actual = user.status.substatus.name
		elif key == 'visible':
			actual = not user.status.substatus.is_offlineish()
		elif key == 'beacon':
			actual = beacon_enabled(user)
		elif key == 'dir_online':
			actual = directory_online_visible(user)
		elif key == 'chat_enabled':
			actual = bs.chat_enabled
		elif key == 'id':
			actual = str(id(bs))
		else:
			raise INSFail(Err.InvalidArgument, f'unknown filter {key}')
		if not _match(actual, expected):
			return False
	return True

def _parse_value_for_column(col, value_str):
	py_type = getattr(col.type, 'python_type', None)
	if py_type is not None:
		try:
			if py_type is bool:
				v = value_str.strip().lower()
				return v in ('1', 'true', 'yes', 'on')
			if py_type is int:
				return int(value_str)
			if py_type is float:
				return float(value_str)
			return py_type(value_str)
		except Exception:
			return value_str
	tname = col.type.__class__.__name__.lower()
	if 'json' in tname or 'json' in str(col.type).lower():
		try:
			return json.loads(value_str)
		except Exception:
			return value_str
	if 'boolean' in tname:
		v = value_str.strip().lower()
		return v in ('1', 'true', 'yes', 'on')
	if 'integer' in tname or 'int' in tname:
		try:
			return int(value_str)
		except Exception:
			return value_str
	return value_str

def _set_passwords_and_prune(user_obj, pw: str, flags_list: List[str]):
	if 'oldmsn' in flags_list:
		user_obj.set_front_data('msn', 'pw_md5', hash.hasher_md5.encode(pw))
	else:
		if user_obj._front_data and 'msn' in user_obj._front_data:
			user_obj._front_data.pop('msn', None)
			flag_modified(user_obj, '_front_data')
	
	if 'yahoo' in flags_list:
		user_obj.set_front_data('ymsg', 'pw_md5_unsalted', hash.hasher_md5.encode(pw, salt=''))
		user_obj.set_front_data('ymsg', 'pw_md5crypt', hash.hasher_md5crypt.encode(pw, salt='$1$_2S43d5f'))
	else:
		if user_obj._front_data and 'ymsg' in user_obj._front_data:
			user_obj._front_data.pop('ymsg', None)
			flag_modified(user_obj, '_front_data')
	
	if 'oldaim' in flags_list:
		pw_md5_encoded = hash.hasher_md5.encode(pw, identifier='AOL Instant Messenger (SM)')
		pw_md5_salt = hash.hasher_md5.extract_salt(pw_md5_encoded)
		user_obj.set_front_data('aim', 'pw_md5', pw_md5_encoded)
		user_obj.set_front_data('aim', 'pw_md5_v5', hash.hasher_md5.encode_aim5(pw, salt=pw_md5_salt))
	else:
		if user_obj._front_data and 'aim' in user_obj._front_data:
			user_obj._front_data.pop('aim', None)
			flag_modified(user_obj, '_front_data')
	
	if 'msim' in flags_list:
		user_obj.set_front_data('msim', 'pw_sha1', hash.hasher_sha1.encode(pw))
	else:
		if user_obj._front_data and 'msim' in user_obj._front_data:
			user_obj._front_data.pop('msim', None)
			flag_modified(user_obj, '_front_data')
	
	user_obj.password = hash.hasher.encode(pw)

class INSReader:
	__slots__ = ('_logger', '_data', 'max_payload')
	
	_logger: misc.Logger
	_data: bytes
	max_payload: int
	
	def __init__(self, logger: misc.Logger) -> None:
		self._logger = logger
		self._data = b''
		self.max_payload = MAX_PAYLOAD_PRE_AUTH
	
	def data_received(self, data: bytes) -> Iterable[Tuple[List[str], Optional[bytes]]]:
		if self._data:
			self._data += data
		else:
			self._data = data
		while self._data:
			m = self._read()
			if m is None:
				break
			if not m[0]:
				continue
			if settings.DEBUG_FULL:
				self._logger.debug('[Client]', *m)
			else:
				self._logger.debug('[Client]', *m[0], *(('<{} bytes>'.format(len(m[1])),) if m[1] is not None else ()))
			yield m
	
	def _read(self) -> Optional[Tuple[List[str], Optional[bytes]]]:
		try:
			i = self._data.index(b'\r\n')
		except ValueError:
			if len(self._data) > MAX_LINE:
				raise INSProtocolError('command line too long')
			return None
		if i > MAX_LINE:
			raise INSProtocolError('command line too long')
		
		chunk = self._data[:i].decode('utf-8', errors='replace')
		end = i + 2
		
		if '\r' in chunk or '\n' in chunk:
			self._logger.info('Embedded CR/LF in incoming line; whack his peepee')
			chunk = chunk.replace('\r', ' ').replace('\n', ' ')
		
		toks = []
		while True:
			chunk = chunk.lstrip(' ')
			if not chunk:
				break
			
			if chunk[:1] == ':':
				toks.append(chunk[1:])
				break
			
			if chunk[0] in ('"', "'"):
				quote_char = chunk[0]
				j = 1
				escaped = False
				found = False
				while j < len(chunk):
					ch = chunk[j]
					if ch == '\\' and not escaped:
						escaped = True
						j += 1
						continue
					if ch == quote_char and not escaped:
						found = True
						break
					escaped = False
					j += 1
				if found:
					raw_tok = chunk[:j+1]
					chunk = chunk[j+1:]
					inner = raw_tok[1:-1]
					inner = inner.replace('\\' + quote_char, quote_char).replace('\\\\', '\\')
					if '\r' in inner or '\n' in inner:
						self._logger.info('Satanizing') # intentional
						inner = inner.replace('\r', ' ').replace('\n', ' ')
					toks.append(inner)
				else:
					inner = chunk[1:].replace('\\' + quote_char, quote_char).replace('\\\\', '\\')
					if '\r' in inner or '\n' in inner:
						self._logger.info('Satanizing but quotes')
						inner = inner.replace('\r', ' ').replace('\n', ' ')
					toks.append(inner)
					break
				continue
			
			k = chunk.find(' ')
			if k < 0:
				tok = chunk
				chunk = ''
			else:
				tok = chunk[:k]
				chunk = chunk[k+1:]
			if tok:
				if '\r' in tok or '\n' in tok:
					self._logger.info('Satanizing CR/LF from token')
					tok = tok.replace('\r', ' ').replace('\n', ' ')
				toks.append(tok)
			if not chunk:
				break
		
		if not toks:
			self._data = self._data[end:]
			return toks, None
		
		payload = None
		if toks[-1].startswith('#'):
			try:
				length = int(toks[-1][1:])
			except ValueError:
				raise INSProtocolError(f'{toks[0]} with a bad payload length')
			if length < 0 or length > self.max_payload:
				raise INSProtocolError(f'{toks[0]} payload of {length} bytes', too_large = True)
			if len(self._data) < end + length:
				return None
			payload = self._data[end:end + length]
			toks = toks[:-1]
			end += length
		self._data = self._data[end:]
		return toks, payload

class INSWriter:
	__slots__ = ('_logger', '_buf')
	
	_logger: misc.Logger
	_buf: io.BytesIO
	
	def __init__(self, logger: misc.Logger) -> None:
		self._logger = logger
		self._buf = io.BytesIO()
	
	def write(self, m: Iterable[Any]) -> None:
		safe_parts = []
		for part in m:
			s = str(part)
			if '\r' in s or '\n' in s:
				self._logger.info('Satanizing before sending')
				s = s.replace('\r', ' ').replace('\n', ' ')
			if ' ' in s or s.startswith(':') or any(ord(c) < 32 for c in s):
				escaped = s.replace('\\', '\\\\').replace('"', '\\"')
				s = f'"{escaped}"'
			safe_parts.append(s)
		self._logger.debug('[Server]', *m)
		self._buf.write(' '.join(safe_parts).encode('utf-8'))
		self._buf.write(b'\r\n')
	
	def write_payload(self, m: Iterable[Any], payload: bytes) -> None:
		self.write((*m, '#{}'.format(len(payload))))
		self._buf.write(payload)
	
	def flush(self) -> bytes:
		data = self._buf.getvalue()
		if data:
			self._buf = io.BytesIO()
		return data

# `1xx`: Generic codes; `2xx`: Circle codes; `3xx`: Server operations codes; `4xx`: User service status codes

class Err:
	AuthenticationFailed = 101
	NotAuthenticated = 102
	UnknownCommand = 103
	InvalidArgument = 104
	TooFewArguments = 105
	PayloadTooLarge = 106
	ProtocolVersionUnsupported = 107
	ChallengeFailed = 108
	AlreadyAuthenticated = 109
	CircleDoesNotExist = 200
	CircleRoleInvalid = 202
	CircleMemberInvalid = 203
	MemberAlreadyInCircle = 204
	CircleMemberIsPending = 205
	DoesntHaveSufficientPermissions = 206
	CantLeaveCircle = 207
	ServerUnknownError = 300
	SessionDoesNotExist = 301
	ServerInModeAlready = 310
	UsernameTaken = 410
	EmailTaken = 411
	UinTaken = 412
	RestrictedUseranme = 415
	RestrictedEmail = 416
	EmailNotVerified = 419
	TooManyCharactersUsername = 425
	TooManyCharactersEmail = 426
	UserCreationFailed = 427
	UserNotInDB = 428
	ActivityDoesNotExist = 501
	ActivityNotPermitted = 502
	ImageInvalid = 503
	BeaconDisabled = 504
	CommentDoesNotExist = 505
	ReactionInvalid = 506
	ContactInvalid = 430
	GroupDoesNotExist = 431
	GroupNameInvalid = 432


class StatusCode:
	CircleActionSuccessful = 201
