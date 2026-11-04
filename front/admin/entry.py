from datetime import datetime
from math import ceil
from typing import Any, Awaitable, Callable, Dict, List, Optional
import asyncio, os, secrets

import jinja2
from aiohttp import web

from core.alerts import AGENTS, MAX_BODY
from core.backend import Backend
from core.interservice.ctrl import ALERT_NETWORKS, INSCtrl
from core.interservice.local import LocalLink, LocalINSError
from core.interservice.registry import ClientRegistry
from util.misc import AIOHTTPRunner
import settings

from .auth import AdminAuth, COOKIE_NAME

TMPL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmpl')
PAGE_SIZE = 50
SECTIONS = [
	('/', 'overview', 'bi-grid-1x2-fill'),
	('/users', 'users', 'bi-people-fill'),
	('/sessions', 'sessions', 'bi-plug-fill'),
	('/circles', 'circles', 'bi-chat-square-dots-fill'),
	('/broadcast', 'broadcast', 'bi-megaphone-fill'),
	('/interservice', 'interservice', 'bi-diagram-3-fill'),
]
USER_FILTERS = [
	('online', 'signed in', 'online'),
	('suspended', 'suspended', 'suspended'),
	('unverified', 'unverified e-mail', '!account_verified'),
	('blocked', 'can\'t sign in', '!verified_to_login'),
	('admins', 'administrators', 'is_admin'),
	('testers', 'testers', 'is_tester'),
]
NETWORK_NAMES = { 'msn': 'MSN Messenger', 'ymsg': 'Yahoo! Messenger', 'aim': 'AIM', 'icq': 'ICQ', 'irc': 'IRC' }
PROGRAM_NAMES = { **NETWORK_NAMES, 'toc': 'AIM (TOC)', 'msim': 'MySpaceIM' }
ALERT_LANGUAGES = [
	(1033, 'English (United States)'), (2057, 'English (United Kingdom)'), (1031, 'German'), (1036, 'French (France)'),
	(3082, 'Spanish (Spain)'), (2058, 'Spanish (Mexico)'), (1040, 'Italian'), (1043, 'Dutch'), (1046, 'Portuguese (Brazil)'),
	(2070, 'Portuguese (Portugal)'), (1053, 'Swedish'), (1030, 'Danish'), (1044, 'Norwegian (Bokmål)'), (1035, 'Finnish'),
	(1045, 'Polish'), (1049, 'Russian'), (1055, 'Turkish'), (1032, 'Greek'), (1041, 'Japanese'), (1042, 'Korean'),
	(2052, 'Chinese (Simplified)'), (1028, 'Chinese (Traditional)'),
]
USER_FLAGS = [
	#('verified_to_login', 'Can sign in', 'Off blocks every client and the website until it\'s turned back on.'),
	('suspended', 'Suspended', 'Signs them out everywhere and keeps them out.'),
	('account_verified', 'E-mail verified', 'Their e-mail address is confirmed as theirs.'),
	('show_in_dir', 'Listed in the member directory', 'Other members can find them and see their profile.'),
	('alias_active', 'Username alias active', 'They sign in with username@crosstalk.im instead of their e-mail address.'),
	('is_tester', 'Tester', 'Sees experimental and unfinished features.'),
	('is_mvp', 'MVP', 'Shows the MVP badge where clients support it.'),
	('is_admin', 'Administrator', 'Can sign into this panel (with the admin key).'),
]
LEGACY_CLIENTS = [('oldmsn', 'MSN Messenger 1.0 - 4.7'), ('yahoo', 'Yahoo! Messenger'), ('oldaim', 'AOL Instant Messenger'), ('msim', 'MySpaceIM')]
ROLE_NAMES = { 1: 'owner', 2: 'administrator', 3: 'member', 4: 'invited' }

Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]

def register(loop: asyncio.AbstractEventLoop, backend: Backend, registry: Optional[ClientRegistry]) -> web.Application:
	app = create_app(backend, registry)
	backend.add_runner(AIOHTTPRunner(settings.ADMIN_HOST, settings.ADMIN_PORT, app, service = 'Admin'))
	if not AdminAuth.configured():
		print('[Admin] <Info> ADMIN_KEY is not set, so nobody can sign into the admin panel yet (see settings.py)')
	print(f'[Admin] <Info> Admin panel on http://{settings.ADMIN_HOST}:{settings.ADMIN_PORT}/')
	return app

def create_app(backend: Backend, registry: Optional[ClientRegistry]) -> web.Application:
	app = web.Application(middlewares = [_security_headers, _require_admin])
	app['backend'] = backend
	app['registry'] = registry
	app['auth'] = AdminAuth()
	env = jinja2.Environment(loader = jinja2.FileSystemLoader(TMPL_DIR), autoescape = jinja2.select_autoescape(default = True))
	env.globals.update(
		settings = settings, role_names = ROLE_NAMES, sections = SECTIONS, network_names = NETWORK_NAMES, program_names = PROGRAM_NAMES,
	)
	env.filters['when'] = _when
	env.filters['ago'] = _ago
	env.filters['until'] = _until
	app['jinja'] = env
	r = app.router
	r.add_get('/login', page_login)
	r.add_post('/login', page_login)
	r.add_post('/logout', action_logout)
	r.add_get('/', page_overview)
	r.add_get('/users', page_users)
	r.add_get('/users/{uuid}', page_user)
	r.add_post('/users/{uuid}', action_user)
	r.add_get('/sessions', page_sessions)
	r.add_post('/sessions', action_sessions)
	r.add_get('/circles', page_circles)
	r.add_get('/circles/{chat_id}', page_circle)
	r.add_post('/circles/{chat_id}', action_circle)
	r.add_get('/broadcast', page_broadcast)
	r.add_post('/broadcast', action_broadcast)
	r.add_get('/interservice', page_interservice)
	r.add_post('/interservice', action_interservice)
	return app

def _when(value: Any) -> str:
	if not value:
		return 'never'
	if isinstance(value, str):
		try:
			value = datetime.fromisoformat(value.rstrip('Z'))
		except ValueError:
			return value
	return '{} {}, {} {}'.format(value.strftime('%B'), value.day, value.year, value.strftime('%H:%M UTC'))

def _ago(value: Any) -> str:
	if not value:
		return 'never'
	if isinstance(value, str):
		try:
			value = datetime.fromisoformat(value.rstrip('Z'))
		except ValueError:
			return value
	seconds = int((datetime.utcnow() - value).total_seconds())
	if seconds < 60:
		return 'just now'
	for size, name in ((86400 * 365, 'year'), (86400 * 30, 'month'), (86400, 'day'), (3600, 'hour'), (60, 'minute')):
		if seconds >= size:
			n = seconds // size
			return '{} {}{} ago'.format(n, name, '' if n == 1 else 's')
	return 'just now'

def _until(value: Any) -> str:
	if not value:
		return 'never'
	if isinstance(value, str):
		try:
			value = datetime.fromisoformat(value.rstrip('Z'))
		except ValueError:
			return value
	seconds = int((value - datetime.utcnow()).total_seconds())
	if seconds <= 0:
		return 'at the next check'
	for size, name in ((86400, 'day'), (3600, 'hour'), (60, 'minute')):
		if seconds >= size:
			n = seconds // size
			return 'in {} {}{}'.format(n, name, '' if n == 1 else 's')
	return 'in under a minute'

def _peer(req: web.Request) -> str:
	return req.remote or ''

def _harden(headers: Any) -> None:
	headers['X-Frame-Options'] = 'DENY'
	headers['X-Content-Type-Options'] = 'nosniff'
	headers['Referrer-Policy'] = 'no-referrer'
	headers['Cache-Control'] = 'no-store'
	headers['Content-Security-Policy'] = (
		"default-src 'none'; img-src 'self' data: http: https:; style-src 'unsafe-inline' https://{0} https://cdn.jsdelivr.net https://fonts.googleapis.com; "
		"font-src https://{0} https://cdn.jsdelivr.net https://fonts.gstatic.com; script-src https://{0} https://code.jquery.com; "
		"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	).format(settings.STATIC_HOST)

@web.middleware
async def _security_headers(req: web.Request, handler: Handler) -> web.StreamResponse:
	try:
		resp = await handler(req)
	except web.HTTPException as ex:
		_harden(ex.headers)
		raise
	_harden(resp.headers)
	return resp

@web.middleware
async def _require_admin(req: web.Request, handler: Handler) -> web.StreamResponse:
	if req.path == '/login':
		return await handler(req)
	auth: AdminAuth = req.app['auth']
	session = auth.get(req.cookies.get(COOKIE_NAME))
	if session is None or not auth.still_admin(session):
		if session is not None:
			auth.sign_out(session.token)
		if req.method != 'GET':
			raise web.HTTPForbidden(text = 'Sign in again.')
		raise web.HTTPFound('/login?next={}'.format(req.path_qs if req.path != '/' else '/'))
	if req.method == 'POST':
		data = await req.post()
		if not AdminAuth.csrf_ok(session, data.get('csrf')):
			raise web.HTTPForbidden(text = 'That form expired. Go back, reload the page and try again.')
		req['form'] = data
	req['admin'] = session
	req['ins'] = LocalLink(req.app['backend'], session.username)
	return await handler(req)

def render(req: web.Request, tmpl: str, ctxt: Optional[Dict[str, Any]] = None, *, status: int = 200) -> web.Response:
	session: AdminSession | None = req.get('admin')
	backend = req.app['backend'] # type: Backend
	context = dict(ctxt or {})
	context.update(
		admin = session, csrf = session.csrf if session else '', flashes = session.take_flashes() if session else [],
		reveal = session.take_reveal() if session else None, path = req.path,
		nav = {
			'sessions': sum(1 for _ in backend._sc.iter_sessions()),
			'maintenance': bool(backend.maintenance_mode or backend.notify_maintenance),
		},
	)
	html = req.app['jinja'].get_template(tmpl).render(**context)
	return web.Response(text = html, content_type = 'text/html', status = status)

def back(req: web.Request, location: str, text: Optional[str] = None, kind: str = 'success') -> web.Response:
	if text:
		req['admin'].flash(text, kind)
	raise web.HTTPSeeOther(location)

async def ins(req: web.Request, cmd: str, data: Optional[Dict[str, Any]] = None) -> Any:
	link: LocalLink = req['ins']
	return await link.call(cmd, data)

def _error_text(ex: LocalINSError) -> str:
	return ex.message or 'InterService error {:03}'.format(ex.code)

async def page_login(req: web.Request) -> web.Response:
	auth: AdminAuth = req.app['auth']
	next_page = req.query.get('next', '/')
	if not next_page.startswith('/') or next_page.startswith('//'):
		next_page = '/'
	error = None
	login = ''
	if req.method == 'POST':
		data = await req.post()
		login = str(data.get('login', ''))[:254]
		if not auth.configured():
			error = 'The admin key isn\'t set up on this server yet. Put its SHA-256 hash in ADMIN_KEY and restart azul.'
		elif auth.throttled(_peer(req)):
			error = 'Too many attempts. Wait a few minutes and try again.'
		else:
			session = await auth.sign_in(_peer(req), login, str(data.get('password', '')), str(data.get('key', '')))
			if session is None:
				error = 'Those details aren\'t right, or that account can\'t use the admin panel.'
			else:
				resp = web.HTTPSeeOther(next_page)
				resp.set_cookie(
					COOKIE_NAME, session.token, httponly = True, samesite = 'Strict', path = '/',
					secure = bool(getattr(settings, 'ADMIN_COOKIE_SECURE', False)),
				)
				raise resp
	env = req.app['jinja']
	html = env.get_template('login.html').render(settings = settings, error = error, login = login, next = next_page, configured = auth.configured())
	return web.Response(text = html, content_type = 'text/html', status = 401 if error else 200)

async def action_logout(req: web.Request) -> web.Response:
	req.app['auth'].sign_out(req['admin'].token)
	resp = web.HTTPSeeOther('/login')
	resp.del_cookie(COOKIE_NAME, path = '/')
	raise resp

async def page_overview(req: web.Request) -> web.Response:
	info = await ins(req, 'INF')
	stats = await ins(req, 'STA')
	alerts = (await ins(req, 'ALR', { 'action': 'LIST' })).get('alerts') or []
	suspended = await ins(req, 'LSU', { 'trait': 'suspended', 'limit': 1 })
	registry: ClientRegistry | None = req.app['registry']
	clients = registry.clients() if registry is not None else []
	online = stats.get('online') or {}
	sessions = int(online.get('sessions') or 0)
	return render(req, 'overview.html', {
		'title': 'Overview', 'info': info, 'stats': stats,
		'clients_active': len([c for c in clients if not c.revoked]),
		'links': [link for link in info.get('links') or [] if link.get('link') != 'local'],
		'uptime': _duration(info.get('uptime')),
		'hourly': _hourly(stats.get('hourly') or []),
		'programs': [
			{ 'name': PROGRAM_NAMES.get(p.get('program'), p.get('program')), 'sessions': p.get('sessions', 0), 'pct': round(100 * p.get('sessions', 0) / sessions, 1) if sessions else 0 }
			for p in online.get('by_program') or []
		],
		'alerts': _alert_rows(alerts[:4]), 'alerts_count': len(alerts),
		'suspended': int(suspended.get('matched') or 0), 'suspended_days': getattr(settings, 'SUSPENDED_ACCOUNT_DAYS', None),
	})

def _hourly(hours: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	top = max([int(h.get('users_active') or 0) for h in hours] + [1])
	out = [] # type: List[Dict[str, Any]]
	for i, h in enumerate(hours):
		value = int(h.get('users_active') or 0)
		try:
			label = datetime.fromisoformat(str(h.get('hour') or '').rstrip('Z')).strftime('%H:00')
		except ValueError:
			label = ''
		out.append({ 'label': label, 'value': value, 'peak': int(h.get('peak') or 0), 'messages': int(h.get('messages_sent') or 0), 'pct': round(100 * value / top, 1), 'is_now': i == len(hours) - 1 })
	return out

def _duration(seconds: Any) -> str:
	try:
		seconds = int(seconds or 0)
	except (TypeError, ValueError):
		return '-'
	days, rest = divmod(seconds, 86400)
	hours, rest = divmod(rest, 3600)
	minutes = rest // 60
	parts = [] # type: List[str]
	if days:
		parts.append('{} day{}'.format(days, '' if days == 1 else 's'))
	if hours:
		parts.append('{} hour{}'.format(hours, '' if hours == 1 else 's'))
	if not days and minutes:
		parts.append('{} minute{}'.format(minutes, '' if minutes == 1 else 's'))
	return ', '.join(parts) or 'less than a minute'

async def page_users(req: web.Request) -> web.Response:
	query = req.query.get('q', '').strip()[:100]
	shown = req.query.get('show', '')
	trait = next((t for name, _, t in USER_FILTERS if name == shown), None)
	if trait is None:
		shown = ''
	try:
		page = max(1, int(req.query.get('page', 1)))
	except ValueError:
		page = 1
	result = await ins(req, 'LSU', { 'query': query, 'trait': trait, 'limit': PAGE_SIZE, 'offset': (page - 1) * PAGE_SIZE })
	matched = int(result.get('matched') or 0)
	return render(req, 'users.html', {
		'title': 'Users', 'q': query, 'show': shown, 'filters': USER_FILTERS, 'page': page, 'pages': max(1, ceil(matched / PAGE_SIZE)),
		'matched': matched, 'users': result.get('users') or [], 'total': result.get('total'), 'online': result.get('online'),
	})

async def _user_or_404(req: web.Request, uuid: str) -> Dict[str, Any]:
	try:
		return await ins(req, 'GTU', { 'uuid': uuid })
	except LocalINSError as ex:
		if ex.code == 428:
			raise web.HTTPNotFound(text = 'No such user.')
		raise

async def page_user(req: web.Request) -> web.Response:
	uuid = req.match_info['uuid']
	user = await _user_or_404(req, uuid)
	sessions = (await ins(req, 'LSS', { 'filter': { 'uuid': uuid } })).get('sessions') or []
	return render(req, 'user.html', {
		'title': user['username'], 'user': user, 'sessions': sessions, 'flags': USER_FLAGS, 'legacy_clients': LEGACY_CLIENTS,
		'reset_available': bool(INSCtrl.listeners('password.reset')),
		'email_available': bool(INSCtrl.listeners('alert.email')),
		'is_self': user['uuid'] == req['admin'].uuid,
		'suspended_days': getattr(settings, 'SUSPENDED_ACCOUNT_DAYS', None),
		'programs': sorted({ PROGRAM_NAMES.get((s.get('client') or {}).get('program'), '?') for s in sessions }),
	})

async def action_user(req: web.Request) -> web.Response:
	uuid = req.match_info['uuid']
	form = req['form']
	action = form.get('action')
	here = '/users/{}'.format(uuid)
	user = await _user_or_404(req, uuid)
	try:
		if action == 'flags':
			changes = {} # type: Dict[str, bool]
			for key, _, _ in USER_FLAGS:
				value = form.get(key) == 'on'
				if key == 'is_admin' and user['uuid'] == req['admin'].uuid and not value:
					return back(req, here, 'You can\'t take away your own admin rights. Ask another administrator.', 'danger')
				if bool(user.get(key)) != value:
					changes[key] = value
			if not changes:
				return back(req, here, 'Nothing changed.', 'info')
			await ins(req, 'EDU', { 'uuid': uuid, 'fields': changes })
			if changes.get('is_admin') is False or changes.get('suspended'):
				req.app['auth'].sign_out_user(uuid)
			return back(req, here, 'Saved {}.'.format(', '.join(label.lower() for key, label, _ in USER_FLAGS if key in changes)))
		if action == 'password':
			password = str(form.get('password', ''))
			if len(password) < 6:
				return back(req, here, 'Passwords need at least 6 characters.', 'danger')
			clients = [flag for flag, _ in LEGACY_CLIENTS if form.get('client_' + flag) == 'on']
			await ins(req, 'EDU', { 'uuid': uuid, 'fields': { 'password': password }, 'clients': clients })
			return back(req, here, 'Password changed. Their open sessions were signed out.')
		if action == 'temp-password':
			password = '-'.join(secrets.token_hex(3) for _ in range(3))
			await ins(req, 'EDU', { 'uuid': uuid, 'fields': { 'password': password }, 'clients': user.get('clients') or [] })
			req['admin'].reveal = { 'kind': 'password', 'value': password, 'for': user['username'] }
			return back(req, here)
		if action == 'reset-email':
			listeners = INSCtrl.listeners('password.reset')
			if not listeners:
				return back(req, here, 'No website is linked to send the e-mail right now.', 'danger')
			INSCtrl.broadcast('password.reset', { 'uuid': uuid, 'email': user['email'] })
			return back(req, here, 'Asked the website to e-mail a reset link to {}.'.format(user['email']))
		if action == 'kill':
			killed = (await ins(req, 'KLS', { 'id': str(form.get('session', '')) }))['killed']
			return back(req, here, 'Signed out {} session{}.'.format(killed, '' if killed == 1 else 's'))
		if action == 'kill-all':
			killed = (await ins(req, 'KLS', { 'uuid': uuid }))['killed']
			return back(req, here, 'Signed out {} session{}.'.format(killed, '' if killed == 1 else 's'))
		if action == 'alert':
			fields = _alert_fields(form)
			if not fields['rich'] and not fields['text']:
				return back(req, here, 'Write the alert first.', 'danger')
			result = await ins(req, 'ALR', { **fields, 'targets': [uuid] })
			return back(req, here, _alert_report(result))
		if action == 'delete':
			if str(form.get('confirm', '')).strip() != user['username']:
				return back(req, here, 'Type their username exactly to delete the account.', 'danger')
			if user['uuid'] == req['admin'].uuid:
				return back(req, here, 'You can\'t delete your own account from here.', 'danger')
			await ins(req, 'RMU', { 'uuid': uuid })
			req.app['auth'].sign_out_user(uuid)
			return back(req, '/users', 'Deleted {}.'.format(user['username']))
	except LocalINSError as ex:
		return back(req, here, _error_text(ex), 'danger')
	raise web.HTTPBadRequest(text = 'Unknown action.')

async def page_sessions(req: web.Request) -> web.Response:
	program = req.query.get('program', '')
	flt = { 'program': program } if program else {}
	result = await ins(req, 'LSS', { 'filter': flt })
	sessions = result.get('sessions') or []
	everything = (await ins(req, 'LSS', {})).get('sessions') or [] if program else sessions
	programs = sorted({ (s.get('client') or {}).get('program') or '?' for s in everything })
	return render(req, 'sessions.html', {
		'title': 'Sessions', 'sessions': sessions, 'program': program, 'programs': [(p, PROGRAM_NAMES.get(p, p)) for p in programs],
		'count': result.get('count', 0), 'total': len(everything),
	})

async def action_sessions(req: web.Request) -> web.Response:
	form = req['form']
	try:
		killed = (await ins(req, 'KLS', { 'id': str(form.get('session', '')) }))['killed']
	except LocalINSError as ex:
		return back(req, '/sessions', _error_text(ex), 'danger')
	return back(req, '/sessions' + ('?program=' + str(form.get('program')) if form.get('program') else ''), 'Signed out {} session{}.'.format(killed, '' if killed == 1 else 's'))

async def page_circles(req: web.Request) -> web.Response:
	circles = (await ins(req, 'CIR', { 'action': 'LIST' })).get('circles') or []
	circles.sort(key = lambda c: str(c.get('name') or '').lower())
	return render(req, 'circles.html', { 'title': 'Circles', 'circles': circles })

async def _circle_or_404(req: web.Request, chat_id: str) -> Dict[str, Any]:
	try:
		return await ins(req, 'CIR', { 'action': 'INFO', 'chat_id': chat_id })
	except LocalINSError as ex:
		if ex.code == 200:
			raise web.HTTPNotFound(text = 'No such circle.')
		raise

async def page_circle(req: web.Request) -> web.Response:
	circle = await _circle_or_404(req, req.match_info['chat_id'])
	members = [m for m in circle.get('members') or [] if m.get('state') not in (0, 4)]
	members.sort(key = lambda m: (m.get('role') or 9, str(m.get('username') or '').lower()))
	return render(req, 'circle.html', { 'title': circle['name'], 'circle': circle, 'members': members })

async def action_circle(req: web.Request) -> web.Response:
	chat_id = req.match_info['chat_id']
	circle = await _circle_or_404(req, chat_id)
	form = req['form']
	action = form.get('action')
	here = '/circles/{}'.format(chat_id)
	member = str(form.get('uuid', ''))
	try:
		if action == 'role':
			role = int(str(form.get('role', '0')))
			if role == 1:
				owner = next((m for m in circle.get('members') or [] if m.get('role') == 1 and m.get('state') == 3), None)
				await ins(req, 'CIR', { 'action': 'ROLE', 'chat_id': chat_id, 'uuid': member, 'role': 1, 'uuid_self': owner['uuid'] if owner else None })
				return back(req, here, 'Ownership moved.')
			await ins(req, 'CIR', { 'action': 'ROLE', 'chat_id': chat_id, 'uuid': member, 'role': role })
			return back(req, here, 'Role changed.')
		if action == 'remove':
			await ins(req, 'CIR', { 'action': 'REMOVE', 'chat_id': chat_id, 'uuid': member })
			return back(req, here, 'Removed from the circle.')
		if action == 'revoke':
			await ins(req, 'CIR', { 'action': 'REVOKE', 'chat_id': chat_id, 'uuid': member })
			return back(req, here, 'Invite withdrawn.')
		if action == 'delete':
			if str(form.get('confirm', '')).strip() != circle['name']:
				return back(req, here, 'Type the circle\'s name exactly to delete it.', 'danger')
			await ins(req, 'CIR', { 'action': 'DELETE', 'chat_id': chat_id })
			return back(req, '/circles', 'Deleted {}.'.format(circle['name']))
	except (ValueError, TypeError):
		return back(req, here, 'That isn\'t a role.', 'danger')
	except LocalINSError as ex:
		return back(req, here, _error_text(ex), 'danger')
	raise web.HTTPBadRequest(text = 'Unknown action.')

async def page_broadcast(req: web.Request) -> web.Response:
	info = await ins(req, 'INF')
	alerts = (await ins(req, 'ALR', { 'action': 'LIST' })).get('alerts') or []
	return render(req, 'broadcast.html', {
		'title': 'Broadcast', 'info': info, 'alerts': _alert_rows(alerts), 'languages': ALERT_LANGUAGES, 'agents': AGENTS,
		'networks': ALERT_NETWORKS, 'max_body': MAX_BODY, 'site_url': settings.ALERT_SITE_URL,
		'email_available': bool(INSCtrl.listeners('alert.email')),
	})

def _alert_fields(form: Any) -> Dict[str, Any]:
	message = str(form.get('message', '')).replace('\r\n', '\n').strip()
	align = str(form.get('align', 'left') or 'left')
	rich = message if message and (align != 'left' or '*' in message or '\\' in message) else ''
	plain = str(form.get('plain', '')).strip()
	kind = str(form.get('kind', 'bell') or 'bell')
	icon = str(form.get('icon', '')).strip() if kind == 'custom' else ''
	fields = {
		'text': plain if rich else message, 'rich': rich, 'align': align,
		'url': str(form.get('url', '')).strip(), 'subscr_url': str(form.get('subscr_url', '')).strip(),
		'kind': 'bell' if kind == 'custom' else kind, 'icon': icon,
		'lang': str(form.get('lang', '') or '1033'), 'priority': str(form.get('priority', '') or '1'),
		'message_id': str(form.get('message_id', '') or '0'), 'via': str(form.get('via', '')).strip() or None,
	} # type: Dict[str, Any]
	if form.get('networks_shown'):
		fields['networks'] = [n for n in ALERT_NETWORKS if form.get('network_' + n) == 'on']
	if form.get('email') == 'on':
		fields['email'] = True
		fields['email_text'] = str(form.get('email_text', '')).strip()
	return fields

def _alert_report(result: Dict[str, Any]) -> str:
	delivered = int(result.get('delivered') or 0)
	per_network = [(NETWORK_NAMES.get(n, n), c) for n, c in (result.get('networks') or {}).items() if c]
	text = 'Alert shown in {}'.format(_count(delivered, 'session'))
	if len(per_network) > 1:
		text += ' ({})'.format(', '.join('{} {}'.format(c, name) for name, c in per_network))
	elif per_network:
		text += ' of {}'.format(per_network[0][0])
	text += '.'
	skipped = int(result.get('skipped') or 0)
	if skipped:
		text += ' {} couldn\'t show it.'.format(_count(skipped, 'session').capitalize())
	emailed = int(result.get('emailed') or 0)
	if emailed:
		text += ' A copy was e-mailed to {}.'.format(_count(emailed, 'person', 'people'))
	return text

def _count(n: int, noun: str, plural: Optional[str] = None) -> str:
	return '{} {}'.format(n, noun if n == 1 else (plural or noun + 's'))

def _alert_rows(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	rows = []
	for alert in alerts:
		targets = alert.get('targets')
		shown = ['{} {}'.format(c, NETWORK_NAMES.get(n, n)) for n, c in (alert.get('networks') or {}).items() if c]
		reach = '{} · shown in {}{}'.format(
			'everyone' if targets == 'all' else ', '.join(str(t) for t in targets or []), _count(int(alert.get('delivered') or 0), 'session'),
			' ({})'.format(', '.join(shown)) if len(shown) > 1 else (' of ' + shown[0].split(' ', 1)[1] if shown else ''),
		)
		if alert.get('emailed'):
			reach += ' · e-mailed to {}'.format(_count(int(alert['emailed']), 'person', 'people'))
		rows.append({ **alert, 'reach': reach })
	return rows

async def action_broadcast(req: web.Request) -> web.Response:
	form = req['form']
	action = form.get('action')
	try:
		if action == 'alert':
			fields = _alert_fields(form)
			if not fields['rich'] and not fields['text']:
				return back(req, '/broadcast#alert', 'Write the alert first.', 'danger')
			everyone = form.get('who', 'everyone') != 'people'
			targets = ['all'] if everyone else [t.strip() for t in str(form.get('targets', '')).replace('\n', ',').split(',') if t.strip()]
			if not targets:
				return back(req, '/broadcast#alert', 'Name who the alert is for, or send it to everyone.', 'danger')
			if fields.get('email') and everyone:
				return back(req, '/broadcast#alert', 'Alerts are only e-mailed to the people you name.', 'danger')
			if 'networks' in fields and not fields['networks']:
				return back(req, '/broadcast#alert', 'Pick at least one network.', 'danger')
			result = await ins(req, 'ALR', { **fields, 'targets': targets })
			return back(req, '/broadcast#history', _alert_report(result))
		if action == 'announce':
			await ins(req, 'ANC', { 'title': str(form.get('title', '')).strip(), 'text': str(form.get('text', '')).strip(), 'url': str(form.get('url', '')).strip() })
			return back(req, '/broadcast#announcement', 'Posted to CrossTalk Beacon and What\'s New.')
		if action == 'maintenance':
			await ins(req, 'MNT', { 'minutes': int(str(form.get('minutes', '')) or '-1') })
			return back(req, '/broadcast#maintenance', 'Maintenance announced to everyone signed in.')
	except (ValueError, TypeError):
		return back(req, '/broadcast#maintenance', 'Give the minutes as a number.', 'danger')
	except LocalINSError as ex:
		return back(req, '/broadcast#{}'.format('alert' if action == 'alert' else action), _error_text(ex), 'danger')
	raise web.HTTPBadRequest(text = 'Unknown action.')

async def page_interservice(req: web.Request) -> web.Response:
	registry: ClientRegistry | None = req.app['registry']
	linked = { link.client_record.id: link for link in INSCtrl._links.values() if link.client_record is not None }
	return render(req, 'interservice.html', {
		'title': 'InterService', 'enabled': registry is not None,
		'clients': registry.clients() if registry is not None else [], 'codes': registry.codes() if registry is not None else [],
		'linked': linked, 'identifiers': settings.INS_IDENTIFIERS, 'host_key': registry.host_public if registry is not None else b'',
		'fingerprint': _fingerprint(registry.host_public) if registry is not None else '',
	})

def _fingerprint(raw: bytes) -> str:
	from core.interservice.crypto import fingerprint
	return fingerprint(raw)

async def action_interservice(req: web.Request) -> web.Response:
	registry: ClientRegistry | None = req.app['registry']
	if registry is None:
		raise web.HTTPNotFound(text = 'InterService is turned off.')
	form = req['form']
	action = form.get('action')
	here = '/interservice'
	try:
		client_id = int(str(form.get('client', '0') or '0'))
	except ValueError:
		client_id = 0
	if action == 'code':
		identifier = str(form.get('identifier', ''))
		try:
			hours = int(str(form.get('hours', '24') or '24'))
			code, record = registry.create_code(
				identifier, label = str(form.get('label', '')).strip(), address = str(form.get('address', '')).strip() or None,
				hours = hours, created_by = req['admin'].username,
			)
		except ValueError as ex:
			return back(req, here, 'Couldn\'t make the code: {}.'.format(ex), 'danger')
		req['admin'].reveal = { 'kind': 'code', 'value': code, 'for': identifier, 'expires': _when(record.expires) }
		return back(req, here)
	if action == 'cancel-code':
		try:
			ok = registry.cancel_code(int(str(form.get('code', '0'))))
		except ValueError:
			ok = False
		return back(req, here, 'Code cancelled.' if ok else 'That code was already used.', 'success' if ok else 'danger')
	if action == 'revoke':
		record = registry.revoke(client_id)
		return back(req, here, 'Revoked {} "{}". Its links were closed.'.format(record.identifier, record.label) if record else 'No such client.')
	if action == 'delete':
		return back(req, here, 'Deleted.' if registry.delete(client_id) else 'Only revoked keys can be deleted.')
	if action == 'addresses':
		try:
			record = registry.set_addresses(client_id, str(form.get('addresses', '')).replace(',', '\n').splitlines())
		except (KeyError, ValueError) as ex:
			return back(req, here, 'Couldn\'t save the addresses ({}).'.format(ex), 'danger')
		return back(req, here, 'Addresses for {} "{}" saved.'.format(record.identifier, record.label))
	raise web.HTTPBadRequest(text = 'Unknown action.')
