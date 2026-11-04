from typing import Any, Dict, Optional, Tuple
from aiohttp import web
import asyncio, shutil, time, uuid, datetime, util.misc, html, settings
from markupsafe import Markup
from urllib.parse import unquote, unquote_plus, quote, parse_qs
from pathlib import Path

from core.backend import Backend, BackendSession
from core.models import Contact, Substatus, ContactList
from util.hash import gen_salt
from util.misc import Logger
from .ymsg_ctrl import YMSGCtrlBase, _try_decode_ymsg
from .misc import YMSGService, yahoo_avatar_url, yahoo_avatar_checksum, TOKEN_LIFETIME
from .pager import _encode_yahoo_id, Y_COOKIE_TEMPLATE, T_COOKIE_TEMPLATE
from . import avatar_sync

YAHOO_TMPL_DIR = 'front/ymsg/tmpl'
# https://github.com/ifwe/digsby/blob/master/digsby/src/yahoo/yahooutil.py
FILE_STORE_PATH = '/storage/file/{filename}'
_tasks_by_token = {} # type: Dict[str, asyncio.Task[None]]

def register(app: web.Application, *, devmode: bool = False) -> None:
	util.misc.add_to_jinja_env(app, 'ymsg', YAHOO_TMPL_DIR)

	# HTTP auth
	app.router.add_get('/config/ncclogin', handle_ncclogin)
	app.router.add_get('/config/pwtoken_get', handle_gettoken)
	app.router.add_get('/config/pwtoken_login', handle_login)
	
	# Yahoo! Insider
	app.router.add_get('/ycontent/', handle_insider_ycontent)
	
	# Yahoo! Chat/Ads
	app.router.add_get('/us.yimg.com/i/msgr/chat/conf-banner.html', handle_chat_banad)
	app.router.add_get('/c/msg/tabs.html', handle_chat_tabad)
	app.router.add_get('/etc/yahoo-tab-ad', handle_chat_tabad)
	app.router.add_get('/c/msg/chat.html', handle_chat_notice)
	app.router.add_get('/c/msg/alerts.html', handle_chat_alertad)
	app.router.add_get('/etc/yahoo-placeholder', handle_placeholder)
	app.router.add_get('/external/client_ad.php', handle_banneradredir)
	app.router.add_get('/client_ad.php', handle_banneradredir)
	
	# Yahoo!'s redirector to cookie-based services
	#app.router.add_get('/config/reset_cookies', handle_cookies_redirect)
	
	# Yahoo!'s redirect service (rd.yahoo.com)
	app.router.add_get('/messenger/search/', handle_rd_yahoo)
	app.router.add_get('/messenger/client/', handle_rd_yahoo)
	
	# Yahoo HTTP file transfer fallback
	app.router.add_post('/notifyft', handle_ft_http)
	app.router.add_get(FILE_STORE_PATH, handle_yahoo_filedl)

	# Misc stuff
	app.router.add_get('/capacity', handle_capacity)
	app.router.add_get('/nofriends/', handle_nofriends)
	
	# Yahoo! Address Book (address.yahoo.com)
	app.router.add_get('/yab/{intl}', handle_yab)
	app.router.add_post('/yab/{intl}', handle_yab)
	
	# Photo sharing and P2P file transfer body
	app.router.add_post('/relay', handle_relay_upload)
	app.router.add_get('/relay', handle_relay_download)

async def handle_insider_ycontent(req: web.Request) -> web.Response:
	backend = req.app['backend']
	
	yab_received = False
	yab_set = False
	config_xml = []
	for query_xml in req.query.keys():
		# Ignore any `chatroom_##########` requests for now
		if query_xml in IGNORED_QUERIES or query_xml.startswith('chatroom_'): continue
		if query_xml in ('ab2','addab2'):
			(_, bs) = _parse_cookies(req, backend)
			if bs is not None:
				user = bs.user
				detail = user.detail
				if detail is not None:
					ab2_tmpl = req.app['jinja_env'].get_template('ymsg:Yinsider/Yinsider.ab2.xml')
					if query_xml == 'ab2':
						if yab_received or yab_set: continue
						ctcs = detail.contacts.values()
						
						records = []
						
						for ctc in ctcs:
							records.append(_gen_yab_record(ctc))
						config_xml.append(ab2_tmpl.render(epoch = round(time.time()), records = Markup('\n'.join(records))))
					if query_xml == 'addab2':
						edit_mode = False
						
						if yab_set or yab_received: continue
						if req.query.get('ee') == '1' and req.query.get('ow') == '1':
							edit_mode = True
						
						if edit_mode:
							if req.query.get('id') is None:
								continue
							
							target_ctc = None
							
							entry_id = str(req.query['id'])
							for ctc in detail.contacts.values():
								if ctc.detail.index_id == entry_id:
									target_ctc = ctc
							
							if not target_ctc:
								continue
							
							if req.query.get('pp') is not None:
								if str(req.query['pp']) not in ('0','1','2'):
									continue
							
							new_first_name = req.query.get('fn')
							new_last_name = req.query.get('ln')
							# Yahoo! will set the email/YID as the first name when editing contact details;
							# if new_first_name == email and last name isn't set, don't set first name
							if new_first_name != target_ctc.head.email and new_last_name:
								target_ctc.detail.first_name = new_first_name
							target_ctc.detail.last_name = new_last_name
							target_ctc.detail.nickname = req.query.get('nn')
							target_ctc.detail.personal_email = req.query.get('e')
							target_ctc.detail.home_phone = req.query.get('hp')
							target_ctc.detail.work_phone = req.query.get('wp')
							target_ctc.detail.mobile_phone = req.query.get('mb')
							
							backend._mark_modified(user)
						else:
							continue
						
						config_xml.append(ab2_tmpl.render(epoch = round(time.time()), records = Markup(_gen_yab_record(target_ctc))))
			continue
		
		if query_xml.startswith('getaudibles_'):
			feed = _get_ycontent_feed('audibles', query_xml[len('getaudibles_'):])
			if feed is not None:
				config_xml.append(feed)
			continue
		if query_xml == 'getimv':
			feed = _get_ycontent_feed('imvs', req.query.get('getimv') or '')
			if feed is not None:
				config_xml.append(feed)
			continue
		if query_xml in ('getgp', 'getwc'):
			continue
		
		tmpl = req.app['jinja_env'].get_template('ymsg:Yinsider/Yinsider.' + query_xml + '.xml')
		config_xml.append(tmpl.render())
	
	return render(req, 'ymsg:Yinsider/Yinsider.xml', {
		'epoch': round(time.time()),
		'configxml': Markup('\n'.join(config_xml)),
	})

# 'intl', 'os', 'ver', 'fn', 'ln', 'yid', 'nn', 'e', 'hp', 'wp', 'mp', 'pp', 'ee',
# 'ow', and 'id' are NOT queries to retrieve config XML files;
# 'getwc' and 'getgp' are undocumented as of now
# Other queries most likely are just not implemented
IGNORED_QUERIES = {
	'intl', 'os', 'ver',
	'imv', 'sms', 'getimv', 'getwc', 'getgp',
	'fn', 'ln', 'yid',
	'nn', 'e', 'hp',
	'wp', 'mb', 'pp',
	'ee', 'ow', 'id',
}

def _gen_yab_record(ctc: Contact) -> str:
	fname = None
	lname = None
	nname = None
	email = None
	hphone = None
	wphone = None
	mphone = None
	if ctc.detail.first_name is not None:
		fname = ' fname="{}"'.format(ctc.detail.first_name)
	if ctc.detail.last_name is not None:
		lname = ' lname="{}"'.format(ctc.detail.last_name)
	if ctc.detail.nickname is not None:
		nname = ' nname="{}"'.format(ctc.detail.nickname)
	if ctc.detail.personal_email is not None:
		email = ' email="{}"'.format(ctc.detail.personal_email)
	if ctc.detail.home_phone is not None:
		hphone = ' hphone="{}"'.format(ctc.detail.home_phone)
	if ctc.detail.work_phone is not None:
		wphone = ' wphone="{}"'.format(ctc.detail.work_phone)
	if ctc.detail.mobile_phone is not None:
		mphone = ' mphone="{}"'.format(ctc.detail.mobile_phone)
	
	return '<record userid="{yid}"{fname}{lname}{nname}{email}{hphone}{wphone}{mphone} dbid="{contact_id}"/>'.format(
		yid = ctc.head.username,
		fname = fname or '', lname = lname or '', nname = nname or '',
		email = email or '', hphone = hphone or '', wphone = wphone or '', mphone = mphone or '',
		contact_id = ctc.detail.index_id,
	)

async def handle_chat_banad(req: web.Request) -> web.Response:
	return render(req, 'ymsg:placeholders/banad.html')

async def handle_chat_tabad(req: web.Request) -> web.Response:
	query = req.query
	
	return render(req, 'ymsg:placeholders/adsmall.html', {
		'adtitle': 'banner ad',
		'spaceid': (query.get('spaceid') or 0),
	})

async def handle_chat_alertad(req: web.Request) -> web.Response:
	query = req.query
	
	return render(req, 'ymsg:placeholders/adsmall.html', {
		'adtitle': 'alert ad usmsgr',
		'spaceid': (query.get('spaceid') or 0),
	})

async def handle_placeholder(req: web.Request) -> web.Response:
	return render(req, 'ymsg:placeholders/generic.html')

async def handle_chat_notice(req: web.Request) -> web.Response:
	return render(req, 'ymsg:placeholders/generic.html')

async def handle_rd_yahoo(req: web.Request) -> web.Response:
	return web.HTTPFound(req.query_string.replace(' ', '+'))

async def handle_ft_http(req: web.Request) -> web.Response:
	body = await req.read()
	
	# Look for incomplete key-value field `29`
	stream_loc = body.find(b'29\xC0\x80')
	stream = body[(stream_loc + 4):]
	
	# Parse the rest of the YMSG packet
	raw_ymsg_data = body[:stream_loc]
	
	# Now change the length field as fit to get the YMSG parser to gobble it up
	import struct
	
	raw_ymsg_part_pre = raw_ymsg_data[0:8]
	raw_ymsg_part_post = raw_ymsg_data[10:]
	
	raw_ymsg_data = raw_ymsg_part_pre + struct.pack('!H', len(raw_ymsg_part_post[10:])) + raw_ymsg_part_post
	
	backend = req.app['backend']
	
	try:
		y_ft_pkt = _try_decode_ymsg(raw_ymsg_data, 0)[0]
	except Exception:
		return web.HTTPInternalServerError(text = '')
	
	try:
		# check version and vendorId
		if y_ft_pkt[1] > 18 or y_ft_pkt[2] not in (0, 100):
			return web.HTTPInternalServerError(text = '')
	except Exception:
		return web.HTTPInternalServerError(text = '')
	
	if y_ft_pkt[0] is YMSGService.FriendIconFileTransfer:
		return await _handle_picture_upload(req, backend, y_ft_pkt[5], stream)
	
	if y_ft_pkt[0] is not YMSGService.FileTransfer:
		return web.HTTPInternalServerError(text = '')
	
	ymsg_data = y_ft_pkt[5]
	
	yahoo_id_sender = util.misc.arbitrary_decode(ymsg_data.get(b'0') or b'')
	(yahoo_id, bs) = _parse_cookies(req, backend)
	if None in (bs,yahoo_id):
		return web.HTTPInternalServerError(text = '')
	assert bs is not None
	
	yahoo_id_recipient = util.misc.arbitrary_decode(ymsg_data.get(b'5') or b'')
	recipient_uuid = backend.util_get_uuid_from_username(yahoo_id_recipient)
	if recipient_uuid is None:
		return web.HTTPInternalServerError(text = '')
	recipient_head = backend._load_user_record(recipient_uuid)
	if recipient_head is None or recipient_head.status.substatus is Substatus.Offline:
		return web.HTTPInternalServerError(text = '')
	
	message = util.misc.arbitrary_decode(ymsg_data.get(b'14') or b'')
	
	file_path_raw = ymsg_data.get(b'27') # type: Optional[bytes]
	file_len = util.misc.arbitrary_decode(ymsg_data.get(b'28') or b'0')
	
	# https://github.com/ifwe/digsby/blob/master/digsby/src/yahoo/yfiletransfer.py#L7
	# Looks like the HTTP file transfer server had its own size limits (10 MB)
	if file_path_raw is None or str(len(stream)) != file_len or len(stream) > (2 ** 20):
		return web.HTTPInternalServerError(text = '')
	
	file_path = util.misc.arbitrary_decode(file_path_raw)
	
	try:
		filename = Path(file_path).name
	except:
		return web.HTTPInternalServerError(text = 'File not found')
	
	token = gen_salt(length = 30)
	path = _get_tmp_file_storage_path(token)
	path.mkdir(exist_ok = True, parents = True)
	
	file_tmp_path = path / unquote_plus(filename)
	file_tmp_path.write_bytes(stream)
	
	upload_time = time.time()
	
	expiry_task = req.app.loop.create_task(_store_tmp_file_until_expiry(file_tmp_path))
	_tasks_by_token[token] = expiry_task
	
	for bs_other in bs.backend._sc.iter_sessions():
		if bs_other.user.uuid != recipient_uuid:
			continue
		bs_other.evt.ymsg_on_sent_ft_http(
			yahoo_id_sender, '{}?{}'.format(FILE_STORE_PATH.format(filename = quote(file_tmp_path.name)), token),
			upload_time, message,
		)
	
	bs.evt.ymsg_on_upload_file_ft(yahoo_id_recipient, message)
	
	return web.HTTPOk(text = '')

async def handle_relay_upload(req: web.Request) -> web.Response:
	backend = req.app['backend']
	token = req.query.get('token')
	if not token or not backend.auth_service.get_token('ymsg/relay', token):
		return web.HTTPNotFound(text = 'Token invalid')
	
	body = await req.read()
	if not body or len(body) > (2 ** 24):
		return web.HTTPInternalServerError(text = 'No body')
	
	path = _get_tmp_file_storage_path(token)
	path.mkdir(exist_ok = True, parents = True)
	(path / 'blob').write_bytes(body)
	
	expiry_task = req.app.loop.create_task(_store_tmp_file_until_expiry(path))
	_tasks_by_token[token] = expiry_task
	
	return web.HTTPOk(text = '')

async def handle_relay_download(req: web.Request) -> web.Response:
	backend = req.app['backend']
	token = req.query.get('token')
	if not token or not backend.auth_service.get_token('ymsg/relay', token):
		return web.HTTPNotFound(text = 'Token invalid')
	
	blob = _get_tmp_file_storage_path(token) / 'blob'
	if req.method == 'HEAD':
		size = blob.stat().st_size if blob.is_file() else 0
		return web.Response(status = 200, headers = {'Content-Length': str(size)})
	
	try:
		data = blob.read_bytes()
	except FileNotFoundError:
		return web.HTTPNotFound(text = 'File not found')
	
	task = _tasks_by_token.pop(token, None)
	if task is not None:
		task.cancel()
	shutil.rmtree(_get_tmp_file_storage_path(token), ignore_errors = True)
	return web.Response(status = 200, body = data)

IGNORED_QUERIES = {
	'intl', 'os', 'ver', 'fmt', 't',
	'imv', 'sms', 'system',
	'countries', 'defaultcountry', 'filter', 'url', 'searchbar', 'games',
	'fn', 'ln', 'yid',
	'nn', 'e', 'hp',
	'wp', 'mb', 'pp',
	'ee', 'ow', 'id',
}


async def _store_tmp_file_until_expiry(path: Path) -> None:
	await asyncio.sleep(86400)
	# When a day passes, delete the file (unless it has already been deleted by
	# the downloader handler; it will cancel the according task then)
	shutil.rmtree(str(path), ignore_errors = True)

async def handle_yahoo_filedl(req: web.Request) -> web.Response:
	filename = req.match_info['filename']
	token = None
	query_keys = list(req.query.keys())
	if query_keys:
		token = list(req.query.keys())[0]
	
	if token is None:
		return web.HTTPNotFound(text = '')
	
	file_storage_path = _get_tmp_file_storage_path(token)
	file_path = file_storage_path / unquote(filename)
	try:
		file_stream = file_path.read_bytes()
	except FileNotFoundError:
		return web.HTTPNotFound(text = '')
	# Only delete temporary file if request is specifically `GET`
	if req.method == 'GET':
		_tasks_by_token[token].cancel()
		del _tasks_by_token[token]
		shutil.rmtree(file_storage_path, ignore_errors = True)
	return web.Response(status = 200, headers = {
		'Content-Disposition': 'attachment; filename="{}"'.format(filename),
	}, body = file_stream)

async def handle_capacity(req: web.Request) -> web.Response:
	return web.Response(text = 'COLO_CAPACITY=1\r\nCS_IP_ADDRESS={}\r\n'.format(settings.TARGET_IP))

async def handle_nofriends(req: web.Request) -> web.Response:
	return render(req, 'ymsg:layout/nofriends.html')

async def handle_gettoken(req: web.Request) -> web.Response:
	backend = req.app['backend']

	params = req.rel_url.query
	username = params.get('login')
	encoded_pwd = params.get('passwd')
	pwd = unquote(encoded_pwd) if encoded_pwd is not None else None
	error_int = None

	uuid_val = backend.util_get_uuid_from_username(username)
	user = backend.user_service.get(uuid_val) if uuid_val else None

	if not username or not encoded_pwd:
		error_int = "100"
	elif not user:
		error_int = "1235"
	elif user.suspended:
		error_int = "1218"
	else:
		token_tpl = _login(req, username, pwd, lifetime = TOKEN_LIFETIME)
		if token_tpl is None:
			error_int = "1212"
		else:
			token, _ = token_tpl

	if error_int:
		return web.Response(text=error_int)
	else:
		return web.Response(text="0\r\nymsgr={}\r\npartnerid=0".format(token))

async def handle_login(req: web.Request) -> web.Response:
	backend = req.app['backend']

	params = req.rel_url.query
	token = params.get('token')

	tpl = backend.login_auth_service.get_token('ymsg/cookie', token)

	crumb = util.misc.generate_random_string(chars=32)
	crumbstr = crumb.decode('utf-8')

	y_cookie = Y_COOKIE_TEMPLATE.format(encodedname=_encode_yahoo_id(token))
	t_cookie = T_COOKIE_TEMPLATE.format(token=token)
	import uuid
	ssl_cookie = str(uuid.uuid4())
	b_cookie = str(uuid.uuid4())

	if tpl is not None:
		resp = render(req, 'ymsg:auth/ok.tmpl', {
			'crumb': crumbstr,
			't_cookie': t_cookie,
			'y_cookie': y_cookie,
			'ssl_cookie': ssl_cookie,
			'b_cookie': b_cookie
		})
		resp.set_cookie('T', t_cookie, path='/')
		resp.set_cookie('Y', y_cookie, path='/',)
		resp.set_cookie('SSL', ssl_cookie, path='/')
		resp.set_cookie('B', b_cookie, path='/')
		return resp
	else:
		return web.Response(text="100")

async def handle_yab(req: web.Request) -> web.Response:
	backend = req.app['backend']
	user = _resolve_user(req, backend)
	if user is None:
		return web.HTTPInternalServerError(text = '')
	detail = user.detail
	if detail is None:
		return web.HTTPInternalServerError(text = '')
	
	esc = lambda s: html.escape(str(s), quote = True)
	
	wanted = None # type: Optional[set[str]]
	if req.method == 'POST':
		posted = (await req.read()).decode('utf-8', 'replace')
		wanted = {yi.lower() for yi in re.findall(r'''\byi=["']([^"']+)["']''', posted)}
	
	records = ['<ct id="0" yi="{}" />\n'.format(esc(user.username))]
	for ctc in detail.contacts.values():
		if not ctc.lists & ContactList.FL:
			continue
		if wanted is not None and ctc.head.username.lower() not in wanted:
			continue
		attrs = ''
		if ctc.detail.first_name: attrs += ' fn="{}"'.format(esc(ctc.detail.first_name))
		if ctc.detail.last_name: attrs += ' ln="{}"'.format(esc(ctc.detail.last_name))
		if ctc.detail.nickname: attrs += ' nn="{}"'.format(esc(ctc.detail.nickname))
		records.append('<ct id="{}" yi="{}"{} />\n'.format(esc(ctc.detail.index_id), esc(ctc.head.username), attrs))
	
	body = '<?xml version="1.0" encoding="utf-8"?><ab k="{}" cc="{}">\n{}</ab>\r\n'.format(esc(user.username), len(records), ''.join(records))
	return web.Response(status = 200, body = body.encode('utf-8'), content_type = 'text/html', charset = 'utf-8')

async def handle_ncclogin(req: web.Request) -> web.Response:
	backend = req.app['backend']
	params = req.rel_url.query

	username = params.get('login')
	encoded_pwd = params.get('passwd')
	pwd = unquote(encoded_pwd)
	uuid = backend.util_get_uuid_from_username(username)
	user = backend.user_service.get(uuid) if uuid else None
	detail = backend._load_detail(user)

	contacts = detail.contacts
	cs = list(contacts.values())
	cs_fl = [c for c in cs if c.lists & ContactList.FL and not c.lists & ContactList.BL]

	contact_group_list = []
	for grp in detail._groups_by_id.values():
		contact_list = []
		for c in cs_fl:
			for group in c._groups.copy():
				if group.id == grp.id:
					contact_list.append(c.head.username)
		if contact_list:
			contact_group_list.append(f"{grp.name}:{','.join(contact_list)}\n")

	# Handle contacts that aren't part of any groups
	no_group_contacts = [c.head.username for c in cs_fl if not c._groups]
	if no_group_contacts:
		contact_group_list.append(f"(No Group):{','.join(no_group_contacts)}\n")

	contact_list_format = ''.join(contact_group_list)
	ignore_list = [c.head.username for c in cs if c.lists & ContactList.BL]
	ignore_list_format = ','.join(ignore_list)

	if user is None:
		return web.Response(status=500, text="Internal Server Error")
	else:
		return web.Response(text=(
			f"OK\r\n"
			f"BEGIN BUDDYLIST\r\n{contact_list_format}END BUDDYLIST\r\n"
			f"BEGIN IGNORELIST\r\n{ignore_list_format}\r\nEND IGNORELIST\r\n"
			f"BEGIN IDENTITIES\r\n{username}\r\nEND IDENTITIES\r\n"
			f"Mail=1\r\nLogin={username}"
		))

async def handle_banneradredir(req: web.Request) -> web.Response:
	return web.HTTPFound(f'http://{settings.TARGET_HOST}/ads/banner')

async def _handle_picture_upload(
	req: web.Request, backend: Backend, ymsg_data: Any, stream: bytes,
) -> web.Response:
	from util.avatar import get_img_type
	import traceback
	
	user = _resolve_user(req, backend)
	if user is None:
		return web.HTTPInternalServerError(text = '')
	
	try:
		declared_len = int(util.misc.arbitrary_decode(ymsg_data.get(b'28') or b'0'))
	except ValueError:
		declared_len = 0
	if declared_len <= 0 or len(stream) < declared_len or declared_len > (2 ** 22):
		return web.HTTPInternalServerError(text = '')
	stream = stream[:declared_len]
	
	ext = get_img_type(stream)
	if ext is None:
		return web.HTTPInternalServerError(text = '')
	
	try:
		backend.user_service.save_avatar(user, stream, ext)
	except Exception:
		traceback.print_exc()
		return web.HTTPInternalServerError(text = '')
	avatar_sync.refresh_avatar(backend, user)
	
	filename_raw = ymsg_data.get(b'27')
	filename = util.misc.arbitrary_decode(filename_raw) if filename_raw else 'im.{}'.format(ext)
	try:
		filename = Path(filename).name
	except Exception:
		filename = 'im.{}'.format(ext)
	
	try:
		lifetime = int(util.misc.arbitrary_decode(ymsg_data.get(b'38') or b'604800'))
	except ValueError:
		lifetime = 604800
	expiry = str(int(time.time()) + lifetime)
	
	url = yahoo_avatar_url(user)
	if url is None or yahoo_avatar_checksum(user) is None:
		return web.HTTPInternalServerError(text = '')
	
	for bs_self in backend.util_get_sessions_by_user(user):
		bs_self.evt.ymsg_on_friend_icon_file_transfer(user.username, user.username, url.decode('utf-8'), filename, expiry)
	avatar_sync.push_avatar_change(backend, user)
	
	return web.Response(status = 200, body = b'\x00\x00\x00\x00', content_type = 'text/html', charset = 'UTF-8')

def _get_tmp_file_storage_path(token: str) -> Path:
	return Path('storage/file') / token

def _get_cookie(req: web.Request, name: str) -> Optional[str]:
	value = req.cookies.get(name)
	if value:
		return value
	for part in (req.headers.get('Cookie') or '').split(';'):
		key, sep, val = part.strip().partition('=')
		if sep and key == name:
			return val
	return None

def _resolve_user(req: web.Request, backend: Backend) -> Optional[Any]:
	y_cookie = _get_cookie(req, 'Y')
	t_cookie = _get_cookie(req, 'T')
	
	(yahoo_id, bs) = _parse_cookies(req, backend, y = y_cookie or '', t = t_cookie or '')
	if bs is not None and yahoo_id is not None:
		return bs.user
	
	if not t_cookie:
		return None
	qs = parse_qs(t_cookie, keep_blank_values = True)
	token = None
	for key in ('z', 'sk', 'd'):
		if qs.get(key) and qs[key][0]:
			token = qs[key][0]
			break
	if not token:
		return None
	
	tpl = backend.login_auth_service.get_token('ymsg/cookie', token)
	if not tpl:
		return None
	user = backend._load_user_record(tpl[0])
	if user is None or not backend.util_get_sessions_by_user(user):
		return None
	return user

def _parse_cookies(
	req: web.Request, backend: Backend, y: Optional[str] = None, t: Optional[str] = None,
) -> Tuple[Optional[str], Optional[BackendSession]]:
	cookies = req.cookies
	
	if None in (y,t):
		y_cookie = cookies.get('Y')
		t_cookie = cookies.get('T')
	else:
		y_cookie = y
		t_cookie = t
	
	return (backend.auth_service.get_token('ymsg/cookie', y_cookie or ''), backend.auth_service.get_token('ymsg/cookie', t_cookie or ''))

def _login(req: web.Request, username: str, pwd: str, lifetime: int = TOKEN_LIFETIME) -> Optional[Tuple[str, datetime]]:
	backend: Backend = req.app['backend']
	uuid_val = backend.user_service.login_with_username(username, pwd)
	if uuid_val is None:
		return None

	token_tuple = backend.login_auth_service.create_token('ymsg/cookie', [uuid_val, None], lifetime=lifetime)
	if token_tuple is None:
		return None

	token, expiry = token_tuple
	return (token, expiry)

def render(req: web.Request, tmpl_name: str, ctxt: Optional[Dict[str, Any]] = None, status: int = 200) -> web.Response:
	if tmpl_name.endswith('.xml'):
		content_type = 'text/xml'
	else:
		content_type = 'text/html'
	tmpl = req.app['jinja_env'].get_template(tmpl_name)
	content = tmpl.render(**(ctxt or {})).replace('\n', '\r\n')
	return web.Response(status = status, content_type = content_type, text = content)
