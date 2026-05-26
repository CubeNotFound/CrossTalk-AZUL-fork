from typing import Any, Dict, Optional, Tuple
from aiohttp import web
import asyncio, shutil, time, uuid, datetime, util.misc, settings
from markupsafe import Markup
from urllib.parse import unquote, unquote_plus, quote
from pathlib import Path

from core.backend import Backend, BackendSession
from core.models import Contact, Substatus, ContactList
from util.hash import gen_salt
from util.misc import Logger
from .ymsg_ctrl import YMSGCtrlBase, _try_decode_ymsg
from .misc import YMSGService
from .pager import _encode_yahoo_id, Y_COOKIE_TEMPLATE, T_COOKIE_TEMPLATE

YAHOO_TMPL_DIR = 'front/ymsg/tmpl'
# https://github.com/ifwe/digsby/blob/f5fe00244744aa131e07f09348d10563f3d8fa99/digsby/src/yahoo/yahooutil.py#L33
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
		if y_ft_pkt[1] > 16 or y_ft_pkt[2] not in (0, 100):
			return web.HTTPInternalServerError(text = '')
	except Exception:
		return web.HTTPInternalServerError(text = '')
	
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
		return web.HTTPInternalServerError(text = '')
	
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
	return web.Response(text="COLO_CAPACITY=1\nCS_IP_ADDRESS={}".format(settings.TARGET_IP))

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
		token_tpl = _login(req, username, pwd, lifetime=86400)
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

async def handle_ncclogin(req: web.Request) -> web.Response:
	backend = req.app['backend']
	params = req.rel_url.query

	username = params.get('login')
	encoded_pwd = params.get('passwd')
	pwd = unquote(encoded_pwd)
	uuid = backend.util_get_uuid_from_username(username)
	user = backend.user_service.get(uuid) if uuid else None
	detail = backend._load_detail(user)

	if settings.DEBUG:
		print(f"Username: {username}")
		print(f"Encoded Password: {encoded_pwd}")
		print(f"Decoded Password: {pwd}")
		print(f"UUID: {uuid}")
		print(f"User: {user}")

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

def _get_tmp_file_storage_path(token: str) -> Path:
	return Path('storage/file') / token

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

def _login(req: web.Request, username: str, pwd: str, lifetime: int = 86400) -> Optional[Tuple[str, datetime]]:
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
