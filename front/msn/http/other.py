from typing import Optional, Any, Tuple, Literal, List, Dict
from datetime import datetime, timedelta
from io import BytesIO
from email.parser import Parser
from email.header import decode_header
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, parse_qsl
from pathlib import Path
import asyncio, re, secrets, base64, random, json, mimetypes, uuid, PyRSS2Gen, settings, util.misc
from markupsafe import Markup
from aiohttp import web
 
from core import models
from core.user import beacon_enabled
from core.backend import Backend, BackendSession
from util.avatar import get_img_type, store_photo_file, get_photo_data
from ..misc import gen_mail_data, format_oim, cid_format, puid_format, encode_xml_ne
from .util import find_element, get_tag_localname, render, preprocess_soap, unknown_soap, bool_to_str
 
LOGIN_PATH = '/login2.srf'
TMPL_DIR = 'front/msn/http/tmpl'
ETC_DIR = 'front/msn/etc'
PP = 'Passport1.4'
PHOTO_MAX_SIZE = 10 * 1024 * 1024
 
def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'msn', TMPL_DIR, globals = {
		'date_format': util.misc.date_format,
		'cid_format': cid_format,
		'puid_format': puid_format,
		'bool_to_str': bool_to_str,
		'contact_is_favorite': _contact_is_favorite,
		'datetime': datetime,
		'settings': settings
	})
	
	# MSN >= 5
	app.router.add_get('/nexus-mock', handle_nexus)
	app.router.add_get('/rdr/pprdr.asp', handle_nexus)
	app.router.add_get(LOGIN_PATH, handle_login)
	app.router.add_get('/svcs/mms/tabs.asp', handle_tabs)
	app.router.add_get('/svcs/mms/portal.asp', handle_portal)
	app.router.add_get('/svcs/mms/ads.asp', handle_msn5ads)
	
	# MSN >= 6
	app.router.add_get('/etc/MsgrConfig', handle_msgrconfig)
	app.router.add_post('/etc/MsgrConfig', handle_msgrconfig)
	# TODO: this is stupid, find a way to make this case-insensitive
	app.router.add_get('/Config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_post('/Config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_get('/config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_post('/config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_get('/start', handle_today)
	
	# MSN >= 7.5
	app.router.add_route('OPTIONS', '/NotRST.srf', handle_not_rst)
	app.router.add_post('/NotRST.srf', handle_not_rst)
	app.router.add_post('/RST.srf', handle_rst)
	app.router.add_post('////RST.srf', handle_rst) # libpurple what the FUCK, also this doesn't even work
	app.router.add_post('/RST2.srf', lambda req: handle_rst(req, rst2 = True))
	
	# MSN >= 8
	app.router.add_post('/ppsecure/sha1auth.srf', handle_sha1auth)
	app.router.add_post('/rsi/rsi.asmx', handle_rsi)
	app.router.add_post('/OimWS/oim.asmx', handle_oim)
	app.router.add_get('/svcs/msn-video-feeds/', handle_videofeed)
	app.router.add_get('/svcs/feed', lambda req: handle_videofeed(req, get_videos = True))
 
	# MSN >= 14
	app.router.add_post('/whatsnew/whatsnewservice.asmx', handle_whatsnew)
	app.router.add_get('/svcs/tab={id}', handle_tabs_newer)
 
	# MSN >= 15
	app.router.add_post('/sqm/messenger/sqmserver.dll', handle_blankok)
	app.router.add_post('/sqm/WindowsLive/sqmserver.dll', handle_blankok)
	app.router.add_post('/uploaddata.aspx', handle_blankok)
	app.router.add_get('/ppcrlcheck.srf', handle_ppcrlcheck)
	app.router.add_post('/profile/profile.asmx', handle_profile)
	app.router.add_get(r'/~Live.ConfigServer/{junk:.*}/~op-GetClientConfig/{tail:.*}', handle_msgrconfig16)
	app.router.add_get(r'/~Live.ConfigServer.SuiteUpdate/{tail:.*}', handle_suiteupdate)
	app.router.add_get(r'/~Live.ConfigServer.PSA/{tail:.*}', handle_socialint)
	app.router.add_get('/svcs/GameBrowser', handle_gamebrowser)
	app.router.add_post('/Users({cid})/Status', handle_user_status)
	app.router.add_post('/Users({cid})/files/{folder}', handle_user_files)
	app.router.add_get('/photos/{uuid}/{name}', handle_photo)
	
	# Misc
	app.router.add_get('/{i}meen_{locale}/{id}', handle_msn_redirect)
 
async def handle_blankok(req: web.Request) -> web.Response:
	return web.Response(status = 200)
 
async def handle_profile(req: web.Request) -> web.Response:
	backend = req.app['backend']
	header, action, bs, token = await preprocess_soap(req)  # was missing entirely
	user = _get_user_from_token(backend, bs, token)
	if user is None:
		raise web.HTTPInternalServerError()

	action_str = get_tag_localname(action)
	now_str = util.misc.date_format(datetime.utcnow())
	cachekey = secrets.token_urlsafe(172)

	if action_str in ('Get', 'GetMany'):
		heads = { cid_format(head.uuid, decimal = True): head for head in [user] + [ctc.head for ctc in backend._load_detail(user).contacts.values()] }
		if action_str == 'Get':
			requested = [(heads.get(str(find_element(action, 'V1'))) or user, str(find_element(action, 'V2')))]
		else:
			requested = [(heads[str(v1)], None) for v1 in action.findall('.//{*}ProfileId/{*}V1') if str(v1) in heads]

		profiles = [] # type: List[Dict[str, Any]]
		for head, puid in requested:
			roaming_info = backend.user_service.get_roaming_info(head)
			if roaming_info is None: continue
			profiles.append({ 'user': head, 'cid': cid_format(head.uuid), 'puid': puid, 'roaming_info': roaming_info })
		if not profiles and action_str == 'Get':
			raise web.HTTPInternalServerError()

		return render(req, 'msn:profile/ProfileResponse.xml', {
			'action': action_str,
			'profiles': profiles,
			'cachekey': cachekey,
			'pptoken1': token,
			'now': now_str,
			'host': settings.USERSTORAGE_HOST,
		})

	return unknown_soap(req, header, action)
 
async def handle_sha1auth(req: web.Request) -> web.Response:
	post = await req.post()
	
	token_data = post.get('token')
	if token_data is None:
		return web.HTTPInternalServerError()
	
	token_fields = dict(parse_qsl(str(token_data)))
	if 'ru' not in token_fields:
		return web.HTTPInternalServerError()
	
	return web.HTTPFound(token_fields['ru'])
 
async def handle_ppcrlcheck(req: web.Request) -> web.Response:
	response = '<config>\r\n\t<deviceid minversion="16.000.26889.00"/>\r\n\t<mobilecfg minversion="16.000.26208.0"/>\r\n</config>'
	return web.HTTPOk(body=response)
 
async def handle_rsi(req: web.Request) -> web.Response:
	_, action, bs, token = await preprocess_soap_rsi(req)
	
	if token is None or bs is None:
		return render(req, 'msn:oim/Fault.validation.xml', status = 500)
	action_str = get_tag_localname(action)
	
	user = bs.user
	
	backend = req.app['backend']
	
	if action_str == 'GetMetadata':
		return render(req, 'msn:oim/GetMetadataResponse.xml', {
			'md': gen_mail_data(user, backend, on_ns = False, e_node = False),
		})
	if action_str == 'GetMessage':
		oim_uuid = find_element(action, 'messageId')
		oim_markAsRead = find_element(action, 'alsoMarkAsRead')
		oim = backend.user_service.get_oim_single(user, oim_uuid, mark_read = oim_markAsRead is True)
		return render(req, 'msn:oim/GetMessageResponse.xml', {
			'oim_data': format_oim(oim),
		})
	if action_str == 'DeleteMessages':
		messageIds = action.findall('.//{*}messageIds/{*}messageId')
		if not messageIds:
			return render(req, 'msn:oim/Fault.validation.xml', status = 500)
		for messageId in messageIds:
			if backend.user_service.get_oim_single(user, str(messageId)) is None:
				return render(req, 'msn:oim/Fault.validation.xml', status = 500)
		for messageId in messageIds:
			backend.user_service.delete_oim(user.uuid, str(messageId))
		bs.evt.msn_on_oim_deletion(len(messageIds))
		return render(req, 'msn:oim/DeleteMessagesResponse.xml')
	
	return render(req, 'msn:Fault.doesnotexist.xml', { 'action': action_str })
 
async def handle_oim(req: web.Request) -> web.Response:
	header, _, body_content, bs, _ = await preprocess_soap_oimws(req)
	soapaction = (req.headers.get('SOAPAction') or '')
	if soapaction.startswith('"') and soapaction.endswith('"'):
		soapaction = soapaction[1:-1]
	owsns = (
		'http://messenger.msn.com/ws/2004/09/oim/'
		if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/')
		else 'http://messenger.live.com/ws/2006/09/oim/'
	)
	
	lockkey_result = header.find('.//{*}Ticket').get('lockkey')
	
	if bs is None or lockkey_result in (None,''):
		return render(req, 'msn:oim/Fault.authfailed.xml', {
			'owsns': owsns,
		}, status = 500)
	
	backend: Backend = req.app['backend']
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	friendlyname = None
	friendlyname_str = None
	friendly_charset = None
	
	friendlyname_mime = header.find('.//{*}From').get('friendlyName')
	email = header.find('.//{*}From').get('memberName')
	recipient = header.find('.//{*}To').get('memberName')
	
	recipient_uuid = backend.util_get_uuid_from_email(recipient)
	
	user_display_email = backend.util_get_display_email(user)
	alias_email = '{}@crosstalk.im'.format(user.username).lower()
	if email.lower() not in (user.email.lower(), alias_email, user_display_email.lower()) or recipient_uuid is None or not _is_on_al(recipient_uuid, backend, user, detail):
		return render(req, 'msn:oim/Fault.unavailable.xml', {
			'owsns': owsns,
		}, status = 500)
	
	assert req.transport is not None
	peername = req.transport.get_extra_info('peername')
	if peername:
		host = peername[0]
	else:
		host = '127.0.0.1'
	
	oim_msg_seq = str(find_element(header, 'Sequence/MessageNumber'))
	if not oim_msg_seq.isnumeric():
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	
	if friendlyname_mime is not None:
		try:
			friendlyname, friendly_charset = decode_header(friendlyname_mime)[0]
		except:
			return render(req, 'msn:oim/Fault.invalidcontent.xml', {
				'owsns': owsns,
			}, status = 500)
	
	if friendly_charset is None:
		friendly_charset = 'utf-8'
	
	if friendlyname is not None:
		friendlyname_str = friendlyname.decode(friendly_charset)
	
	oim_proxy_string = header.find('.//{*}From').get('proxy')
	
	try:
		oim_mime = Parser().parsestr(body_content)
	except:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	
	oim_run_id = str(oim_mime.get('X-OIM-Run-Id'))
	if oim_run_id is None:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	if not re.match(r'^\{?[A-Fa-f0-9]{8,8}-([A-Fa-f0-9]{4,4}-){3,3}[A-Fa-f0-9]{12,12}\}?', oim_run_id):
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	oim_run_id = oim_run_id.replace('{', '').replace('}', '')
	if (
		'X-Message-Info', 'Received', 'From', 'To', 'Subject', 'X-OIM-originatingSource', 'X-OIMProxy', 'Message-ID',
		'X-OriginalArrivalTime', 'Date', 'Return-Path'
	) in oim_mime.keys():
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	if str(oim_mime.get('MIME-Version')) != '1.0':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	if not str(oim_mime.get('Content-Type')).startswith('text/plain'):
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	if str(oim_mime.get('Content-Transfer-Encoding')) != 'base64':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	if str(oim_mime.get('X-OIM-Message-Type')) != 'OfflineMessage':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	oim_seq_num = str(oim_mime.get('X-OIM-Sequence-Num'))
	if oim_seq_num != oim_msg_seq:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	oim_headers = {name: str(value) for name, value in oim_mime.items()}
	
	try:
		i = body_content.index('\n\n') + 2
		oim_body = body_content[i:]
		for oim_b64_line in oim_body.split('\n'):
			if len(oim_b64_line) > 77:
				return render(req, 'msn:oim/Fault.invalidcontent.xml', {
					'owsns': owsns,
				}, status = 500)
		oim_body_normal = oim_body.strip()
		oim_body_normal = base64.b64decode(oim_body_normal).decode('utf-8')
		if len(oim_body_normal.encode('utf-8')) > OIM_MAX_SIZE:
			return render(req, 'msn:oim/Fault.messagetoolarge.xml', {
				'owsns': owsns,
			}, status = 500)
		
		# An offline message is a message like any other: over the sender's rate (or at the maximum warning level) it's
		# refused, and its recipient may warn (vote) its sender for it
		if not backend.util_message_allowed(user, models.MessageData(sender = user, type = models.MessageType.Chat, text = oim_body_normal)):
			return render(req, 'msn:oim/Fault.throttle.xml', {
				'owsns': owsns,
			}, status = 500)
		recipient_user = backend._load_user_record(recipient_uuid)
		if recipient_user is not None:
			backend.abuse.track_message(user, recipient_user)
		
		backend.user_service.save_oim(
			bs, recipient_uuid, oim_run_id, host, oim_body_normal, True, from_friendly = friendlyname_str,
			from_friendly_charset = friendly_charset, headers = oim_headers, oim_proxy = oim_proxy_string,
		)
	except:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': owsns,
		}, status = 500)
	
	return render(req, 'msn:oim/StoreResponse.xml', {
		'seq': oim_msg_seq,
		'owsns': owsns,
	})
 
OIM_MAX_SIZE = 64 * 1024

def _is_on_al(uuid: str, backend: Backend, user: models.User, detail: models.UserDetail) -> bool:
	contact = detail.contacts.get(uuid)
	if user.settings.get('BLP', 'AL') == 'AL' and (contact is None or not contact.lists & models.ContactList.BL):
		return True
	if user.settings.get('BLP', 'AL') == 'BL' and contact is not None and not contact.lists & models.ContactList.BL:
		return True
	
	if contact is not None:
		ctc_detail = backend._load_detail(contact.head)
		assert ctc_detail is not None
		
		ctc_me = ctc_detail.contacts.get(user.uuid)
		if ctc_me is None and contact.head.settings.get('BLP', 'AL') == 'AL':
			return True
		if ctc_me is not None and not ctc_me.lists & models.ContactList.BL:
			return True
	return False
 
async def preprocess_soap_rsi(req: web.Request) -> Tuple[Any, Any, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	token_tag = root.find('.//{*}PassportCookie/{*}*[1]')
	if get_tag_localname(token_tag) != 't':
		token = None
	token = token_tag.text
	if token is not None:
		token = token[0:20]
	
	backend: Backend = req.app['backend']
	bs = backend.util_get_sess_by_token(token)
	
	header = find_element(root, 'Header')
	action = find_element(root, 'Body/*[1]')
	#if settings.DEBUG: print('Action: {}'.format(get_tag_localname(action)))
	
	return header, action, bs, token
 
async def preprocess_soap_oimws(req: web.Request) -> Tuple[Any, str, str, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	token = root.find('.//{*}Ticket').get('passport')
	if token[0:2] == 't=':
		token = token[2:22]
	
	backend: Backend = req.app['backend']
	bs = backend.util_get_sess_by_token(token)
	
	header = find_element(root, 'Header')
	body_msgtype = str(find_element(root, 'Body/MessageType'))
	body_content = str(find_element(root, 'Body/Content')).replace('\r\n', '\n')
	
	return header, body_msgtype, body_content, bs, token
 
async def handle_whatsnew(req: web.Request) -> web.Response:
	backend: Backend = req.app['backend']
	header, action, bs, token = await preprocess_soap(req)
	user = _get_user_from_token(backend, bs, token)
	if user is None:
		raise web.HTTPInternalServerError()

	action_str = get_tag_localname(action)
	if action_str not in ('GetContactsRecentActivity', 'GetBatchRecentActivity'):
		return unknown_soap(req, header, action)

	detail = backend._load_detail(user)
	if action_str == 'GetContactsRecentActivity':
		# The user's own activities, their contacts' and service announcements
		publishers = [user] + [
			ctc.head for ctc in detail.contacts.values() if ctc.lists & models.ContactList.FL and not ctc.lists & models.ContactList.BL
		]
		if not beacon_enabled(user):
			publishers = []
	else:
		# Activities of specific people (contact card, own profile)
		cids = { cid.text for cid in action.findall('.//{*}Cid') }
		publishers = [head for head in [user] + [ctc.head for ctc in detail.contacts.values()] if cid_format(head.uuid, decimal = True) in cids]

	activities = backend.user_service.get_activities(
		[head.uuid for head in publishers], int(str(find_element(action, 'count') or 10)),
		announcements = (action_str == 'GetContactsRecentActivity'),
	)

	return render(req, 'msn:whatsnew/WhatsNewResponse.xml', {
		'action': action_str,
		'owner_cid': cid_format(user.uuid, decimal = True),
		'locale': str(find_element(action, 'locales/string') or 'en-us'),
		'activities': activities,
		'types': { int(activity.type) for activity in activities },
		'detail': detail,
		'now': datetime.utcnow(),
	})

async def handle_user_status(req: web.Request) -> web.Response:
	# WLM 2011 shares status messages to "What's New" through the Live Atom API
	from lxml.etree import fromstring as parse_xml
	
	backend: Backend = req.app['backend']
	user, bs = _get_live_api_user(req)
	cid = req.match_info['cid']
	
	try:
		message = parse_xml(await req.read()).findtext('{http://www.w3.org/2005/Atom}title') or ''
	except Exception:
		raise web.HTTPBadRequest()
	
	_set_status_message(backend, user, bs, message)
	
	message_xml = encode_xml_ne(message)
	return web.HTTPOk(content_type = 'application/atom+xml', text = (
		'<?xml version="1.0" encoding="utf-8"?><entry xmlns="http://www.w3.org/2005/Atom" xmlns:live="http://api.live.com/schemas">'
		f'<id>{req.url}</id><updated>{util.misc.date_format(datetime.utcnow())}</updated>'
		f'<live:legacyPsm>{message_xml}</live:legacyPsm><title>{message_xml}</title>'
		f'<author><name>{encode_xml_ne(user.status.name)}</name><live:cid>{cid}</live:cid></author></entry>'
	))

def _get_live_api_user(req: web.Request) -> Tuple[models.User, Optional[BackendSession]]:
	backend: Backend = req.app['backend']
	auth = req.headers.get('Authorization') or ''
	token = (auth.split('t=', 1)[1][:20] if 't=' in auth else '')
	bs = backend.util_get_sess_by_token(token)
	user = _get_user_from_token(backend, bs, token)
	if user is None or cid_format(user.uuid, decimal = True) != req.match_info['cid']:
		raise web.HTTPUnauthorized()
	return user, bs

def _set_status_message(backend: Backend, user: models.User, bs: Optional[BackendSession], message: str) -> None:
	activity_added = backend.user_service.save_single_roaming(user, { 'message': message })
	sessions = backend.util_get_sessions_by_user(user)
	if bs is None or bs not in sessions:
		bs = (sessions[0] if sessions else None)
	if bs is not None and message != bs.user.status.message:
		bs.me_update({ 'message': message, 'notify_self': True })
	if activity_added:
		backend.notify_whats_new(user)

async def handle_user_files(req: web.Request) -> web.Response:
	from lxml.etree import fromstring as parse_xml, XMLSyntaxError
	
	backend: Backend = req.app['backend']
	user, _ = _get_live_api_user(req)
	cid = req.match_info['cid']
	
	if not req.content_type.startswith('multipart/'):
		raise web.HTTPUnsupportedMediaType()
	entry = None # type: Optional[Any]
	data = None # type: Optional[bytes]
	try:
		reader = await req.multipart()
		while True:
			part = await reader.next()
			if part is None: break
			body = await _read_part(part, PHOTO_MAX_SIZE)
			if entry is None and 'atom+xml' in (part.headers.get('Content-Type') or ''):
				entry = parse_xml(body)
			elif data is None:
				data = body
	except (ValueError, XMLSyntaxError):
		raise web.HTTPBadRequest()
	if entry is None or not data:
		raise web.HTTPBadRequest()
	ext = get_img_type(data)
	if ext is None:
		raise web.HTTPUnsupportedMediaType()
	
	title = entry.findtext('{http://www.w3.org/2005/Atom}title') or ''
	summary = entry.findtext('{http://www.w3.org/2005/Atom}summary') or ''
	name = await asyncio.get_running_loop().run_in_executor(None, store_photo_file, user.uuid, data, ext)
	media_url = 'https://{}/photos/{}/{}'.format(settings.USERSTORAGE_HOST, user.uuid, name)
	if backend.user_service.add_activity(user, models.ActivityType.Photo, title = title, text = summary, url = media_url):
		backend.notify_whats_new(user)
	
	location = '{}/{}'.format(str(req.url).rstrip('/'), name)
	entry_url = encode_xml_ne(location)
	media_url_xml = encode_xml_ne(media_url)
	mime = 'image/' + ext
	now_str = util.misc.date_format(datetime.utcnow())
	return web.Response(status = 201, content_type = 'application/atom+xml', headers = { 'Location': location }, text = (
		'<?xml version="1.0" encoding="utf-8"?><entry xmlns="http://www.w3.org/2005/Atom" xmlns:live="http://api.live.com/schemas">'
		f'<id>{entry_url}</id><title>{encode_xml_ne(title)}</title><summary>{encode_xml_ne(summary)}</summary>'
		f'<published>{now_str}</published><updated>{now_str}</updated>'
		f'<author><name>{encode_xml_ne(user.status.name or "")}</name><live:cid>{cid}</live:cid></author>'
		f'<link rel="self" type="application/atom+xml" href="{entry_url}"/><link rel="edit" type="application/atom+xml" href="{entry_url}"/>'
		f'<link rel="edit-media" type="{mime}" href="{media_url_xml}"/><link rel="alternate" type="{mime}" href="{media_url_xml}"/>'
		f'<content type="{mime}" src="{media_url_xml}"/><live:type>photo</live:type></entry>'
	))

async def _read_part(part: Any, limit: int) -> bytes:
	chunks = [] # type: List[bytes]
	size = 0
	while True:
		chunk = await part.read_chunk()
		if not chunk: break
		size += len(chunk)
		if size > limit:
			raise web.HTTPRequestEntityTooLarge(max_size = limit, actual_size = size)
		chunks.append(chunk)
	return b''.join(chunks)

async def handle_photo(req: web.Request) -> web.Response:
	# Photos shared as a status, shown in "What's New"
	user_uuid = req.match_info['uuid']
	name = req.match_info['name']
	if not (re.fullmatch(r'[0-9a-f-]{36}', user_uuid) and re.fullmatch(r'[0-9a-f]{16}\.(?:jpeg|png|gif)', name)):
		raise web.HTTPNotFound()
	result = await asyncio.get_running_loop().run_in_executor(None, get_photo_data, user_uuid, name)
	if result is None:
		raise web.HTTPNotFound()
	photo, content_type = result
	return web.Response(body = photo, content_type = content_type)

def _get_user_from_token(backend: Backend, bs: Optional[BackendSession], token: Optional[str]) -> Optional[models.User]:
	# Social services are also used before (or without) a notification server session
	if bs is not None:
		return bs.user
	if not token:
		return None
	tpl = backend.login_auth_service.get_token('ns/login', token)
	if tpl is None:
		return None
	return backend._load_user_record(tpl[0])
 
async def handle_today(req: web.Request) -> web.Response:
	return render(req, 'msn:svcs/MSNToday.html', {
		'title': "CrossTalk Today",
		'msn': req.query.get('msn') or False,
		'wlm': req.query.get('wlm') or False,
		'windowslive': req.query.get('windowslive') or False
	})
 
async def handle_gamebrowser(req: web.Request) -> web.Response:
	return render(req, 'msn:svcs/GameBrowser.html', {
		'title': "Game Browser | CrossTalk",
	})
 
async def handle_portal(req: web.Request) -> web.Response:
	return web.HTTPFound(f'http://{settings.TODAY_HOST}/start/msn')
 
async def handle_textadredir(req: web.Request) -> web.Response:
	return web.HTTPFound(f'http://{settings.AD_HOST}/ads/txt')
 
async def handle_banneradredir(req: web.Request) -> web.Response:
	return web.HTTPFound(f'http://{settings.AD_HOST}/ads/banner')
 
async def handle_msn_redirect(req: web.Request) -> web.Response:
	i = req.match_info['i']
	id = req.match_info['id']
	
	if i == '5':
		if id == '60':
			return web.HTTPFound('/svcs/mms/tabs.asp')
		elif id == '153':
			return web.HTTPFound('/start')
	
	return web.HTTPFound('http://g.msn.com{}'.format(req.path_qs))
 
async def handle_msn5ads(req: web.Request) -> web.Response:
	response = '<?xml version="1.0"?><msn-data><RefreshLogin>False</RefreshLogin><RefreshInterval>10080</RefreshInterval></msn-data>'
	return web.HTTPOk(body=response)
 
async def handle_suiteupdate(req: web.Request) -> web.Response:
	return render(req, 'msn:config/SuiteUpdate.xml')
 
async def handle_socialint(req: web.Request) -> web.Response:
	return render(req, 'msn:config/Config.PSA.xml')
 
async def handle_tabs(req: web.Request) -> web.Response:	
	with open('config/tabs.json') as fh:
		tabs_data = json.load(fh)
 
	tmpl = req.app['jinja_env'].get_template('msn:svcs/svcs_tabs.xml')
	tab_tmpl = tmpl.render(tabs=tabs_data)
 
	return web.HTTPOk(content_type='text/xml', text='<?xml version="1.0"?>\n' + tab_tmpl)
 
# TODO: Unify the tabs handlers so spaghetti code isn't a problem
async def handle_tabs_newer(req: web.Request) -> web.Response:
	id = int(req.match_info['id'])
 
	with open('config/tabs.json') as fh:
		tabs_data = json.load(fh)
 
	tab_data = next((tab for tab in tabs_data if tab["id"] == id), None)
	if not tab_data:
		return web.HTTPNotFound(text="Tab not found")
 
	tmpl = req.app['jinja_env'].get_template('msn:svcs/svcs_tabs_newer.xml')
	tab_tmpl = tmpl.render(tab=tab_data)
 
	return web.HTTPOk(content_type='text/xml', text=tab_tmpl)
 
async def handle_msgrconfig(req: web.Request) -> web.Response:
	if req.method == 'POST':
		body = await req.read() # type: Optional[bytes]
	else:
		body = None
	msgr_config = _get_msgr_config(req, body)
	if msgr_config == 'INVALID_VER':
		return web.Response(status = 500)
	return web.HTTPOk(content_type = 'text/xml', text = msgr_config)
 
MsgrConfigVariant = Literal['msn', 'wlm8', 'wlm14', 'wlm16']

async def handle_msgrconfig16(req: web.Request) -> web.Response:
	return web.HTTPOk(content_type = 'text/xml', text = _render_msgr_config(req, 'wlm16'))

def _get_msgr_config(req: web.Request, body: Optional[bytes]) -> str:
	query = req.query
	ver = query.get('ver') or ''
	
	if ver:
		if re.match(r'[^\d\.]', ver):
			return 'INVALID_VER'
		
		config_ver = ver.split('.', 4)
		if 8 <= int(config_ver[0]) <= 9:
			return _render_msgr_config(req, 'wlm8')
		elif int(config_ver[0]) >= 14:
			return _render_msgr_config(req, 'wlm14')
	elif body is not None:
		# MSN Messenger 6.0 - 7.5 only use the SOAP `GetClientConfig` action
		return _render_msgr_config(req, 'msn', soap = True)
	
	return ''

def _render_msgr_config(req: web.Request, variant: MsgrConfigVariant, *, soap: bool = False) -> str:
	with open('config/tabs.json') as fh:
		tabs_data = json.load(fh)
	tmpl = req.app['jinja_env'].get_template('msn:config/MsgrConfig.xml')
	return tmpl.render(variant = variant, soap = soap, tabs = tabs_data, settings = settings)
 
PassportURLs = 'PassportURLs'
 
async def handle_nexus(req: web.Request) -> web.Response:
	return web.HTTPOk(headers = {
		PassportURLs: 'DALogin=https://{}{}'.format(settings.LOGIN_HOST, LOGIN_PATH),
	})
 
async def handle_login(req: web.Request) -> web.Response:
	tmp = _extract_pp_credentials(req.headers.get('Authorization') or '')
	if tmp is None:
		token = None
	else:
		email, pwd = tmp
		token_tpl = _login(req, email, pwd)
	if token_tpl is None:
		raise web.HTTPUnauthorized(headers={
			'WWW-Authenticate': '{}da-status=failed'.format(PP),
		})
	token, _, _ = token_tpl
	return web.HTTPOk(headers={
		'Authentication-Info': '{}da-status=success,from-PP=\'{}\''.format(PP, token),
	})
 
async def handle_not_rst(req: web.Request) -> web.Response:
	if req.method == 'OPTIONS':
		return web.HTTPOk(headers = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'POST',
			'Access-Control-Allow-Headers': 'X-User, X-Password, Content-Type',
			'Access-Control-Expose-Headers': 'X-Token',
			'Access-Control-Max-Age': str(86400),
		})
	
	email = req.headers.get('X-User') or ''
	pwd = req.headers.get('X-Password') or ''
	token_tpl = _login(req, email, pwd, lifetime = 86400)
	headers = {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'POST',
		'Access-Control-Expose-Headers': 'X-Token',
	}
	if token_tpl is not None:
		token, _, _ = token_tpl
		headers['X-Token'] = token
	return web.HTTPOk(headers = headers)
 
DA_TOKEN_LIFETIME = 86400 * 30

async def handle_rst(req: web.Request, rst2: bool = False) -> web.Response:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	try:
		root = parse_xml(body)
	except:
		return render(req, 'msn:RST/{}.error.xml'.format('RST2' if rst2 else 'RST'))
	
	backend: Backend = req.app['backend']
	
	email = find_element(root, 'Username')
	pwd = str(find_element(root, 'Password'))
	# Saved passwords: IDCRL signs in with the `http://Passport.NET/tb` token (`BinaryDAToken0`) from its last sign-in
	# instead of a username and password
	da_token = find_element(root, 'Security/EncryptedData/CipherData/CipherValue')
	
	if email is not None:
		token_tpl = _login(req, email, pwd, binary_secret = True, lifetime = 86400)
		uuid = backend.util_get_uuid_from_email(email)
	elif da_token is not None:
		uuid = _get_uuid_from_da_token(backend, str(da_token))
		token_tpl = None
		if uuid is not None:
			user = backend._load_user_record(uuid)
			if user is not None:
				email = user.email
				token_tpl = _create_login_token(backend, uuid, binary_secret = True, lifetime = 86400)
	else:
		return render(req, 'msn:RST/{}.error.xml'.format('RST2' if rst2 else 'RST'))
	
	if token_tpl is not None and uuid is not None:
		token, expiry, bsecret = token_tpl
		day_before_expiry = expiry - timedelta(days = 1)
		timez = util.misc.date_format(day_before_expiry)
		tomorrowz = util.misc.date_format(expiry)
		time_5mz = util.misc.date_format((day_before_expiry + timedelta(minutes = 5)))
		
		# load PUID and CID
		cid = cid_format(uuid)
		puid = puid_format(uuid)
		
		# The client stores this and sends it back to sign in again without the password
		da_token_new, _ = backend.login_auth_service.create_token('rst/da', [uuid], lifetime = DA_TOKEN_LIFETIME)
		datoken = base64.b64encode(da_token_new.encode('ascii')).decode('ascii')
		dabinarysecret = base64.b64encode(secrets.token_bytes(24)).decode('ascii')
		
		assert req.transport is not None
		peername = req.transport.get_extra_info('peername')
		if peername:
			host = peername[0]
		else:
			host = '127.0.0.1'
		
		# get list of requested domains
		domains = root.findall('.//{*}Address')
		
		tmpl = req.app['jinja_env'].get_template('msn:RST/{}.token.xml'.format('RST2' if rst2 else 'RST'))
		# collect tokens for requested domains, ignore Passport token request
		tokenxmls = [tmpl.render(
			i = i + 1,
			domain = domain,
			timez = timez,
			tomorrowz = tomorrowz,
			pptoken1 = token,
			binarysecret = bsecret,
		) for i, domain in enumerate(domains) if domain != 'http://Passport.NET/tb']
		
		tmpl = req.app['jinja_env'].get_template('msn:RST/{}.xml'.format('RST2' if rst2 else 'RST'))
		return web.HTTPOk(
			content_type = 'text/xml',
			text = (tmpl.render(
				puidhex = puid,
				time_5mz = time_5mz,
				timez = timez,
				tomorrowz = tomorrowz,
				cid = cid,
				email = email,
				firstname = "John",
				lastname = "Doe",
				ip = req.headers.get('X-Forwarded-For', req.remote),
				pptoken1 = token,
				datoken = datoken,
				dabinarysecret = dabinarysecret,
				tokenxml = Markup(''.join(tokenxmls)),
			) if rst2 else tmpl.render(
				puidhex = puid,
				timez = timez,
				tomorrowz = tomorrowz,
				cid = cid,
				email = email,
				firstname = "John",
				lastname = "Doe",
				ip = req.headers.get('X-Forwarded-For', req.remote),
				pptoken1 = token,
				datoken = datoken,
				dabinarysecret = dabinarysecret,
				tokenxml = Markup(''.join(tokenxmls)),
			)),
		)
	
	return render(req, 'msn:RST/{}.authfailed.xml'.format('RST2' if rst2 else 'RST'), {
		'timez': util.misc.date_format(datetime.utcnow()),
	})
 
async def handle_videofeed(req: web.Request, get_videos: bool = False) -> web.Response:
	if not get_videos:
		return render(req, 'msn:svcs/videofeedroot.xml')
	else:
		with open('config/videos.json', 'rb') as f:
			vid_data = json.load(f)
		rss_items = []
		for video in vid_data:
			try:
				pub_date = parsedate_to_datetime(video['publish_date'])
			except Exception:
				pub_date = datetime.now()
			item = PyRSS2Gen.RSSItem(
				title=video['title'],
				link=video['link'],
				description=video['description'],
				guid=PyRSS2Gen.Guid(video['link'], isPermaLink=True),
				pubDate=pub_date,
				enclosure=PyRSS2Gen.Enclosure(
					url=video['thumbnail'],
					length="1",
					type="image/jpeg"
				)
			)
			rss_items.append(item)
		rss_feed = PyRSS2Gen.RSS2(
			title="CrossTalk",
			link="http://crosstalk.im",
			description="CrossTalk Videos",
			language="en-us",
			lastBuildDate=datetime.now(),
			ttl=10,
			copyright="&copy; 2023 - 2026 hiden",
			image=PyRSS2Gen.Image(
				url="https://static.ugnet.xyz/svc/ct/logo/shadow.svg",
				title="CrossTalk Videos",
				link="https://crosstalk.im"
			),
			items=rss_items
		)
 
		rss_xml = rss_feed.to_xml(encoding="utf-8")
		return web.HTTPOk(content_type="text/xml", text=rss_xml)
 
def _extract_pp_credentials(auth_str: str) -> Optional[Tuple[str, str]]:
	if not auth_str:
		return None
	assert auth_str.startswith(PP)
	auth = {}
	for part in auth_str[len(PP):].split(','):
		parts = part.split('=', 1)
		if len(parts) == 2:
			auth[unquote(parts[0])] = unquote(parts[1])
	email = auth['sign-in']
	pwd = auth['pwd']
	return email, pwd
 
def _login(req: web.Request, email: str, pwd: str, binary_secret: bool = False, lifetime: int = 30) -> Optional[Tuple[str, datetime, Optional[str]]]:
	backend: Backend = req.app['backend']
	uuid = backend.user_service.login(email, pwd)
	if uuid is None and email.lower().endswith('@crosstalk.im'):
		username = email.lower()[:-len('@crosstalk.im')]
		uuid = backend.user_service.login_with_username(username, pwd)
	if uuid is None: return None
	return _create_login_token(backend, uuid, binary_secret = binary_secret, lifetime = lifetime)

def _create_login_token(backend: Backend, uuid: str, *, binary_secret: bool = False, lifetime: int = 30) -> Tuple[str, datetime, Optional[str]]:
	bsecret = None
	if binary_secret:
		bsecret = base64.b64encode(secrets.token_bytes(24)).decode('ascii')
	return (*backend.login_auth_service.create_token('ns/login', [uuid, bsecret], lifetime = lifetime), bsecret)

def _get_uuid_from_da_token(backend: Backend, cipher_value: str) -> Optional[str]:
	try:
		token = base64.b64decode(cipher_value).decode('ascii')
	except (ValueError, UnicodeDecodeError):
		return None
	tpl = backend.login_auth_service.get_token('rst/da', token)
	if tpl is None: return None
	return tpl[0]
 
def _contact_is_favorite(user_detail: models.UserDetail, ctc: models.Contact) -> bool:
	groups = user_detail._groups_by_uuid
	for group in ctc._groups.copy():
		if group.id not in groups: continue
		if groups[group.id].is_favorite: return True
	return False