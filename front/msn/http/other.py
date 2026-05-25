from typing import Optional, Any, Tuple
from datetime import datetime, timedelta
from io import BytesIO
from email.parser import Parser
from email.header import decode_header
from email.utils import parsedate_to_datetime
from urllib.parse import unquote, parse_qsl
from pathlib import Path
import re, secrets, base64, random, json, mimetypes, uuid, PyRSS2Gen, settings, util.misc
from markupsafe import Markup
from aiohttp import web

from core import models
from core.backend import Backend, BackendSession
from util.avatar import get_img_type, find_avatar_file
from ..misc import gen_mail_data, format_oim, cid_format, puid_format
from .util import find_element, get_tag_localname, render, preprocess_soap, unknown_soap, bool_to_str

LOGIN_PATH = '/login.srf'
TMPL_DIR = 'front/msn/http/tmpl'
ETC_DIR = 'front/msn/etc'
PP = 'Passport1.4'

def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'msn', TMPL_DIR, globals = {
		'date_format': util.misc.date_format,
		'cid_format': cid_format,
		'puid_format': puid_format,
		'bool_to_str': bool_to_str,
		'contact_is_favorite': _contact_is_favorite,
		'datetime': datetime,
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
	app.router.add_post('/storageservice/SchematizedStore.asmx', handle_storageservice)
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
	app.router.add_post('/profile/profile.asmx', handle_blankok) # TODO: do the thing
	app.router.add_get(r'/~Live.ConfigServer/{junk:.*}/~op-GetClientConfig/{tail:.*}', handle_msgrconfig16)
	app.router.add_get(r'/~Live.ConfigServer.SuiteUpdate/{tail:.*}', handle_suiteupdate)
	app.router.add_get(r'/~Live.ConfigServer.PSA/{tail:.*}', handle_socialint)
	app.router.add_get('/svcs/GameBrowser', handle_gamebrowser)

	# Misc
	app.router.add_get('/{i}meen_{locale}/{id}', handle_msn_redirect)

async def handle_blankok(req: web.Request) -> web.Response:
	return web.Response(status = 200)

async def handle_storageservice(req: web.Request) -> web.Response:
	backend = req.app['backend']
	header, action, bs, token = await preprocess_soap(req)
	assert bs is not None
	soapaction = (req.headers.get('SOAPAction') or '')
	if soapaction.startswith('"') and soapaction.endswith('"'):
		soapaction = soapaction[1:-1]
	storage_ns = ('w10' if soapaction.startswith('http://www.msn.com/webservices/storage/w10/') else '2008')
	action_str = get_tag_localname(action)
	now_str = util.misc.date_format(datetime.utcnow())
	user = bs.user
	cachekey = secrets.token_urlsafe(172)
	
	cid = cid_format(user.uuid)
	
	if action_str == 'GetProfile':
		roaming_info = backend.user_service.get_roaming_info(user)
		assert roaming_info is not None

		# Resolve the active avatar using the md5 stored in users.avatar.
		# find_avatar_file returns None if no avatar has been uploaded yet.
		avatar_md5 = user.avatar
		mime		= None
		image_size  = 0
		image_thumb_size = 0

		if avatar_md5:
			full_file  = find_avatar_file(user.uuid, avatar_md5, small=False)
			thumb_file = find_avatar_file(user.uuid, avatar_md5, small=True)

			if full_file and full_file.is_file():
				ext  = full_file.suffix.lstrip('.').lower()
				mime = ext
				image_size = full_file.stat().st_size

			if thumb_file and thumb_file.is_file():
				image_thumb_size = thumb_file.stat().st_size

		return render(req, 'msn:storageservice/GetProfileResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
			'now': now_str,
			'mime': mime,
			'size_static': image_size,
			'size_small': image_thumb_size,
			'roaming_info': roaming_info,
			'host': settings.USERSTORAGE_HOST,
		})
	if action_str == 'FindDocuments':
		# TODO: FindDocuments
		return render(req, 'msn:storageservice/FindDocumentsResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
		})
	if action_str == 'UpdateProfile':
		delete_psm = False
		delete_name = False
		delete_avatar = False
		
		# TODO: More properties?
		
		# Update to roaming name/message
		# ```
		# <UpdateProfile xmlns="http://www.msn.com/webservices/storage/w10">
		#   <profile>
		#	 <ResourceID>862d987eb60b7a63!106</ResourceID>
		#	 <ExpressionProfile>
		#	   <FreeText>Update</FreeText>
		#	   <DisplayName>Society is betrayal</DisplayName>
		#	   <PersonalStatus>Prosperity is the best medicine. :)</PersonalStatus>
		#	 </ExpressionProfile>
		#   </profile>
		# </UpdateProfile>
		# ```
		
		# Remove roaming message
		# ```
		# <UpdateProfile xmlns="http://www.msn.com/webservices/storage/w10">
		#   <profile>
		#	 <ResourceID>bb4542ce2eacdbde!106</ResourceID>
		#	 <ExpressionProfile>
		#	   <FreeText>Update</FreeText>
		#	   <DisplayName>%walkingphas3r%</DisplayName>
		#	   <Flags>0</Flags>
		#	 </ExpressionProfile>
		#   </profile>
		#   <profileAttributesToDelete>
		#	 <ExpressionProfileAttributes>
		#	   <PersonalStatus>true</PersonalStatus>
		#	 </ExpressionProfileAttributes>
		#   </profileAttributesToDelete>
		# </UpdateProfile>
		# ```
		
		expression_profile = find_element(action, 'ExpressionProfile')
		name = find_element(expression_profile, 'DisplayName')
		message = find_element(expression_profile, 'PersonalStatus')
		
		attributes_to_delete = find_element(action, 'profileAttributesToDelete/ExpressionProfileAttributes')
		if attributes_to_delete is not None:
			# `PersonalStatus` and `DisplayName` is the only known attribute that has the ability to be deleted
			delete_psm = find_element(attributes_to_delete, 'PersonalStatus') or False
			assert isinstance(delete_psm, bool)
			delete_name = find_element(attributes_to_delete, 'DisplayName') or False
			assert isinstance(delete_name, bool)
		
		name = find_element(action, 'DisplayName')
		message = find_element(action, 'PersonalStatus')
		
		if name:
			backend.user_service.save_single_roaming(user, { 'name': name })
		if message and not delete_psm:
			backend.user_service.save_single_roaming(user, { 'message': message })
		
		if delete_psm:
			backend.user_service.save_single_roaming(user, { 'message': '' })
		if delete_name:
			backend.user_service.save_single_roaming(user, { 'name': '' })
		
		return render(req, 'msn:storageservice/UpdateProfileResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user
		})
	if action_str == 'DeleteRelationships':
		# TODO: DeleteRelationships
		return render(req, 'msn:storageservice/DeleteRelationshipsResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
		})
	if action_str in ('CreateDocument', 'UpdateDocument'):
		op = 'Update' if action_str == 'UpdateDocument' else 'Create'
		return handle_document(req, action, op, storage_ns, user, cid, token, backend)
	if action_str == 'CreateRelationships':
		# TODO: CreateRelationships
		return render(req, 'msn:storageservice/CreateRelationshipsResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
		})
	if action_str in { 'ShareItem' }:
		# TODO: ShareItem
		return unknown_soap(req, header, action, expected = True)
	return unknown_soap(req, header, action)


def handle_document(
	req: web.Request,
	action: Any,
	op_type: str,		  # 'Create' or 'Update'
	storage_ns: str,
	user: models.User,
	cid: str,
	token: str,
	backend: Backend,
) -> web.Response:
	streamtype = find_element(action, 'DocumentStreamType')

	if streamtype == 'UserTileStatic':
		raw_b64 = find_element(action, 'Data')
		if raw_b64:
			try:
				data = base64.b64decode(raw_b64)
			except Exception:
				return web.HTTPInternalServerError(text='')

			err = _store_avatar_from_bytes(backend, user, data)
			if err is not None:
				return err

	return render(req, 'msn:storageservice/{}DocumentResponse.xml'.format(op_type), {
		'storage_ns': storage_ns,
		'cid': cid,
		'pptoken1': token,
		'user': user,
	})


def _store_avatar_from_bytes(
	backend: Backend,
	user: models.User,
	data: bytes,
) -> Optional[web.Response]:
	ext = get_img_type(data)
	if ext is None:
		return web.HTTPInternalServerError(text='AZUL: Unsupported image format')

	try:
		backend.user_service.save_avatar(user, data, ext)
	except Exception:
		return web.HTTPInternalServerError(text='')

	return None


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

# TODO: Make this actually accurate
async def handle_whatsnew(req: web.Request) -> web.Response:
	whatsnew = ''
	with open('config/whatsnew.json', 'rb') as f:
		whatsnew_list = json.loads(f.read()) 
		f.close()
	
	if len(whatsnew_list) > 0:
		whatsnew_dict = whatsnew_list[0]
		with open(TMPL_DIR + '/whatsnew/WhatsNewResponse.xml') as fh:
			whatsnew = fh.read()
		whatsnew = whatsnew.format(
			date=whatsnew_dict['date'],
			url=whatsnew_dict['url'],
			title=whatsnew_dict['title'],
			appName=whatsnew_dict['appName'],
			content=whatsnew_dict['content']
		)
	
	return web.HTTPOk(content_type = 'text/xml', text = whatsnew)

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
	return web.HTTPFound(f'http://{settings.TODAY_HOSTs}/start/msn')

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

async def handle_msgrconfig16(req: web.Request) -> web.Response:
	body = await req.read()
	msgr_config = _get_msgr_config_16(req, body)
	return web.HTTPOk(content_type = 'text/xml', text = msgr_config)

def _get_msgr_config(req: web.Request, body: Optional[bytes]) -> str:
	query = req.query
	result = None # type: Optional[str]
	ver = query.get('ver') or ''
	
	if ver:
		if re.match(r'[^\d\.]', ver):
			return 'INVALID_VER'
		
		config_ver = ver.split('.', 4)
		if 8 <= int(config_ver[0]) <= 9:
			with open(TMPL_DIR + '/config/MsgrConfig.wlm.8.xml') as fh:
				config = fh.read()
			with open('config/tabs.json') as fh:
				with open(TMPL_DIR + '/svcs/svcs_tabs.xml') as th:
					template = th.read()
				tabs_data = json.load(fh)
				tmpl_before = req.app['jinja_env'].from_string(template)
				tab_tmpl = tmpl_before.render(tabs=tabs_data, settings=settings)
			result = config.format(tabs = tab_tmpl)
		elif int(config_ver[0]) >= 14:
			with open(TMPL_DIR + '/config/MsgrConfig.wlm.14.xml') as fh:
				template = fh.read()
			with open('config/tabs.json') as fh:
				tabs_data = json.load(fh)
				tmpl_before = req.app['jinja_env'].from_string(template)
				tmpl = tmpl_before.render(tabs=tabs_data, settings=settings)
				result = tmpl
	elif body is not None:
		with open(TMPL_DIR + '/config/MsgrConfig.msn.envelope.xml') as fh:
			envelope = fh.read()
		with open(TMPL_DIR + '/config/MsgrConfig.msn.xml') as fh:
			config = fh.read()
		with open('config/tabs.json') as fh:
			with open(TMPL_DIR + '/svcs/svcs_tabs.xml') as th:
				template = th.read()
			tabs_data = json.load(fh)
			tmpl_before = req.app['jinja_env'].from_string(template)
			tab_tmpl = tmpl_before.render(tabs=tabs_data)
		result = envelope.format(MsgrConfig = config.format(tabs = tab_tmpl, settings = settings))
	
	return result or ''

def _get_msgr_config_16(req: web.Request, body: Optional[bytes]) -> str:
	with open(TMPL_DIR + '/config/MsgrConfig.wlm.16.xml') as fh:
		template = fh.read()
	with open('config/tabs.json') as fh:
		tabs_data = json.load(fh)
	tmpl_before = req.app['jinja_env'].from_string(template)
	tmpl = tmpl_before.render(tabs=tabs_data, settings=settings)
	result = tmpl

	return result or ''

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

async def handle_rst(req: web.Request, rst2: bool = False) -> web.Response:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	try:
		root = parse_xml(body)
	except:
		return render(req, 'msn:RST/{}.error.xml'.format('RST2' if rst2 else 'RST'))
	
	email = find_element(root, 'Username')
	pwd = str(find_element(root, 'Password'))

	if email is None or pwd is None:
		return render(req, 'msn:RST/{}.error.xml'.format('RST2' if rst2 else 'RST'))
	
	backend: Backend = req.app['backend']
	
	token_tpl = _login(req, email, pwd, binary_secret = True, lifetime = 86400)
	
	uuid = backend.util_get_uuid_from_email(email)
	
	if token_tpl is not None and uuid is not None:
		token, expiry, bsecret = token_tpl
		day_before_expiry = expiry - timedelta(days = 1)
		timez = util.misc.date_format(day_before_expiry)
		tomorrowz = util.misc.date_format(expiry)
		time_5mz = util.misc.date_format((day_before_expiry + timedelta(minutes = 5)))
		
		# load PUID and CID
		cid = cid_format(uuid)
		puid = puid_format(uuid)
		
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
			copyright="&copy; 2023 - 2025 the undergr0und",
			image=PyRSS2Gen.Image(
				url="http://hiden.cc/static/icon/misc/hidnet.png",
				title="CrossTalk Video - InDev",
				link="http://crosstalk.im"
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
	bsecret = None
	if binary_secret:
		bsecret = base64.b64encode(secrets.token_bytes(24)).decode('ascii')
	return (*backend.login_auth_service.create_token('ns/login', [uuid, bsecret], lifetime = lifetime), bsecret)

def _contact_is_favorite(user_detail: models.UserDetail, ctc: models.Contact) -> bool:
	groups = user_detail._groups_by_uuid
	for group in ctc._groups.copy():
		if group.id not in groups: continue
		if groups[group.id].is_favorite: return True
	return False