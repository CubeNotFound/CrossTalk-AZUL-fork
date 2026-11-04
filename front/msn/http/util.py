from typing import Optional, Dict, Any, Tuple

from aiohttp import web
import lxml, settings

from core.backend import Backend, BackendSession

def render(req: web.Request, tmpl_name: str, ctxt: Optional[Dict[str, Any]] = None, status: int = 200) -> web.Response:
	if tmpl_name.endswith('.xml'):
		content_type = 'text/xml'
	else:
		content_type = 'text/html'
	tmpl = req.app['jinja_env'].get_template(tmpl_name)
	content = tmpl.render(**(ctxt or {}))
	return web.Response(status = status, content_type = content_type, text = content)

async def preprocess_soap(req: web.Request) -> Tuple[Any, Any, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	mspauth = False
	
	body = await req.read()
	root = parse_xml(body[:body.rfind(b'>') + 1])
	
	token = find_element(root, 'TicketToken')
	if token is None:
		token = req.cookies.get('MSPAuth')
		if token is None:
			token = parse_cookies(req.headers.get('Cookie')).get('MSPAuth')
			if token is None:
				token = req.cookies.get('Authorization')
		if token is not None:
			mspauth = True
	if token is None:
		raise web.HTTPInternalServerError()
		
	if token[0:2] == 't=':
		token = token[2:22]
	elif mspauth:
		token = token[0:20]
	
	backend: Backend = req.app['backend']
	backend_sess = backend.util_get_sess_by_token(token)
	
	header = find_element(root, 'Header')
	action = find_element(root, 'Body/*[1]')
	if settings.DEBUG: print('Action: {}'.format(get_tag_localname(action)))
	
	return header, action, backend_sess, token

# What the Address Book and Contact Sharing services say for each of their error codes (`<errorcode>` in a fault's `<detail>`)
ABCH_FAULT_STRINGS = {
	'ABAlreadyExists': 'Address Book Already Exists ',
	'ABDoesNotExist': 'Address Book Does Not Exist ',
	'BadArgumentLength': 'Argument Exceeded Allowed Length',
	'BadEmailArgument': 'Malformed email Argument',
	'ContactAlreadyExists': 'Contact Already Exists ',
	'ContactDoesNotExist': 'Contact Does Not Exist ',
	'DynamicItemDoesNotExist': 'Dynamic Item Does Not Exist ',
	'EmailDomainIsFederated': 'Email Domain Is Federated ',
	'FullSyncRequired': 'Full sync required.  Details: Delta syncs disabled.',
	'GroupAlreadyExists': 'Group Already Exists ',
	'GroupDoesNotExist': 'Group Does Not Exist ',
	'InvalidPassportUser': 'The Passport user specified is invalid',
	'InvalidSyncTimeStamp': 'Invalid Sync Time Stamp ',
	'MemberAlreadyExists': 'Member already exists ',
	'MemberDoesNotExist': 'Member does not exist ',
	'PassportAuthFail': 'Passport Authentication Failed ',
	'RequestLimitReached': 'Request Limit Reached ',
	'SecureConnectionRequired': 'Secure Connection Required ',
	'UserDoesNotExist': 'User does not exist ',
}

# The same for the Schematized Storage service
STORAGE_FAULT_STRINGS = {
	'AccessDenied': 'Access Denied ',
	'GeneralException': 'General Exception ',
	'ItemAlreadyExists': 'Item Already Exists ',
	'ItemDoesNotExist': 'Item Does Not Exist ',
	'InvalidObjectHandle': 'Invalid Object Handle ',
	'InvalidDocumentStream': 'Invalid Document Stream ',
}

def abch_fault(
	req: web.Request, action_str: str, errorcode: str, *, errorstring: Optional[str] = None, faultcode: str = 'soap:Client',
	parameter_fault: Optional[str] = None, conflict_object_id: Optional[str] = None,
) -> web.Response:
	# An Address Book or Contact Sharing service fault (`errorcode` is one of `ABCH_FAULT_STRINGS`)
	return render(req, 'msn:abservice/Fault.abch.xml', {
		'action_str': action_str, 'faultcode': faultcode, 'errorcode': errorcode,
		'errorstring': (errorstring or ABCH_FAULT_STRINGS.get(errorcode) or errorcode), 'parameter_fault': parameter_fault,
		'conflict_object_id': conflict_object_id,
	}, status = 500)

def storage_fault(req: web.Request, storage_ns: str, action_str: str, errorcode: str, *, errorstring: Optional[str] = None) -> web.Response:
	# A Schematized Storage service fault (`errorcode` is one of `STORAGE_FAULT_STRINGS`)
	return render(req, 'msn:storageservice/Fault.storage.xml', {
		'storage_ns': storage_ns, 'action_str': action_str, 'errorcode': errorcode,
		'errorstring': (errorstring or STORAGE_FAULT_STRINGS.get(errorcode) or errorcode),
	}, status = 500)

def schema_fault(req: web.Request, actor: str, faultstring: Optional[str] = None) -> web.Response:
	# A request that's missing something, or has something that isn't allowed where it is (or `faultstring`, for a request
	# that's fine but can't be done)
	return render(req, 'msn:Fault.schema.xml', { 'actor': actor, 'faultstring': faultstring }, status = 500)

def server_fault(req: web.Request, actor: Optional[str] = None) -> web.Response:
	# Something went wrong handling the request; what it was stays in the server's log
	return render(req, 'msn:Fault.server.xml', { 'actor': actor }, status = 500)

def get_tag_localname(elm: Any) -> str:
	return lxml.etree.QName(elm.tag).localname

def find_element(xml: Any, query: str) -> Any:
	thing = xml.find('.//{*}' + query.replace('/', '/{*}'))
	if isinstance(thing, lxml.objectify.StringElement):
		thing = str(thing)
	elif isinstance(thing, lxml.objectify.BoolElement):
		thing = bool(thing)
	return thing

def unknown_soap(req: web.Request, header: Any, action: Any, *, expected: bool = False) -> web.Response:
	action_str = get_tag_localname(action)
	if not expected and settings.DEBUG:
		print("Unknown SOAP:", action_str)
		print(xml_to_string(header))
		print(xml_to_string(action))
	return render(req, 'msn:Fault.unsupported.xml' if expected else 'msn:Fault.doesnotexist.xml', { 'action': action_str })

def xml_to_string(xml: Any) -> str:
	return lxml.etree.tostring(xml, pretty_print = True).decode('utf-8')

def bool_to_str(b: bool) -> str:
	return 'true' if b else 'false'

def parse_cookies(cookie_string: Optional[str]) -> Dict[str, Any]:
	cookie_dict = {}
	cookie_data = None
	
	if not cookie_string:
		return {}
	
	cookies = cookie_string.split(';')
	
	for cookie in cookies:
		if not cookie: continue
		cookie_kv = cookie.split('=', 1)
		if len(cookie_kv) == 2:
			cookie_data = cookie_kv[1]
		cookie_dict[cookie_kv[0]] = cookie_data
	
	return cookie_dict

async def dispatch_abch(req: web.Request, module: Any, prefix: str) -> web.Response:
	header, action, bs, _ = await preprocess_soap(req)
	if bs is None:
		raise web.HTTPForbidden()
	action_str = get_tag_localname(action)
	if find_element(action, 'deltasOnly') or find_element(action, 'DeltasOnly'):
		return render(req, 'msn:abservice/Fault.fullsync.xml', { 'faultactor': action_str })
	
	if settings.DEBUG_FULL:
		print(xml_to_string(action))
	
	method = getattr(module, prefix + '_' + action_str, None)
	if not method:
		return unknown_soap(req, header, action)
	
	try:
		return method(req, header, action, bs)
	except:
		import traceback
		# The traceback goes to the log, not to the client
		traceback.print_exc()
		return server_fault(req, 'http://www.msn.com/webservices/AddressBook/{}'.format(action_str))