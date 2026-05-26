import asyncio, secrets, ssl, jinja2, json, mimetypes, random, base64, settings, util.misc
from typing import Any, Dict, Optional
from aiohttp import web, ClientSession, ClientTimeout, ClientError
from pathlib import Path

from util.misc import AIOHTTPRunner, _get_avatar_path
from core.backend import Backend

from brutus import Brutus

MISC_TMPL_DIR = "core/tmpl/misc/"
AD_TMPL_DIR = "core/tmpl/ads"

def register(loop: asyncio.AbstractEventLoop, backend: Backend, *, devmode: bool = False) -> web.Application:		
	ssl_context: Optional[ssl.SSLContext]
	http_host = '0.0.0.0'
	http_port = settings.HTTP_PORT
	if devmode:
		ssl_context = Brutus('CrossTalk').create_ssl_context()
	else:
		ssl_context = None
	
	app = create_app(loop, backend)
	backend.add_runner(AIOHTTPRunner(http_host, http_port, app, ssl_context=ssl_context, service='HTTP'))
	app.router.add_get('/', handle_misc_conns)
	app.router.add_post('/', handle_blankok)
	app.router.add_static('/static', 'core/static')
	app.router.add_get('/ads/txt', handle_textad)
	app.router.add_get('/ads/banner', handle_bannerad)
	app.router.add_get('/ads/banner-lg', lambda req: handle_bannerad(req, yuge=True))
	app.router.add_get('/ads/banner-sq', lambda req: handle_bannerad(req, sq = True))
	app.router.add_get('/ads/GetMSNAdImage.asmx', handle_msnbannerimg)
	app.router.add_get('/svcs/mms/adxml_main.asp', lambda req: handle_bannerad(req, msnxml=True))
	app.router.add_get('/avatar/{uuid}/static', handle_avatar)
	app.router.add_get('/avatar/{uuid}/small', lambda req: handle_avatar(req, small = True))
	app.router.add_route('*', '/{path:.*}', handle_notfound)
 
	return app

def create_app(loop: asyncio.AbstractEventLoop, backend: Backend) -> Any:
	app = web.Application(loop=loop)
	app['backend'] = backend
	app['jinja_env'] = jinja2.Environment(
		loader=jinja2.PrefixLoader({}, delimiter=':'),
		autoescape=jinja2.select_autoescape(default=False),
	)
	
	app.on_response_prepare.append(on_response_prepare)

	util.misc.add_to_jinja_env(app, 'misc', MISC_TMPL_DIR)
	
	return app

async def on_response_prepare(req: web.Request, res: web.StreamResponse) -> None:
	res.headers['X-Azul-Version'] = settings.VERSION 

	if not settings.DEBUG:
		return
	if settings.DEBUG:
		ip_address = req.headers.get('X-Forwarded-For', req.remote)
		print("[HTTP] <Debug> (IP: {}) [Client] {} {}://{}{}".format(
			ip_address, req.method, req.scheme, req.host, req.path_qs))
		if settings.DEBUG_FULL:
			for header, value in req.headers.items():
				print(f"{header}: {value}")
			body = await req.read()
			if body:
				print(body.decode('utf-8', errors='replace'))

		print(f"\n[HTTP] <Debug> (IP: {ip_address}) [Server]: {res.status} {res.reason}")
		if settings.DEBUG_FULL:
			for header, value in res.headers.items():
				print(f"{header}: {value}")
			if isinstance(res, web.Response):
				if res.body:
					print(res.body.decode(res.charset or 'utf-8', errors='replace'))
			
async def handle_misc_conns(req: web.Request) -> web.Response:
	return render(req, 'misc:miscconns.html', {
		'settings': settings
	}, status=400)

async def handle_notfound(req: web.Request) -> web.Response:
	return render(req, 'misc:miscconns.html', {
		'settings': settings
	}, status=404)
	
async def handle_bannerad(req: web.Request, yuge: bool = False, sq: bool = False, msnxml: bool = False) -> web.Response:
	with open('config/big-bannerimages.json' if yuge else 'config/sq-bannerimages.json' if sq else 'config/bannerimages.json', 'r') as json_file:
		data = json.load(json_file)
		random_entry = random.choice(data)
		image_path = f"core/{random_entry['image']}"
		image_link = random_entry['link']
		id = random_entry['id']
		urlparams = req.rel_url.query
		version = urlparams.get('Version')

	content_type, _ = mimetypes.guess_type(image_path)
	headers = {
		'Content-Type': 'text/xml' if msnxml else 'text/html',
	}
		
	html_response = f'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd"><html style="-ms-overflow-style: none;"><body style="-ms-overflow-style: none;overflow: hidden;padding:0;margin:0;overflow:hidden;-ms-scroll-limit: 0 0 0 0;" scroll=no><a href="{image_link}" style="text-decoration:none;" target="_blank"><img border="0" src="http://static.ugnet.gay/svc/ads/ct/{random_entry["image"]}"></a></body></html>'
	msn_response = f'<?xml version="1.0"?><ADRSP V="{version}"><image IMG="http://ctsvcs.advertising.ugnet.gay/ads/GetMSNAdImage.asmx?id={id}" ALT="Advertisement" HEIGHT="60" WIDTH="234"/><click CLK="{image_link}" TARGET="_NEW"/></ADRSP>'
	return web.HTTPOk(body=msn_response if msnxml else html_response, headers=headers)

async def handle_msnbannerimg(req: web.Request) -> web.Response:
	with open("config/bannerimages.json", "r", encoding="utf-8") as f:
		data = json.load(f)

	id_in_url = req.rel_url.query.get("id")
	entry = None
	if id_in_url is not None:
		wanted = int(id_in_url)
		for e in data:
			if e.get("id") == wanted:
				entry = e
				break
	else:
		entry = random.choice(data)

	image_url = f"http://static.ugnet.gay/svc/ads/ct/{entry['image']}"

	async with ClientSession() as sess:
		async with sess.get(image_url) as resp:
			body = await resp.read()
			content_type = resp.headers.get("Content-Type")

	if not content_type:
		content_type = mimetypes.guess_type(entry["image"])[0] or "application/octet-stream"

	return web.Response(body=body, content_type=content_type)

async def handle_textad(req: web.Request) -> web.Response:
	textad = ''
	# Use 'rb' to make UTF-8 text load properly
	with open('config/textads.json', 'rb') as f:
		textads = json.loads(f.read())
		f.close()
	
	if len(textads) > 0:
		if len(textads) > 1:
			ad = textads[secrets.randbelow(len(textads))]
		else:
			ad = textads[0]
		with open(AD_TMPL_DIR + '/text-msn.xml') as fh:
			textad = fh.read()
		textad = textad.format(caption=ad['caption'], url=ad['url'])
	return web.HTTPOk(content_type='text/xml', text=textad)

async def handle_blankok(req: web.Request) -> web.Response:
	# MSN counts the login server as a "key port" by POSTing to the root of the server with no content.
	return web.Response(status = 200)
	
async def handle_avatar(req: web.Request, small: bool = False) -> web.Response:
	uuid = req.match_info['uuid']
	storage_path: Path = _get_avatar_path(uuid)

	if not (storage_path.exists() and storage_path.is_dir()):
		return await _get_default_avatar(small)
	else:
		chosen: Path | None = None
		for p in storage_path.iterdir():
			if not p.is_file():
				continue
			if not p.name.startswith(uuid):
				continue
			has_thumb = "_thumb" in p.stem
			if has_thumb == small:
				chosen = p
				break

		if chosen is None:
			for p in storage_path.iterdir():
				if p.is_file() and p.name.startswith(uuid):
					chosen = p
					break

		if chosen is not None and chosen.exists():
			try:
				data = chosen.read_bytes()
				if not data:
					chosen = None
				else:
					ext = chosen.suffix.lstrip(".").lower() or "png"
					content_type = f"image/{ext}"
					return web.Response(status=200, body=data, content_type=content_type)
			except (PermissionError, IsADirectoryError, OSError):
				chosen = None

		return await _get_default_avatar(small)

async def _get_default_avatar(small: bool) -> web.Response:
	default_url = "https://static.ugnet.gay/svc/userstore/avatar/default-sm.png" if small else "https://static.ugnet.gay/svc/userstore/avatar/default.png"
	timeout = ClientTimeout(total=5)
	try:
		async with ClientSession(timeout=timeout) as session:
			async with session.get(default_url) as resp:
				if resp.status != 200:
					raise web.HTTPNotFound()
				data = await resp.read()
				content_type = resp.headers.get("Content-Type", "image/png")
				return web.Response(status=200, body=data, content_type=content_type)
	except ClientError:
		raise

def render(req: web.Request, tmpl_name: str, ctxt: Optional[Dict[str, Any]] = None, status: int = 200) -> web.Response:
	if tmpl_name.endswith('.xml'):
		content_type = 'text/xml'
	else:
		content_type = 'text/html'
	tmpl = req.app['jinja_env'].get_template(tmpl_name)
	content = tmpl.render(**(ctxt or {}))
	return web.Response(status=status, content_type=content_type, text=content)
