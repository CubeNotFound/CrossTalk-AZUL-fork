from aiohttp import web
import lxml, jinja2, secrets, util.misc
from markupsafe import Markup
from .util import render, preprocess_soap

from .appdirdb import DB

TMPL_DIR = 'front/msn/http/tmpl/appdir'

def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'appdir', TMPL_DIR, globals = {
		'bool_to_str': _bool_to_str,
	})

	# Version cacche
	app.router.add_get('/AppDirectory/GetAppdirVersion.aspx', handle_getappdirversion)
	# AppDirctory SOAP service
	app.router.add_get('/AppDirectory/AppDirectory.asmx', handle_appdirectory)
	app.router.add_post('/AppDirectory/AppDirectory.asmx', handle_appdirectory)
	app.router.add_get(r'/~Live.ConfigServer/{junk:.*}/~op-GetFilteredDataSet2/', handle_appdirectory)
	app.router.add_get(r'/~Live.ConfigServer/{junk:.*}/~op-GetFilteredDataSet2/{tail:.*}', handle_appdirectory)
	# Activities page
	app.router.add_get('/AppDirectory/Directory.aspx', page_directory)

async def handle_getappdirversion(req):
	return render(req, 'appdir:GetAppdirVersion.html', {
		'version': secrets.token_urlsafe(128),
	})

async def handle_appdirectory(req):
	action = None
	action_str = None
	ver = ''
	seg_args = {}
	if req.method == 'POST':
		action = await _preprocess_soap(req)
		if action is None:
			return web.Response(status=500, text='')
		action_str = _get_tag_localname(action)
	elif req.method == 'GET':
		if 'op' in req.query:
			action_str = req.query.get('op')
			ver = req.query.get('ver', '')
		elif req.match_info.get('tail') is not None:
			action_str = 'GetFilteredDataSet2'
			parts = [p for p in req.match_info['tail'].split('/') if p]
			for seg in parts:
				if not seg.startswith('~') or '-' not in seg:
					continue
				key, val = seg[1:].split('-', 1)
				seg_args[key.lower()] = val
			ver = seg_args.get('ts', '')
			seg_args['locale'] = seg_args.get('locale')
			try:
				seg_args['page'] = int(seg_args.get('page', 0))
				seg_args['kids'] = int(seg_args.get('kids', -1))
				seg_args['app_type'] = int(seg_args.get('apptype', 0))
			except ValueError:
				return web.Response(status=500, text='')
		else:
			return web.Response(status=500, text='')
	else:
		return web.Response(status=405, text='')
	if action_str == 'GetFullDataSet':
		results = []
		db = DB()
		for apps_locale in db.apps.values():
			results.extend([_create_entry_container(req, i, entry) for i, entry in enumerate(apps_locale)])
		results.extend([_create_category(req, 'en-US', category, i) for i, category in enumerate(db.categories)])
		if req.method == 'POST':
			diffgram = _create_diffgram(req, Markup(''.join(results)))
			return render(req, 'appdir:GetFullDataSetResponse.xml', {'diffgram': Markup(diffgram)})
		else:
			return render(req, 'appdir:AppDir.xml', {'v': ver, 'results': Markup(''.join(results))})
	elif action_str == 'GetFilteredDataSet2':
		if req.method == 'POST':
			locale = _get_action_argument(req, action, 'locale')
			if locale is not None:
				locale = str(locale)
			try:
				page = int(_get_action_argument(req, action, 'Page'))
				kids = int(_get_action_argument(req, action, 'Kids'))
				app_type = int(_get_action_argument(req, action, 'AppType'))
			except:
				return web.Response(status=500, text='')
		else:
			locale = req.query.get('Locale') or seg_args.get('locale')
			page = seg_args.get('page') or int(req.query.get('Page', 0))
			kids = seg_args.get('kids') or int(req.query.get('Kids', -1))
			app_type = seg_args.get('app_type') or int(req.query.get('AppType', 0))
		results = []
		db = DB()
		entries = [app for app in db.apps['none'] if app.page == page and app.app_type == app_type]
		if locale and locale in db.apps:
			entries.extend([app for app in db.apps[locale] if app.page == page and app.app_type == app_type])
		if kids >= 0:
			entries = [app for app in entries if app.kids == (kids == 1)]
		categories_filtered = []
		for category in db.categories:
			if category.app_type != app_type:
				continue
			for entry in entries:
				if entry.category_id == category.id:
					categories_filtered.append(category)
					break
		results.extend([_create_entry_container(req, i, entry) for i, entry in enumerate(entries)])
		results.extend([_create_category(req, locale, category, i) for i, category in enumerate(categories_filtered)])
		if req.method == 'POST':
			diffgram = _create_diffgram(req, Markup(''.join(results)))
			return render(req, 'appdir:GetFilteredDataSet2Response.xml', {'diffgram': Markup(diffgram)})
		else:
			return render(req, 'appdir:AppDir.xml', {'v': ver, 'results': Markup(''.join(results))})
	elif action_str == 'GetAppEntry':
		try:
			id = int(_get_action_argument(req, action, 'ID'))
		except:
			return web.Response(status=500, text='')
		entry = None
		db = DB()
		for apps_locale in db.apps.values():
			for app in apps_locale:
				if app.id == id:
					entry = app
					break
			if entry is not None:
				break
		if req.method == 'POST':
			entry_markup = None
			if entry:
				entry_markup = Markup(_create_entry(req, 0, entry))
			return render(req, 'appdir:GetAppEntryResponse.xml', {'entry': entry_markup})
		else:
			if entry:
				return web.Response(status=200, content_type='text/xml', text=_create_entry_container(req, 0, entry, extra=f' code="2" v="{ver}"'))
			return web.Response(status=200, content_type='text/xml', text='')
	else:
		return web.Response(status=500, text='')

async def page_directory(req):
	app_entries_js = []
	results = []
	locale = req.query.get('L') or 'en-US'
	
	db = DB()
	categories = db.categories
	entries = db.apps
	
	category_tmpl = req.app['jinja_env'].get_template('appdir:Directory/Directory.category.html')
	entry_tmpl = req.app['jinja_env'].get_template('appdir:Directory/Directory.entry.html')
	category_end_tmpl = req.app['jinja_env'].get_template('appdir:Directory/Directory.category.end.html')
	
	for category in categories:
		filtered_entries = [
			app for app in entries['none']
			if app.category_id == category.id
		]
		if locale and locale in entries:
			filtered_entries.extend([
				app for app in entries[locale]
				if app.category_id == category.id
			])
		if not filtered_entries:
			continue
		
		results.append(category_tmpl.render(
			cat_id = category.id,
			cat_name = category.name,
		))
		
		for entry in filtered_entries:
			results.append(entry_tmpl.render(
				app_id = entry.id,
				description = entry.description,
				name = entry.name,
			))
			app_entries_js.append(APP_ENTRY_JS.format(
				entry.id, (1 if entry.kids else 0), entry.min_users, entry.max_users,
			))
		
		results.append(category_end_tmpl.render(
			cat_id = category.id,
		))
	
	return render(req, 'appdir:Directory/Directory.html', {
		'app_entries_js': Markup(''.join(app_entries_js)),
		'results': Markup(''.join(results)),
	})
	
# TODO: remove and replace with util.preprocess_soap
async def _preprocess_soap(req):
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	action = _find_element(root, 'Body/*[1]')
	
	return action

def _get_action_argument(req, action, name):
	result = None
	if req.method == 'POST':
		result = _find_element(action, name)
	elif req.method == 'GET':
		result = req.query.get(name)
	
	return result

def _create_entry_container(req, i, entry, *, extra = None):
	entry_container_tmpl = req.app['jinja_env'].get_template('appdir:Entry_container.xml')
	if req.method == 'POST':
		extra = Markup(' diffgr:id="Entry{}" msdata:rowOrder="{}" diffgr:hasChanges="inserted"'.format(i + 1, i))
	elif extra is not None and req.method != 'POST':
		extra = Markup(extra)
	
	return entry_container_tmpl.render(
		extra = extra,
		entry = Markup(_create_entry(req, i, entry)),
	)

def _create_entry(req, i, entry):
	entry_tmpl = req.app['jinja_env'].get_template('appdir:Entry.xml')
	return entry_tmpl.render(entry = entry, i = i)

def _create_category(req, locale, category, i):
	category_tmpl = req.app['jinja_env'].get_template('appdir:Category.xml')
	extra = None
	if req.method == 'POST':
		extra = Markup(' diffgr:id="Category{}" msdata:rowOrder="{}" diffgr:hasChanges="inserted"'.format(i + 1, i))
	
	return category_tmpl.render(
		extra = extra,
		locale = locale,
		category = category,
	)

def _create_diffgram(req, results):
	diffgram_tmpl = req.app['jinja_env'].get_template('appdir:diffgram.xml')
	return diffgram_tmpl.render(
		results = results,
	)

def _get_tag_localname(elm):
	return lxml.etree.QName(elm.tag).localname

def _bool_to_str(b):
	return 'True' if b else 'False'

def _find_element(xml, query):
	thing = xml.find('.//{*}' + query.replace('/', '/{*}'))
	if isinstance(thing, lxml.objectify.StringElement):
		thing = str(thing)
	elif isinstance(thing, lxml.objectify.BoolElement):
		thing = bool(thing)
	elif isinstance(thing, lxml.objectify.IntElement):
		thing = int(thing)
	return thing

APP_ENTRY_JS = '''		[{}, [{}, {}, {}, ""]],
'''