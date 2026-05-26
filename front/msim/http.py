import settings
from aiohttp import web


def register(app: web.Application) -> None:
	# http://myspace.com/html.ng/site=myspace&page=30000001&position=imbut&rand=9879
	app.router.add_get('/html.ng/{tail:.*}', handle_client_advert)


async def handle_client_advert(request: web.Request) -> web.Response:
	return web.HTTPFound(f'http://ctsvcs.advertising.ugnet.gay/ads/banner-sq')
