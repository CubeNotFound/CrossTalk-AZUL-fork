from typing import Type
from types import TracebackType
import sys
from core.conn import Conn
from core.auth import AuthService, LoginAuthService
from core.user import UserService
from core.stats import Stats

def main(*, devmode: bool = False) -> None:
	
	sys.excepthook = _excepthook

	import asyncio, settings, platform
	from core.backend import Backend
	from core import http

	print("""   █████████                         ████ 
  ███▒▒▒▒▒███                       ▒▒███ 
 ▒███    ▒███   █████████ █████ ████ ▒███ 
 ▒███████████  ▒█▒▒▒▒███ ▒▒███ ▒███  ▒███ 
 ▒███▒▒▒▒▒███  ▒   ███▒   ▒███ ▒███  ▒███ 
 ▒███    ▒███    ███▒   █ ▒███ ▒███  ▒███ 
 █████   █████  █████████ ▒▒████████ █████
▒▒▒▒▒   ▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒ ▒▒▒▒▒

""")

	print(f"===== AZUL {settings.VERSION} =====")
	print(f"""2023 - 2026 hiden
	""")
	print(f"""Running on Python {sys.version} on {platform.platform()}
	""")
	if settings.DEBUG:
		print(f"""Debug mode on!
		""")
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	
	from core import db
	schema_changes = db.ensure_schema(db.engine)
	if schema_changes:
		print(f"Database brought up to date ({', '.join(schema_changes)})")

	user_service = UserService(Conn(settings.DB))
	auth_service = AuthService()
	login_auth_service = LoginAuthService(Conn(settings.DB))
	stats_service = Stats(Conn(settings.STATS_DB))
	backend = Backend(loop, user_service = user_service, login_auth_service = login_auth_service, auth_service = auth_service, stats_service = stats_service)
	http_app = http.register(loop, backend, devmode = devmode)

	if settings.ENABLE_FRONT_MSN:
		import front.msn
		front.msn.register(loop, backend, http_app)
	if settings.ENABLE_FRONT_YMSG:
		import front.ymsg
		front.ymsg.register(loop, backend, http_app, devmode = devmode)
	if settings.ENABLE_FRONT_IRC:
		import front.irc
		front.irc.register(loop, backend, devmode = devmode)
	if settings.ENABLE_FRONT_OSCAR:
		import front.oscar
		front.oscar.register(loop, backend)
	if getattr(settings, 'ENABLE_FRONT_ICQ', False):
		import front.icq
		front.icq.register(loop, backend)
	if settings.ENABLE_FRONT_TOC:
		import front.toc
		front.toc.register(loop, backend)
	if settings.ENABLE_FRONT_MSIM:
		import front.msim
		front.msim.register(loop, backend, http_app)
	ins_registry = None
	if settings.ENABLE_INS:
		import core.interservice
		ins_registry = core.interservice.register(loop, backend)
	if settings.ENABLE_ADMIN:
		import front.admin
		front.admin.register(loop, backend, ins_registry)

	backend.run_forever()

def _excepthook(type_: Type[BaseException], value: BaseException, traceback: TracebackType) -> None:
	# TODO: Something useful
	sys.__excepthook__(type_, value, traceback)

if __name__ == '__main__':
	main()