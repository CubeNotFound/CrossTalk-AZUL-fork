import asyncio
import settings

from aiohttp import web
from core.backend import Backend
from typing import Optional, Callable
from util.misc import Logger, ProtocolRunner

from . import http
from .ctrl import MSIMCtrl


def register(loop: asyncio.AbstractEventLoop, backend: Backend, http_app: web.Application) -> None:
	# Port 6660 is used here due to being symbolic with the 2nd port it tries, however in practice it always
	# connects to port 1863 first.  Set the key "HKEY_CURRENT_USER\Software\MySpace\IM\LastConnectedPort" to 6660
	# in order to prevent this.  If it doesn't exist, add it as a DWORD.
	backend.add_runner(ProtocolRunner('0.0.0.0', 6660, ListenerMSIM, args=['MySpaceIM', backend, MSIMCtrl], service="MSIM"))

	# Register HTTP routes for e.g. advertisements
	http.register(http_app)


class ListenerMSIM(asyncio.Protocol):
	logger: Logger
	backend: Backend
	controller: MSIMCtrl
	transport: Optional[asyncio.WriteTransport]

	def __init__(self, logger_prefix: str, backend: Backend, controller_factory: Callable[[Logger, str, Backend], MSIMCtrl]) -> None:
		super().__init__()

		self.logger = Logger(logger_prefix, self)
		self.backend = backend
		self.controller = controller_factory(self.logger, 'direct', backend)
		self.controller.close_callback = self._on_close
		self.transport = None

	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		assert isinstance(transport, asyncio.WriteTransport)

		self.transport = transport
		self.controller.transport = transport
		self.logger.log_connect()
		self.controller.on_connect()

	def connection_lost(self, exc: Optional[Exception]) -> None:
		self.controller.close()
		self.logger.log_disconnect()
		self.transport = None

	def data_received(self, data: bytes) -> None:
		transport = self.transport
		assert transport is not None

		if self.backend.maintenance_mode:
			self.transport.close()
			return

		self.controller.on_data_recieved(data)
		transport.write(self.controller.flush())

	def _on_close(self) -> None:
		if self.transport is not None:
			self.transport.close()
