import asyncio
import struct

from core.backend import Backend
from typing import Optional, Callable
from util.misc import Logger, ProtocolRunner

from .ctrl import TOCCtrl


def register(loop: asyncio.AbstractEventLoop, backend: Backend) -> None:
	backend.add_runner(ProtocolRunner('0.0.0.0', 9898, ListenerTOC, args = ['TOC', backend, TOCCtrl], service = 'TOC'))


class ListenerTOC(asyncio.Protocol):
	logger: Logger
	backend: Backend
	controller: TOCCtrl
	transport: Optional[asyncio.WriteTransport]

	buffer: bytes = b''

	def __init__(self, logger_prefix: str, backend: Backend, controller_factory: Callable[[Logger, str, Backend], TOCCtrl]) -> None:
		super().__init__()
		self.logger = Logger(logger_prefix, self)
		self.backend = backend
		self.controller = controller_factory(self.logger, 'direct', backend)
		self.controller.close_callback = self._on_close
		self.transport = None

	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		self.controller.transport = transport
		self.controller.on_connect()
		self.logger.log_connect()

	def connection_lost(self, exc: Optional[Exception]) -> None:
		self.controller.close()
		self.logger.log_disconnect()

	def data_received(self, packet: bytes) -> None:
		if self.backend.maintenance_mode:
			self.transport.close()
			return
		self.buffer += packet
		self.parse_buffer()

	def parse_buffer(self) -> None:
		while True:
			if self.controller.closed:
				self.buffer = b''
				break
			if not self.buffer or self.buffer[0] != 0x2A:
				break
			if len(self.buffer) < 6:
				break

			channel, sequence, length = struct.unpack('>BHH', self.buffer[1:6])
			if len(self.buffer) < length + 6:
				break

			data = self.buffer[6:length + 6]
			match channel:
				case 0x01:
					self.controller.on_signon_frame(data)
				case 0x02:
					self.controller.on_data_frame(data)
				case 0x04:
					self.controller.close()
				case 0x05:
					pass
				case _:
					self.logger.info('Recieved unknown FLAP channel:', str(channel))

			self.buffer = self.buffer[length + 6:]

	def _on_close(self) -> None:
		if self.transport is not None:
			self.transport.close()