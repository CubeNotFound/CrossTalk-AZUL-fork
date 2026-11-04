import asyncio
import struct
import settings

from core.backend import Backend
from typing import Optional, Callable
from util.misc import Logger, ProtocolRunner

from .ctrl import OSCARCtrl
from .proto.snac import SNACMessage


def register(loop: asyncio.AbstractEventLoop, backend: Backend) -> None:
	backend.add_runner(ProtocolRunner('0.0.0.0', 5190, ListenerOSCAR, args=['OSCAR', backend, OSCARCtrl], service = 'OSCAR'))

	# once someone's avatar has been turned into a buddy icon, OSCAR clients watching them get an arrival that carries it
	from .proto.bart import set_refresh_hook
	from .foodgroups.buddy import refresh_contact
	set_refresh_hook(lambda user: refresh_contact(backend, user))

class ListenerOSCAR(asyncio.Protocol):
	logger: Logger
	backend: Backend
	controller: OSCARCtrl
	transport: Optional[asyncio.WriteTransport]

	buffer: bytes = b''

	def __init__(self,
				 logger_prefix: str,
				 backend: Backend,
				 controller_factory: Callable[[Logger, str, Backend], OSCARCtrl]) -> None:
		super().__init__()

		self.logger = Logger(logger_prefix, self)
		self.backend = backend
		self.controller = controller_factory(self.logger, 'direct', backend)
		self.controller.close_callback = self._on_close
		self.transport = None
		self.buffer = b''

	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		self.transport = transport
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

			# a FLAP header is 6 bytes (u8 0x2A, u8 frame, u16 sequence, u16 length); TCP can hand it over in pieces
			if len(self.buffer) < 6:
				break

			if self.buffer[0] != 0x2A:
				# without the marker there's no telling where the next frame starts, so the stream can't be recovered
				self.logger.info('Recieved data without a FLAP start marker, closing connection')
				self.buffer = b''
				self.controller.close()
				break

			# TODO: bufferize this?
			frame, sequence, length = struct.unpack('>BHH', self.buffer[1:6])

			if len(self.buffer) < length + 6:
				break

			if len(self.buffer) >= length + 6:
				data = self.buffer[6:length + 6]
				# the frame is consumed before it's handled, so nothing a handler does can leave it in the buffer
				self.buffer = self.buffer[length + 6:]

				try:
					self._handle_frame(frame, data)
				except Exception as ex:
					self.logger.error(ex)

			if len(self.buffer) < 6:
				break

	def _handle_frame(self, frame: int, data: bytes) -> None:
		match frame:
			# SIGNON
			case 0x01:
				self.controller.on_signon_frame(data)

			# DATA (always contains a SNAC)
			case 0x02:
				if len(data) < 10:
					self.logger.info('Recieved a DATA frame too short to hold a SNAC:', data.hex())
					return

				msg = SNACMessage()
				msg.unmarshal(data)
				self.controller.on_data_frame(msg)

			# ERROR
			case 0x03:
				self.controller.on_error_frame(data)

			# SIGNOFF
			case 0x04:
				self.controller.on_signoff_frame(data)

			# KEEP_ALIVE
			case 0x05:
				pass

			case _:
				self.logger.info('Recieved unknown frame:', str(frame), 'with data:', data.hex())

	def _on_close(self) -> None:
		if self.transport is not None:
			self.transport.close()
