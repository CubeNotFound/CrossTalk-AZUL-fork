from typing import Optional, Callable

import asyncio, ipaddress

from core.backend import Backend
from util.misc import Logger
import settings

from .crypto import load_or_generate_server_keys, fingerprint
from .ctrl import INSCtrl
from .registry import ClientRegistry

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

def register(loop: asyncio.AbstractEventLoop, backend: Backend) -> ClientRegistry:
	from util.misc import ProtocolRunner
	keys = load_or_generate_server_keys(settings.INS_KEY_DIR)
	if keys.generated:
		print(f'[InterService] <Info> Generated the InterService host key in {settings.INS_KEY_DIR}')
	print(f'[InterService] <Info> Host key {fingerprint(keys.host.public_key())}')
	registry = ClientRegistry(keys.public_raw)
	active = [record for record in registry.clients() if not record.revoked]
	if not active:
		print('[InterService] <Info> No clients are enrolled yet. Make an enrollment code for each one in the admin panel (InterService)')
	else:
		print(f'[InterService] <Info> {len(active)} enrolled client(s)')
	INSCtrl.configure(keys, registry)
	INSCtrl.attach(backend)
	allowed = parse_networks(settings.INS_ALLOWED_IPS)
	backend.add_runner(ProtocolRunner(settings.INS_HOST, settings.INS_PORT, ListenerINS, args = ['InterService', backend, INSCtrl, allowed], service = 'InterService'))
	return registry

def parse_networks(entries: list[str]) -> list[IPNetwork]:
	return [ipaddress.ip_network(str(entry).strip(), strict = False) for entry in entries]

def is_allowed(host: str, allowed: list[IPNetwork]) -> bool:
	try:
		addr = ipaddress.ip_address(host.split('%', 1)[0])
	except ValueError:
		return False
	candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [addr]
	if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
		candidates.append(addr.ipv4_mapped)
	return any(candidate in network for candidate in candidates for network in allowed if candidate.version == network.version)

class ListenerINS(asyncio.Protocol):
	logger: Logger
	backend: Backend
	controller: INSCtrl
	transport: Optional[asyncio.WriteTransport]
	allowed: list[IPNetwork]
	
	def __init__(
		self, logger_prefix: str, backend: Backend, controller_factory: Callable[[Logger, str, Backend], INSCtrl], allowed: list[IPNetwork],
	) -> None:
		super().__init__()
		self.logger = Logger(logger_prefix, self)
		self.backend = backend
		self.controller = controller_factory(self.logger, 'direct', backend)
		self.controller.close_callback = self._on_close
		self.transport = None
		self.allowed = allowed
	
	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		assert isinstance(transport, asyncio.WriteTransport)
		peername = transport.get_extra_info('peername')
		host = (peername[0] if peername else '')
		if not is_allowed(host, self.allowed):
			self.logger.info(f'Refused InterService connection from unauthorized address {host}')
			self.controller.closed = True
			transport.abort()
			return
		self.transport = transport
		self.logger.log_connect()
		self.controller.connection_made(transport)
	
	def connection_lost(self, exc: Optional[Exception]) -> None:
		if self.transport is None:
			return
		self.controller.close()
		self.logger.log_disconnect()
		self.transport = None
	
	def data_received(self, data: bytes) -> None:
		transport = self.transport
		if transport is None:
			return
		if self.backend.maintenance_mode:
			transport.close()
			return
		self.controller.transport = None
		self.controller.data_received(transport, data)
		transport.write(self.controller.flush())
		self.controller.transport = transport
	
	def _on_close(self) -> None:
		if self.transport is None: return
		self.transport.close()
