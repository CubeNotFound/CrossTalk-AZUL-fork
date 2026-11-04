import asyncio
import time

import settings

from core.backend import Backend
from util.misc import DatagramRunner, Logger

from . import wire
from .ctrl import LegacyCtrl, prelogin
from .packets import Command, Version

Address = tuple[str, int]

# a client that hasn't been heard from in this long is gone (it pings every minute or so)
SESSION_TIMEOUT = 120
REAP_INTERVAL = 30
# how long a passed password check (CMD_GET_DEPS) waits for the login that follows it
PREAUTH_LIFETIME = 60

# what a client sends before it has a session, answered the same whether or not it had one
PRELOGIN_COMMANDS = frozenset({
	Command.Login, Command.GetDeps, Command.FirstLogin, Command.RegRequestInfo, Command.RegNewUser, Command.RegNewUserInfo,
})


def register(loop: asyncio.AbstractEventLoop, backend: Backend) -> None:
	# the pre-OSCAR ICQ protocols (V1-V5, ICQ 1.x to ICQ 2000a) are all UDP, on Mirabilis' port 4000
	port = getattr(settings, 'ICQ_LEGACY_PORT', 4000)
	backend.add_runner(DatagramRunner('0.0.0.0', port, ListenerICQ, args = ['ICQ', backend], service = 'ICQ'))


class ListenerICQ(asyncio.DatagramProtocol):
	# one endpoint for every client: each datagram finds its session by the address it came from
	logger: Logger
	backend: Backend
	transport: asyncio.DatagramTransport | None
	by_addr: dict[Address, LegacyCtrl]
	by_uin: dict[int, LegacyCtrl]
	preauth: dict[Address, float]
	_reaper: asyncio.Task | None

	def __init__(self, logger_prefix: str, backend: Backend) -> None:
		super().__init__()
		self.logger = Logger(logger_prefix, self)
		self.backend = backend
		self.transport = None
		self.by_addr = {}
		self.by_uin = {}
		self.preauth = {}
		self._reaper = None

	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		assert isinstance(transport, asyncio.DatagramTransport)
		self.transport = transport
		self._reaper = self.backend.loop.create_task(self._reap())

	def connection_lost(self, exc: Exception | None) -> None:
		if self._reaper is not None:
			self._reaper.cancel()
			self._reaper = None
		for ctrl in list(self.by_uin.values()):
			ctrl.close()
		self.transport = None

	def error_received(self, exc: Exception) -> None:
		# an ICMP port unreachable from a client that went away; its session times out by itself
		self.logger.info('UDP error:', str(exc))

	def send(self, packet: bytes, addr: Address) -> None:
		if self.transport is not None:
			self.transport.sendto(packet, addr)

	def datagram_received(self, packet: bytes, addr: Address) -> None:
		if self.backend.maintenance_mode:
			return
		try:
			parsed = wire.parse(packet)
			if parsed is None:
				self.logger.info('Dropped a datagram that is no ICQ packet from', addr[0])
				return
			header, data = parsed
			self.logger.debug('[Client]', header, 'from', addr)
			ctrl = self._find(header, addr)
			if ctrl is None or header.command in PRELOGIN_COMMANDS:
				# (a login or the steps before it from an address that already has a session: the client started over)
				prelogin(self, header, data, addr)
			else:
				ctrl.on_packet(header, data)
		except Exception as ex:
			self.logger.error(ex)

	def _find(self, header: wire.Header, addr: Address) -> LegacyCtrl | None:
		ctrl = self.by_addr.get(addr)
		if ctrl is not None:
			if ctrl.uin != header.uin and header.uin:
				return None
			return ctrl
		# a client behind NAT can turn up from a new port: the same UIN from the same host (and for V5 the same session)
		# is the same session
		ctrl = self.by_uin.get(header.uin) if header.uin else None
		if ctrl is None or ctrl.addr[0] != addr[0] or ctrl.version != header.version:
			return None
		if header.version == Version.V5 and ctrl.session_id != header.session_id:
			return None
		self.by_addr.pop(ctrl.addr, None)
		ctrl.addr = addr
		self.by_addr[addr] = ctrl
		return ctrl

	def add(self, ctrl: LegacyCtrl) -> None:
		self.by_addr[ctrl.addr] = ctrl
		self.by_uin[ctrl.uin] = ctrl

	def remove(self, ctrl: LegacyCtrl) -> None:
		if self.by_addr.get(ctrl.addr) is ctrl:
			del self.by_addr[ctrl.addr]
		if self.by_uin.get(ctrl.uin) is ctrl:
			del self.by_uin[ctrl.uin]

	def note_preauth(self, addr: Address) -> None:
		self.preauth[addr] = time.monotonic()

	def take_preauth(self, addr: Address) -> bool:
		noted = self.preauth.pop(addr, None)
		return noted is not None and time.monotonic() - noted < PREAUTH_LIFETIME

	async def _reap(self) -> None:
		# UDP has no hang-up: a session that stops pinging is signed off
		while True:
			await asyncio.sleep(REAP_INTERVAL)
			now = time.monotonic()
			for ctrl in list(self.by_uin.values()):
				if now - ctrl.last_activity > SESSION_TIMEOUT:
					ctrl.logger.info('Timed out')
					ctrl.close()
			for addr, noted in list(self.preauth.items()):
				if now - noted > PREAUTH_LIFETIME:
					del self.preauth[addr]
