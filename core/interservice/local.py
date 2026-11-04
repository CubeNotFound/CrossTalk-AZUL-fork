from types import SimpleNamespace
from typing import Any, Dict, Optional
import asyncio

from core.backend import Backend
from util.misc import Logger
import settings

from .ctrl import INSCtrl, INSFail, JSON_COMMANDS

class LocalINSError(Exception):
	code: int
	detail: Dict[str, Any]
	
	def __init__(self, code: int, detail: Optional[Dict[str, Any]] = None) -> None:
		self.code = code
		self.detail = detail or {}
		super().__init__('InterService error {:03}{}'.format(code, ': ' + self.message if self.message else ''))
	
	@property
	def message(self) -> str:
		return str(self.detail.get('error') or '')

class LocalLink(INSCtrl):
	def __init__(self, backend: Backend, actor: str) -> None:
		self.logger = Logger('Admin', self)
		self.backend = backend
		self.identifier = 'admin'
		self.authenticated = True
		self.closed = False
		self.link_id = 'local'
		self.client_record = None
		self.client_info = { 'program': 'admin panel', 'version': settings.VERSION }
		self.subscriptions = set()
		self.tasks = set()
		self.peername = ('127.0.0.1', 0)
		self.transport = None
		self.raw_transport = None
		self.channel = SimpleNamespace(post_quantum = False, binding = b'', enrolled = False)
		self.privileged = True
		self.actor = actor
		self._reply: tuple[str, Any] | None = None
	
	def send_payload(self, cmd: str, trid: str, obj: Any) -> None:
		self._reply = (cmd, obj)
	
	def send_reply(self, *m: str) -> None:
		self._reply = (m[0] if m else '', list(m[1:]))
	
	def close(self, reason: Optional[str] = None) -> None:
		pass
	
	async def call(self, cmd: str, data: Optional[Dict[str, Any]] = None) -> Any:
		cmd = cmd.upper()
		if cmd not in JSON_COMMANDS:
			raise ValueError('{} is not a JSON command'.format(cmd))
		handler = getattr(self, '_m_{}'.format(cmd.lower()))
		self._reply = None
		self.logger.info(f'{self.actor} ran {cmd}')
		try:
			result = handler('1', dict(data or {}))
			if asyncio.iscoroutine(result):
				await result
		except INSFail as ex:
			raise LocalINSError(ex.code, ex.detail)
		reply = self._reply
		if reply is None:
			return None
		name, payload = reply
		if name.isdigit():
			raise LocalINSError(int(name), payload if isinstance(payload, dict) else None)
		return payload
