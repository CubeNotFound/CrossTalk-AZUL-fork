import settings
import asyncio

from typing import Optional
from util.misc import Logger

from core import event, error
from core.backend import Backend, BackendSession

from .msnp import MSNPCtrl
from .misc import Err

MSNP_DIALECTS = ['MSNP{}'.format(d) for d in (
	22,
	21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
	10, 9, 8, 7, 6, 5, 4, 3, 2
)]

class MSNPCtrlDP(MSNPCtrl):
	__slots__ = (
		'backend', 'dialect', 'bs', 'redir_attempts'
	)
	
	backend: Backend
	dialect: int
	bs: Optional[BackendSession]
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.redir_attempts = 0
		self.bs = None
	
	def _on_close(self) -> None:
		if self.bs:
			self.bs.close()
	
	def on_connect(self) -> None:
		pass
	
	def _m_ver(self, trid: str, *args: str) -> None:
		if self.dialect != 0:
			self.send_reply(Err.NotExpected, trid)
			self.close()
			return
		
		dialects = [a.upper() for a in args]
		try:
			_ = int(trid)
		except ValueError:
			self.close()
		d = None
		for d in MSNP_DIALECTS:
			if d in dialects: break
		if d not in dialects:
			self.send_reply('VER', trid, 0)
			self.close()
			return
		self.dialect = int(d[4:])
		self.send_reply('VER', trid, d)
	
	def _m_cvr(self, trid: str, *args: str) -> None:
		v = args[5]
		self.send_reply('CVR', trid, v, v, '1.0.0000', 'https://crosstalk.im/downloads', 'https://crosstalk.im/compat')
	
	def _m_cvq(self, trid: str, *args: str) -> None:
		if len(args) < 6:
			self.send_reply(Err.InvalidCVQ, trid)
			self.close()
			return
		v = args[5]
		self.send_reply('CVQ', trid, v, v, '1.0.0000', 'https://crosstalk.im/downloads', 'https://crosstalk.im/compat')
	
	def _m_inf(self, trid: str) -> None:
		if self.dialect < 9:
			self.send_reply('INF', trid, 'MD5')
		else:
			self.close()
			return

	def __getattr__(self, name):
		if name.startswith('_m_') and name not in ('_m_ver', '_m_cvr', '_m_cvq', '_m_inf'):
			def handler(trid: str, *args: str):
				if self.dialect == 2:
					self.send_reply('XFR', trid, 'NS', f'{settings.TARGET_IP}:1864')
				elif self.dialect <= 6:
					self.send_reply('XFR', trid, 'NS', f'{settings.TARGET_IP}:1864', '0')
				elif self.dialect <= 13:
					self.send_reply('XFR', trid, 'NS', f'{settings.TARGET_IP}:1864', '0', f'{settings.TARGET_IP}:1863')
				elif self.dialect <= 19:
					self.send_reply('XFR', trid, 'NS', f'{settings.TARGET_IP}:1864', 'U', 'D')
				else: 
					self.send_reply('XFR', trid, 'NS', f'{settings.TARGET_IP}:1864', 'U', 'D', 'VmVyc2lvbjogMQ0KWGZyQ291bnQ6IDINCg==')
				asyncio.create_task(self._close_conn())
			return handler
		raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")
	
	async def _close_conn(self):
		await asyncio.sleep(5)
		self.close()