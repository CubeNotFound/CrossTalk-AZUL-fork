from typing import FrozenSet, Any, Iterable, Optional, TypeVar, List, Dict, Tuple, Generic, TYPE_CHECKING
from abc import ABCMeta, abstractmethod
import asyncio, functools, itertools, traceback, ssl, jinja2, settings, sys, platform
from datetime import datetime
from uuid import uuid4
from aiohttp import web
from pathlib import Path

EMPTY_SET: FrozenSet[Any] = frozenset()

if TYPE_CHECKING:
	VoidTaskType = asyncio.Task[None]
else:
	VoidTaskType = Any

def gen_uuid() -> str:
	return str(uuid4())

T = TypeVar('T')
def first_in_iterable(iterable: Iterable[T]) -> Optional[T]:
	for x in iterable: return x
	return None

def last_in_iterable(iterable: Iterable[T]) -> Optional[T]:
	last = None
	
	for x in iterable:
		last = x
	return last

def generate_random_string(chars: int) -> bytes:
	import random, string

	result = ''.join(random.choice(string.ascii_letters) for i in range(chars))
	return result.encode()

class Runner(metaclass = ABCMeta):
	__slots__ = ('host', 'port', 'ssl_context', 'ssl_only', 'service')
	
	host: str
	port: int
	ssl_context: Optional[ssl.SSLContext]
	ssl_only: bool
	service: str
	
	def __init__(self, host: str, port: int, *, ssl_context: Optional[ssl.SSLContext] = None, ssl_only: bool = False, service: str) -> None:
		self.host = host
		self.port = port
		self.ssl_context = ssl_context
		self.ssl_only = ssl_only
		self.service = service
	
	@abstractmethod
	def create_servers(self, loop: asyncio.AbstractEventLoop) -> List[Any]: pass
	
	def teardown(self, loop: asyncio.AbstractEventLoop) -> Any:
		pass

class ProtocolRunner(Runner):
	__slots__ = ('_protocol')
	
	_protocol: Any
	
	def __init__(
		self, host: str, port: int, protocol: Any, *, args: Optional[List[Any]] = None,
		ssl_context: Optional[ssl.SSLContext] = None, ssl_only: bool = False, service: str
	) -> None:
		super().__init__(host, port, ssl_context = ssl_context, ssl_only = ssl_only, service = service)
		if args:
			protocol = functools.partial(protocol, *args)
		self._protocol = protocol
	
	def create_servers(self, loop: asyncio.AbstractEventLoop) -> List[Any]:
		return [loop.create_server(self._protocol, self.host, self.port, ssl = self.ssl_context)]

class AIOHTTPRunner(Runner):
	__slots__ = ('app', '_handler')
	
	app: Any
	_handler: Optional[Any]
	
	def __init__(self, host: str, port: int, app: Any, *, ssl_context: Optional[ssl.SSLContext] = None, ssl_only: bool = False, service: str) -> None:
		super().__init__(host, port, ssl_context = ssl_context, ssl_only = ssl_only, service = service)
		self.app = app
		self._handler = None
	
	def create_servers(self, loop: asyncio.AbstractEventLoop) -> List[Any]:
		assert self._handler is None
		self._handler = self.app.make_handler(loop = loop)
		loop.run_until_complete(self.app.startup())
		
		ret = []
		if not self.ssl_only:
			ret.append(loop.create_server(self._handler, self.host, self.port, ssl = None))
		if self.ssl_context is not None:
			ret.append(loop.create_server(self._handler, self.host, (self.port if self.ssl_only else 443), ssl = self.ssl_context))
		return ret
	
	def teardown(self, loop: asyncio.AbstractEventLoop) -> None:
		handler = self._handler
		assert handler is not None
		self._handler = None
		loop.run_until_complete(self.app.shutdown())
		loop.run_until_complete(handler.shutdown(60))
		loop.run_until_complete(self.app.cleanup())

class Logger:
	__slots__ = ('prefix', '_log')
	
	prefix: str
	_log: bool
	
	def __init__(self, prefix: str, obj: object) -> None:
		import settings
		self.prefix = '[{}] ({:06x})'.format(prefix, hash(obj) % 0xFFFFFF)
	
	def debug(self, *args: Any) -> None:
		if settings.DEBUG:
			print(self.prefix, '<Debug>', *args)

	def info(self, *args: Any) -> None:
		print(self.prefix, '<Info>', *args)
	
	def error(self, exc: Exception) -> None:
		trace = traceback.print_exception(type(exc), exc, exc.__traceback__)
		print (self.prefix, '<Error>', trace)
	
	def log_connect(self) -> None:
		self.debug("Connected!")
	
	def log_disconnect(self) -> None:
		self.debug("Disconnected!")

def run_loop(loop: asyncio.AbstractEventLoop, runners: List[Runner]) -> None:

	for runner in runners:
		print("[{}] Started service on {}:{}".format(runner.service, runner.host, runner.port))
		
	foos = itertools.chain(*(
		runner.create_servers(loop) for runner in runners
	))
	servers = loop.run_until_complete(asyncio.gather(*foos))

	try:
		loop.run_forever()
	except KeyboardInterrupt:
		raise
	finally:
		for server in servers:
			server.close()
		loop.run_until_complete(asyncio.gather(*(
			server.wait_closed() for server in servers
		)))
		for runner in runners:
			runner.teardown(loop)
		server_temp_cleanup()
		loop.close()

def add_to_jinja_env(app: web.Application, prefix: str, tmpl_dir: str, *, globals: Optional[Dict[str, Any]] = None) -> None:
	jinja_env = app['jinja_env']
	jinja_env.loader.mapping[prefix] = jinja2.FileSystemLoader(tmpl_dir)
	if globals:
		jinja_env.globals.update(globals)

def arbitrary_decode(d: bytes) -> str:
	if not d: return ''
	
	return ''.join(map(chr, [b for b in d]))

def arbitrary_encode(s: str) -> bytes:
	return bytes([ord(c) for c in s])

def date_format(d: Optional[datetime]) -> Optional[str]:
	if d is None:
		return None
	d_iso = '{}{}'.format(
		d.isoformat()[0:19], 'Z',
	)
	return d_iso

def server_temp_cleanup() -> None:
	# For now, just clean up stuff in the Yahoo! HTTP file transfer storage folder
	
	import shutil
	from pathlib import Path
	
	path = Path('storage/file')
	if not path.exists():
		return
	for file_dir in path.iterdir():
		shutil.rmtree(str(file_dir), ignore_errors = True)


def _get_avatar_path(uuid: str) -> Path:
	return Path('storage/dp') / uuid[0:1] / uuid[0:2]

K = TypeVar('K')
V = TypeVar('V')
class DefaultDict(Dict[K, V]):
	_default: V
	
	def __init__(self, default: V, mapping: Dict[K, V]) -> None:
		super().__init__(mapping)
		self._default = default
	
	def __getitem__(self, key: K) -> V:
		v = super().__getitem__(key)
		if v is None:
			v = self._default
		return v

class MultiDict(Generic[K, V]):
	_impl: List[Tuple[K, V]]
	
	def __init__(self, data: Optional[Iterable[Tuple[K, V]]] = None) -> None:
		super().__init__()
		self._impl = ([] if data is None else list(data))
	
	def __contains__(self, key: K) -> bool:
		for d in self._impl:
			if d[0] == key: return True
		return False
	
	def add(self, key: K, value: V) -> None:
		self._impl.append((key, value))
	
	def get(self, key: K) -> Optional[V]:
		for d in self._impl:
			if d[0] == key: return d[1]
		return None
	
	def getall(self, key: K) -> Optional[Iterable[V]]:
		values = [] # type: List[V]
		for d in self._impl:
			if d[0] == key:
				values.append(d[1])
		return values if values else None
	
	def items(self) -> Iterable[Tuple[K, V]]:
		return self._impl
