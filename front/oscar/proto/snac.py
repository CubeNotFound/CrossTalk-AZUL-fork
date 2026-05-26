from core.backend import Backend, BackendSession
from core.client import Client
from core.models import User
from dataclasses import dataclass
from typing import Optional, Callable, Any

from .buffer import Buffer

foodgroups = {}


@dataclass
class SNACMessage(Buffer):
	__slots__ = ('foodgroup', 'subgroup', 'flags', 'request_id', 'data')

	foodgroup: int
	subgroup: int
	flags: int
	request_id: int
	data: bytes

	def __init__(self, foodgroup: int = 0x0000, subgroup: int = 0x0000, flags: int = 0x0000,
				 request_id: int = 0x00000000, data: bytes = b'') -> None:
		super().__init__()

		self.foodgroup = foodgroup
		self.subgroup = subgroup
		self.flags = flags
		self.request_id = request_id
		self.data = data

	def marshal(self) -> bytes:
		# we use a new Buffer here because even though we are a subclass of Buffer, the methods are reserved
		# for SNAC data (everything after the header)
		buf = Buffer()
		buf.write_u16(self.foodgroup)
		buf.write_u16(self.subgroup)
		buf.write_u16(self.flags)
		buf.write_u32(self.request_id)
		buf.write_bytes(self.data)

		return buf.data

	def unmarshal(self, flap_data: bytes) -> None:
		buf = Buffer(flap_data)

		self.foodgroup = buf.read_u16()
		self.subgroup = buf.read_u16()
		self.flags = buf.read_u16()
		self.request_id = buf.read_u32()
		self.data = buf.data


class Foodgroup:
	__slots__ = ('value', 'cls')

	value: int
	cls: Any

	def __init__(self, value) -> None:
		self.value = value
		self.cls = None

	def __call__(self, *args) -> None:
		self.cls = args[0]

		foodgroups[self.value] = self.cls()


class Subgroup:
	__slots__ = ('value', 'mode', 'func')

	value: int
	mode: str
	func: Optional[Callable]

	def __init__(self, value) -> None:
		self.value = value
		self.mode = 'decorating'
		self.func = None

	def __call__(self, *args) -> Any:
		if self.mode == 'decorating':
			self.func = args[0]
			self.mode = 'calling'
			return self

		return self.func(*args)

	def __set_name__(self, owner, name) -> None:
		if not hasattr(owner, 'subgroups'):
			owner.subgroups = {}

		owner.subgroups[self.value] = self.func

		self.func.class_name = owner.__name__
		setattr(owner, name, self.func)


# OSCARClient and OSCARContext
class OSCARClient:
	__slots__ = 'ctrl'

	ctrl: Any  # Any because of circular imports - TODO(subpurple): make this less hacky

	def __init__(self, ctrl: Any) -> None:
		self.ctrl = ctrl

	def send_snac(self, msg: SNACMessage) -> None:
		self.ctrl.send_specific_frame(0x02, msg.marshal())

	def get_ip(self) -> str:
		ip, *_ = self.ctrl.transport.get_extra_info('peername')
		return ip


@dataclass
class OSCARContext:
	__slots__ = ('backend', 'bs', 'client', 'user')

	backend: Backend
	bs: Optional[BackendSession]
	client: Client

	# These slots are equivalent to .bs.* and only exist for the sake of convenience
	user: Optional[User]

	def __init__(self, backend: Backend, client: Client) -> None:
		self.backend = backend
		self.bs = None
		self.client = client
		self.user = None
