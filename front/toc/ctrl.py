import random
import struct

from core.backend import Backend, BackendSession
from core.client import Client
from typing import Optional, Callable
from util.misc import Logger, is_valid_oscar_screenname

from .commands import COMMANDS, TOCBackendEventHandler, build_config2, build_nick, build_update_buddy
from core.models import ContactList


class TOCCtrl:
	logger: Logger
	transport: Optional[object]

	close_callback: Optional[Callable[[], None]]
	closed: bool

	backend: Backend
	bs: Optional[BackendSession]
	client: Client

	dialect: int
	sequence: int

	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		self.logger = logger
		self.transport = None
		self.close_callback = None
		self.closed = False
		self.backend = backend
		self.bs = None
		self.client = Client('toc', '1.0', via)
		self.dialect = 1
		self.sequence = random.randint(0x0000, 0xFFFF)
		self.evt = None  # type: Optional[TOCBackendEventHandler]
		self.front_data = {}
		self.chats = {}  # numeric chat id -> (ChatSession, TOCChatEventHandler)

	def on_connect(self) -> None:
		self.transport.write(struct.pack('>BBHHL', 0x2A, 0x01, self._next_seq(), 4, 1))

	def _next_seq(self) -> int:
		self.sequence = 0 if self.sequence == 0xFFFF else self.sequence + 1
		return self.sequence

	def send_line(self, line: str) -> None:
		payload = line.encode('utf-8', 'replace') + b'\x00'
		packet = struct.pack('>BBHH', 0x2A, 0x02, self._next_seq(), len(payload)) + payload
		if self.transport is not None:
			self.transport.write(packet)

	def on_signon_frame(self, data: bytes) -> None:
		pass

	def on_data_frame(self, data: bytes) -> None:
		line = data.rstrip(b'\x00').decode('utf-8', 'replace')
		if not line:
			return

		parts = _tokenize(line)
		if not parts:
			return

		handler = COMMANDS.get(parts[0])
		if handler is None:
			self.logger.info('[Client] Unknown TOC command:', parts[0])
			return
		handler(self, parts[1:])

	def sign_on(self, username_login: str, roasted_pw: str, *, dialect: int) -> None:
		from .roast import unroast_hex

		self.dialect = dialect
		self.client = Client('toc', 'TOC{}.0'.format(dialect), self.client.via)

		password = unroast_hex(roasted_pw.encode('utf-8')).decode('utf-8', 'replace')
		uuid = self.backend.user_service.login_with_username(username_login, password)
		if uuid is None:
			self.send_line('ERROR:980')  # incorrect nickname or password
			self.close()
			return

		self.evt = TOCBackendEventHandler(self)
		self.bs = self.backend.login(uuid, self.client, self.evt, option = None)
		if self.bs is None:
			self.send_line('ERROR:981')  # service temporarily unavailable
			self.close()
			return
		self.bs.front_data['toc'] = True

		self.send_line('SIGN_ON:TOC{}.0'.format(dialect))

	def init_done(self) -> None:
		if self.bs is None:
			return
		self.send_line(build_config2(self.bs))
		self.send_line(build_nick(self.bs.user))

		# push presence for everyone already online, otherwise nobody shows online
		# until their status next changes
		detail = self.bs.user.detail
		if detail is not None:
			for ctc in detail.get_contacts_by_list(ContactList.FL):
				if is_valid_oscar_screenname(ctc.head.username) and not ctc.status.is_offlineish():
					self.send_line(build_update_buddy(ctc, dialect = self.dialect))

	def close(self) -> None:
		if self.closed:
			return
		self.closed = True
		if self.close_callback:
			self.close_callback()
		if self.bs:
			self.bs.close()


def _tokenize(line: str) -> list[str]:
	tokens = []
	i = 0
	n = len(line)
	while i < n:
		while i < n and line[i] == ' ':
			i += 1
		if i >= n:
			break
		if line[i] == '{':
			depth = 1
			j = i + 1
			while j < n and depth > 0:
				if line[j] == '{': depth += 1
				elif line[j] == '}': depth -= 1
				j += 1
			tokens.append(line[i + 1:j - 1])
			i = j
		else:
			j = i
			while j < n and line[j] != ' ':
				j += 1
			tokens.append(line[i:j])
			i = j
	return tokens