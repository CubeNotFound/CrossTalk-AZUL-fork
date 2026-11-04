from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple
import asyncio, hashlib, hmac, secrets, time

import sqlalchemy as sa

import core.db as db
from util import hash
import settings

COOKIE_NAME = 'azul_admin'
_DUMMY_HASH: Optional[str] = None
MAX_FAILURES = 5
FAIL_WINDOW = 900

@dataclass
class AdminSession:
	token: str
	uuid: str
	username: str
	csrf: str
	expires: float
	address: str
	flashes: List[Tuple[str, str]] = field(default_factory = list)
	reveal: Optional[Dict[str, str]] = None

	def flash(self, text: str, kind: str = 'success') -> None:
		self.flashes.append((kind, text))

	def take_flashes(self) -> List[Tuple[str, str]]:
		flashes, self.flashes = self.flashes, []
		return flashes

	def take_reveal(self) -> Optional[Dict[str, str]]:
		reveal, self.reveal = self.reveal, None
		return reveal

class AdminAuth:
	__slots__ = ('_sessions', '_failures')

	_sessions: Dict[str, AdminSession]
	_failures: Dict[str, Deque[float]]

	def __init__(self) -> None:
		self._sessions = {}
		self._failures = {}

	@staticmethod
	def configured() -> bool:
		return len(str(getattr(settings, 'ADMIN_KEY', '') or '')) == 64

	@staticmethod
	def key_matches(key: str) -> bool:
		expected = str(getattr(settings, 'ADMIN_KEY', '') or '').lower()
		if len(expected) != 64:
			return False
		return hmac.compare_digest(hashlib.sha256(key.encode('utf-8')).hexdigest(), expected)

	def throttled(self, address: str) -> bool:
		failures = self._failures.get(address)
		if not failures:
			return False
		now = time.monotonic()
		while failures and now - failures[0] > FAIL_WINDOW:
			failures.popleft()
		return len(failures) >= MAX_FAILURES

	def _fail(self, address: str) -> None:
		self._failures.setdefault(address, deque()).append(time.monotonic())

	async def sign_in(self, address: str, login: str, password: str, key: str) -> Optional[AdminSession]:
		login = login.strip()
		with db.Session() as sess:
			row = sess.query(db.User).filter(sa.or_(sa.func.lower(db.User.email) == login.lower(), sa.func.lower(db.User.username) == login.lower())).first()
			stored = row.password if row is not None else None
			found = (row.uuid, row.username, bool(row.is_admin), bool(row.suspended)) if row is not None else None
		loop = asyncio.get_running_loop()
		global _DUMMY_HASH
		if stored is None and _DUMMY_HASH is None:
			_DUMMY_HASH = await loop.run_in_executor(None, hash.hasher.encode, secrets.token_hex(8))
		password_ok = bool(await loop.run_in_executor(None, hash.hasher.verify, password, stored or _DUMMY_HASH))
		key_ok = self.key_matches(key)
		if found is None or not password_ok or not key_ok or not found[2] or found[3]:
			self._fail(address)
			return None
		self._failures.pop(address, None)
		session = AdminSession(
			secrets.token_urlsafe(32), found[0], found[1], secrets.token_urlsafe(24),
			time.time() + int(getattr(settings, 'ADMIN_SESSION_LIFETIME', 8 * 3600)), address,
		)
		self._prune()
		self._sessions[session.token] = session
		return session

	def get(self, token: Optional[str]) -> Optional[AdminSession]:
		if not token:
			return None
		session = self._sessions.get(token)
		if session is None:
			return None
		if session.expires <= time.time():
			self._sessions.pop(token, None)
			return None
		return session

	def still_admin(self, session: AdminSession) -> bool:
		with db.Session() as sess:
			row = sess.query(db.User.is_admin, db.User.suspended).filter(db.User.uuid == session.uuid).one_or_none()
		return row is not None and bool(row[0]) and not bool(row[1])

	def sign_out(self, token: Optional[str]) -> None:
		if token:
			self._sessions.pop(token, None)

	def sign_out_user(self, uuid: str) -> None:
		for token in [token for token, session in self._sessions.items() if session.uuid == uuid]:
			self._sessions.pop(token, None)

	def _prune(self) -> None:
		now = time.time()
		for token in [token for token, session in self._sessions.items() if session.expires <= now]:
			self._sessions.pop(token, None)

	@staticmethod
	def csrf_ok(session: AdminSession, value: Any) -> bool:
		return isinstance(value, str) and hmac.compare_digest(session.csrf, value)
