from __future__ import annotations

from typing import TYPE_CHECKING
import asyncio, time

from .models import User, MessageType

if TYPE_CHECKING:
	from .backend import Backend, BackendSession

EVIL_DELTA = 100
EVIL_DELTA_ANONYMOUS = 30
EVIL_DECAY = 50
EVIL_DECAY_INTERVAL = 300
EVIL_MAX = 999
CONVERSATION_WINDOW = 3600

RATED_MESSAGE_TYPES = frozenset({ MessageType.Chat, MessageType.Nudge, MessageType.Ink })

RATE_WINDOW = 20
RATE_MAX = 6000
RATE_LIMIT = 500
RATE_CLEAR = 1500
RATE_WARNING_SCALE = 250

class _RateState:
	__slots__ = ('level', 'last', 'limited')

	level: float
	last: float
	limited: bool

	def __init__(self, now: float) -> None:
		self.level = float(RATE_MAX)
		self.last = now
		self.limited = False

class AbuseService:
	__slots__ = ('backend', '_conversations', '_warnings', '_warned', '_rates', '_decay_task')

	backend: Backend
	_conversations: dict[str, dict[str, list[float]]]
	_warnings: dict[str, dict[str, list[float]]]
	_warned: dict[str, User]
	_rates: dict[str, _RateState]
	_decay_task: asyncio.Task[None] | None

	def __init__(self, backend: Backend) -> None:
		self.backend = backend
		self._conversations = {}
		self._warnings = {}
		self._warned = {}
		self._rates = {}
		self._decay_task = None

	def warning_level(self, user: User) -> int:
		return max(0, min(EVIL_MAX, int(user.evil_permanent or 0) + int(user.evil_temporary or 0)))

	def track_message(self, sender: User, recipient: User, *, now: float | None = None) -> None:
		if sender is recipient: return
		now = (time.time() if now is None else now)
		times = self._conversations.setdefault(sender.uuid, {}).setdefault(recipient.uuid, [])
		times.append(now)
		del times[:-3]

	def may_warn(self, warner: User, warnee: User, *, now: float | None = None) -> bool:
		if warner is warnee: return False
		now = (time.time() if now is None else now)
		received = [t for t in self._conversations.get(warnee.uuid, {}).get(warner.uuid, []) if now - t < CONVERSATION_WINDOW]
		warns = self._warnings.setdefault(warner.uuid, {}).setdefault(warnee.uuid, [])
		warns[:] = [t for t in warns if now - t < CONVERSATION_WINDOW]
		if len(received) <= len(warns):
			return False
		warns.append(now)
		return True

	def warn(self, warner: User, warnee: User, *, anonymous: bool, delta: int | None = None) -> tuple[int, int] | None:
		level = self.warning_level(warnee)
		if level >= EVIL_MAX or not self.may_warn(warner, warnee):
			return None
		if delta is None:
			delta = (EVIL_DELTA_ANONYMOUS if anonymous else EVIL_DELTA)
		delta = min(delta, EVIL_MAX - level)
		warnee.evil_temporary = int(warnee.evil_temporary or 0) + delta
		new_level = self.warning_level(warnee)
		print(f"[Abuse] <Info> {warnee.username} ({warnee.email}) was warned ({'anonymously' if anonymous else 'by ' + warner.username}); their warning level is now {new_level}")
		self._start_decay(warnee)
		self.announce(warnee, (None if anonymous else warner))
		return delta, new_level

	def announce(self, user: User, warner: User | None) -> None:
		level = self.warning_level(user)
		sessions: list[BackendSession] = list(self.backend.util_get_sessions_by_user(user))
		for bs in sessions:
			try:
				bs.evt.on_warning_level_changed(level, warner)
			except Exception:
				import traceback
				traceback.print_exc()
		for bs in sessions:
			if bs.closed: continue
			bs.me_update({ 'needs_notify': True, 'notify_status': True })
			break

	def allow_message(self, user: User, *, now: float | None = None) -> bool:
		now = (time.time() if now is None else now)
		level = self.warning_level(user)
		if level >= EVIL_MAX:
			return False
		state = self._rates.get(user.uuid)
		if state is None:
			state = self._rates[user.uuid] = _RateState(now)
			return True
		delta_ms = max(0.0, (now - state.last) * 1000)
		state.last = now
		state.level = min(float(RATE_MAX), ((RATE_WINDOW - 1) * state.level + delta_ms) / RATE_WINDOW)
		scale = 1 + level / RATE_WARNING_SCALE
		limit = RATE_LIMIT * scale
		clear = min(RATE_CLEAR * scale, RATE_MAX * 0.95)
		if state.limited:
			if state.level < clear:
				return False
			state.limited = False
		if state.level < limit:
			state.limited = True
			print(f"[Abuse] <Info> {user.username} ({user.email}) is sending messages too fast and is being rate limited")
			return False
		return True

	def is_rate_limited(self, user: User) -> bool:
		state = self._rates.get(user.uuid)
		return self.warning_level(user) >= EVIL_MAX or (state is not None and state.limited)

	def _start_decay(self, user: User) -> None:
		self._warned[user.uuid] = user
		if self._decay_task is None or self._decay_task.done():
			try:
				self._decay_task = self.backend.loop.create_task(self._decay_warnings())
			except RuntimeError:
				self._decay_task = None

	async def _decay_warnings(self) -> None:
		while self._warned:
			await asyncio.sleep(EVIL_DECAY_INTERVAL)
			self.decay_once()

	def decay_once(self) -> None:
		for uuid, user in list(self._warned.items()):
			temporary = int(user.evil_temporary or 0)
			user.evil_temporary = max(0, temporary - EVIL_DECAY)
			if user.evil_temporary == 0:
				del self._warned[uuid]
			if user.evil_temporary != temporary and self.backend.util_get_sessions_by_user(user):
				self.announce(user, None)
