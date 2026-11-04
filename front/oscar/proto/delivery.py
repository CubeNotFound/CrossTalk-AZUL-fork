from typing import Any, Callable, TYPE_CHECKING

from core.models import User

from .snac import SNACMessage

if TYPE_CHECKING:
	from core.backend import Backend, BackendSession


def oscar_sessions(backend: 'Backend', user: User) -> list['BackendSession']:
	# the BOS sessions of `user` that an OSCAR client is behind (the event handler is how SNACs reach its connection)
	return [
		bs for bs in backend.util_get_sessions_by_user(user)
		if bs.front_data.get('oscar0') and hasattr(bs.evt, 'oscar_on_snac') and not bs.closed
	]

def send_to_user(backend: 'Backend', user: User, build: Callable[['BackendSession'], SNACMessage | None]) -> int:
	# hand a SNAC (built per viewer, since names and formatting depend on who receives it) to each OSCAR session of `user`
	sent = 0
	for bs in oscar_sessions(backend, user):
		msg = build(bs)
		if msg is None:
			continue
		bs.evt.oscar_on_snac(msg)
		sent += 1
	return sent

def feedbag_sessions(backend: 'Backend', user: User) -> list['BackendSession']:
	# the OSCAR sessions that run on a server-side buddy list (they sent FEEDBAG__USE)
	return [bs for bs in oscar_sessions(backend, user) if bs.front_data.get('oscar0_feedbag')]

def any_session(backend: 'Backend', user: User) -> 'BackendSession | None':
	sessions = oscar_sessions(backend, user)
	return sessions[0] if sessions else None

def ctrl_of(bs: 'BackendSession') -> Any:
	return getattr(bs.evt, 'ctrl', None)
