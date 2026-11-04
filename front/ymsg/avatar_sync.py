from typing import Dict, List, Optional
import asyncio, time, traceback

from core.backend import Backend
from core.models import ContactList, User, _is_blocking

from . import misc

SYNC_INTERVAL = 15
PUSH_DEDUPE_SECS = 5

_UNSET = object()
_last_checksum = {} # type: Dict[str, Optional[bytes]]
_last_push = {} # type: Dict[str, tuple]


def refresh_avatar(backend: Backend, user: User) -> bool:
	try:
		fresh = backend.user_service.get(user.uuid)
	except Exception:
		traceback.print_exc()
		return False
	if fresh is None or fresh.avatar == user.avatar:
		return False
	user.avatar = fresh.avatar
	return True

def note_login(backend: Backend, user: User) -> None:
	refresh_avatar(backend, user)
	_last_checksum[user.uuid] = misc.yahoo_avatar_checksum(user)

def icon_recipients(user: User) -> List[User]:
	detail = user.detail
	if detail is None:
		return []
	heads = [] # type: List[User]
	for ctc in detail.contacts.values():
		if not ctc.lists & (ContactList.FL | ContactList.RL):
			continue
		if _is_blocking(user, ctc.head):
			continue
		heads.append(ctc.head)
	return heads

def push_avatar_change(backend: Backend, user: User) -> None:
	checksum = misc.yahoo_avatar_checksum(user)
	_last_checksum[user.uuid] = checksum
	if checksum is None:
		return
	_last_push[user.uuid] = (checksum, time.monotonic())
	
	for bs_self in backend.util_get_sessions_by_user(user):
		bs_self.evt.ymsg_on_friend_icon(user.username, user.username, checksum)
	
	for head in icon_recipients(user):
		for bs_other in backend.util_get_sessions_by_user(head):
			bs_other.evt.ymsg_on_friend_icon(user.username, head.username, checksum)

def recently_pushed(user: User, checksum: bytes) -> bool:
	last = _last_push.get(user.uuid)
	return last is not None and last[0] == checksum and (time.monotonic() - last[1]) < PUSH_DEDUPE_SECS

def sync_once(backend: Backend) -> None:
	seen = set()
	for bs in list(backend._sc.iter_sessions()):
		user = bs.user
		if user.uuid in seen:
			continue
		seen.add(user.uuid)
		
		refresh_avatar(backend, user)
		checksum = misc.yahoo_avatar_checksum(user)
		previous = _last_checksum.get(user.uuid, _UNSET)
		if previous is _UNSET:
			_last_checksum[user.uuid] = checksum
			continue
		if checksum != previous:
			push_avatar_change(backend, user)

async def worker_sync_avatars(backend: Backend) -> None:
	while True:
		await asyncio.sleep(SYNC_INTERVAL)
		try:
			sync_once(backend)
		except Exception:
			traceback.print_exc()