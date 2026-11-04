import re

from typing import Any, TYPE_CHECKING

from core.models import AIM_SSI_KEY, User
from util.misc import is_valid_oscar_screenname

if TYPE_CHECKING:
	from core.backend import Backend, BackendSession

# ICQ numbers are plain decimal and fit in a u32
_UIN_RE = re.compile(r'^[0-9]{1,10}$')


def is_uin(name: str) -> bool:
	return _UIN_RE.match(name) is not None and 0 < int(name) <= 0xFFFFFFFF

def normalize(name: str) -> str:
	# OSCAR compares screen names without spaces or case ("Joe Smith" and "joesmith" are the same account)
	return name.replace(' ', '').lower()

def valid_name(name: str) -> bool:
	# what a client may name an account by: a screen name, or an ICQ number (which is one too)
	return bool(name) and is_valid_oscar_screenname(name.replace(' ', ''))

def uin_of(user: User) -> int | None:
	uin = getattr(user, 'uin', None)
	if not uin or int(uin) <= 0 or int(uin) > 0xFFFFFFFF:
		return None
	return int(uin)

def resolve(backend: 'Backend', name: str) -> str | None:
	# both an account's screen name and its UIN reach it
	if not valid_name(name):
		return None
	return backend.util_get_uuid_from_screenname(name)

def resolve_user(backend: 'Backend', name: str) -> User | None:
	uuid = resolve(backend, name)
	if uuid is None:
		return None
	return backend._load_user_record(uuid)

def is_icq_session(bs: 'BackendSession | None') -> bool:
	return bool(bs is not None and bs.front_data.get('oscar0_icq'))

def self_name(bs: 'BackendSession') -> str:
	# the name the client signed on with comes back to it in everything about itself
	return bs.front_data.get('oscar0_sn') or bs.user.username

def representable(user: User) -> bool:
	# a screen name OSCAR can carry, or a UIN to stand in for one
	return is_valid_oscar_screenname(user.username) or uin_of(user) is not None

def matches(form: str, user: User) -> bool:
	uin = uin_of(user)
	if uin is not None and is_uin(form) and int(form) == uin:
		return True
	return normalize(form) == user.username.lower()

def default_name(bs: 'BackendSession | None', user: User) -> str:
	# ICQ sessions know people by number wherever there is one, AIM sessions by screen name
	uin = uin_of(user)
	if is_icq_session(bs) and uin is not None:
		return str(uin)
	if is_valid_oscar_screenname(user.username):
		return user.username
	if uin is not None:
		return str(uin)
	return user.username

def _aliases(user: User) -> dict[str, Any]:
	store = user.settings.get(AIM_SSI_KEY)
	if not isinstance(store, dict):
		store = {}
		user.settings[AIM_SSI_KEY] = store
	names = store.get('names')
	if not isinstance(names, dict):
		names = {}
		store['names'] = names
	return names

def name_for(bs: 'BackendSession | None', user: User) -> str:
	# the form `bs`'s client knows `user` by: what it named them by this session, what it stored them as, or the default
	if bs is not None:
		if user is bs.user:
			return self_name(bs)
		form = bs.front_data.get('oscar0_names', {}).get(user.uuid)
		if form is not None and matches(form, user):
			return form
		store = bs.user.settings.get(AIM_SSI_KEY)
		alias = ((store.get('names') or {}) if isinstance(store, dict) else {}).get(user.uuid)
		if isinstance(alias, str) and matches(alias, user):
			return alias
	return default_name(bs, user)

def remember(bs: 'BackendSession', user: User, form: str) -> None:
	# a client keeps its own spelling of a name; replies about that account have to use it or the client won't match them up
	if user is bs.user or not matches(form, user):
		return
	bs.front_data.setdefault('oscar0_names', {})[user.uuid] = form

def store_alias(bs: 'BackendSession', user: User, form: str) -> bool:
	# a feedbag buddy keeps the form it was added by across sign-ons; returns whether anything changed
	if not matches(form, user):
		return False
	names = _aliases(bs.user)
	if normalize(form) == normalize(default_name(bs, user)):
		return names.pop(user.uuid, None) is not None
	if names.get(user.uuid) == form:
		return False
	names[user.uuid] = form
	return True

def drop_alias(bs: 'BackendSession', uuid: str) -> None:
	_aliases(bs.user).pop(uuid, None)
	bs.front_data.get('oscar0_names', {}).pop(uuid, None)
