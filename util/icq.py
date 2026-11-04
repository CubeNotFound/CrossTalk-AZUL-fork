from datetime import date, datetime
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
	from core.backend import Backend
	from core.models import User

ICQ_INFO_KEY = 'ICQ_INFO'

INTEREST_SLOTS = 4
AFFILIATION_SLOTS = 3

MAX_QUEUED_AUTH_EVENTS = 50

_BASIC_FIELDS = ('nick', 'first', 'last', 'email', 'city', 'state', 'phone', 'fax', 'address', 'cell', 'zip')
_WORK_FIELDS = ('city', 'state', 'phone', 'fax', 'address', 'zip', 'company', 'department', 'position', 'webpage')


def _store(user: 'User') -> dict[str, Any]:
	store = user.settings.get(ICQ_INFO_KEY)
	if not isinstance(store, dict):
		store = {}
		user.settings[ICQ_INFO_KEY] = store
	return store

def _section(user: 'User', name: str) -> dict[str, Any]:
	store = _store(user)
	section = store.get(name)
	if not isinstance(section, dict):
		section = {}
		store[name] = section
	return section

def _text(value: Any) -> str:
	return '' if value is None else str(value)

def save(backend: 'Backend', user: 'User') -> None:
	if user.detail is not None:
		backend._mark_modified(user)
	else:
		backend._mark_modified(user, detail = backend._load_detail(user))

def nickname(user: 'User') -> str:
	nick = _section(user, 'basic').get('nick')
	if nick:
		return str(nick)
	name = user.status.name or ''
	if not name or '@' in name:
		return user.username
	return name

def basic_info(user: 'User') -> dict[str, Any]:
	stored = _section(user, 'basic')
	profile = user.profile
	info = {
		'nick': nickname(user),
		'first': stored.get('first', user.first_name or ''),
		'last': stored.get('last', user.last_name or ''),
		'email': stored.get('email', ''),
		'city': stored.get('city', (profile.city if profile is not None else None) or ''),
		'state': stored.get('state', (profile.state if profile is not None else None) or ''),
		'phone': stored.get('phone', ''),
		'fax': stored.get('fax', ''),
		'address': stored.get('address', ''),
		'cell': stored.get('cell', ''),
		'zip': stored.get('zip', _text(profile.zip if profile is not None else None)),
		'country': int(stored.get('country', 0) or 0),
		'gmt': int(stored.get('gmt', 0) or 0),
		# ICQ only ever shows an e-mail address its owner chose to publish
		'publish_email': bool(stored.get('publish_email', False)),
	}
	for field in _BASIC_FIELDS:
		info[field] = _text(info[field])
	return info

def more_info(user: 'User') -> dict[str, Any]:
	stored = _section(user, 'more')
	profile = user.profile
	return {
		'gender': int(stored.get('gender', 0) or 0),
		'homepage': _text(stored.get('homepage', (profile.website if profile is not None else None) or '')),
		'birth_year': int(stored.get('birth_year', 0) or 0),
		'birth_month': int(stored.get('birth_month', 0) or 0),
		'birth_day': int(stored.get('birth_day', 0) or 0),
		'lang1': int(stored.get('lang1', 0) or 0),
		'lang2': int(stored.get('lang2', 0) or 0),
		'lang3': int(stored.get('lang3', 0) or 0),
	}

def work_info(user: 'User') -> dict[str, Any]:
	stored = _section(user, 'work')
	info = { field: _text(stored.get(field, '')) for field in _WORK_FIELDS }
	info['country'] = int(stored.get('country', 0) or 0)
	info['occupation'] = int(stored.get('occupation', 0) or 0)
	return info

def notes(user: 'User') -> str:
	stored = _store(user).get('notes')
	if stored is not None:
		return _text(stored)
	profile = user.profile
	return (profile.bio if profile is not None else None) or ''

def _pairs(user: 'User', name: str, slots: int) -> list[list[Any]]:
	stored = _store(user).get(name)
	pairs = []
	if isinstance(stored, list):
		for entry in stored[:slots]:
			if isinstance(entry, (list, tuple)) and len(entry) == 2:
				pairs.append([int(entry[0] or 0), _text(entry[1])])
	while len(pairs) < slots:
		pairs.append([0, ''])
	return pairs

def interests(user: 'User') -> list[list[Any]]:
	return _pairs(user, 'interests', INTEREST_SLOTS)

def affiliations(user: 'User') -> dict[str, list[list[Any]]]:
	return {
		'past': _pairs(user, 'past_affiliations', AFFILIATION_SLOTS),
		'current': _pairs(user, 'affiliations', AFFILIATION_SLOTS),
	}

def age(user: 'User', today: date | None = None) -> int:
	more = more_info(user)
	year, month, day = more['birth_year'], more['birth_month'], more['birth_day']
	if not year or not month or not day:
		return 0
	today = today or datetime.utcnow().date()
	try:
		born = date(year, month, day)
	except ValueError:
		return 0
	years = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
	return max(0, years)

def set_basic(user: 'User', fields: dict[str, Any]) -> None:
	_section(user, 'basic').update(fields)

def set_more(user: 'User', fields: dict[str, Any]) -> None:
	_section(user, 'more').update(fields)

def set_work(user: 'User', fields: dict[str, Any]) -> None:
	_section(user, 'work').update(fields)

def set_notes(user: 'User', text: str) -> None:
	_store(user)['notes'] = text

def set_interests(user: 'User', pairs: list[list[Any]]) -> None:
	_store(user)['interests'] = [[int(code), _text(keyword)] for code, keyword in pairs[:INTEREST_SLOTS]]

def set_affiliations(user: 'User', past: list[list[Any]], current: list[list[Any]]) -> None:
	_store(user)['past_affiliations'] = [[int(code), _text(keyword)] for code, keyword in past[:AFFILIATION_SLOTS]]
	_store(user)['affiliations'] = [[int(code), _text(keyword)] for code, keyword in current[:AFFILIATION_SLOTS]]

def permissions(user: 'User') -> dict[str, bool]:
	stored = _section(user, 'perms')
	return {
		'auth_required': bool(stored.get('auth_required', False)),
		'web_aware': bool(stored.get('web_aware', False)),
	}

def set_permissions(user: 'User', *, auth_required: bool | None = None, web_aware: bool | None = None) -> None:
	stored = _section(user, 'perms')
	if auth_required is not None:
		stored['auth_required'] = auth_required
	if web_aware is not None:
		stored['web_aware'] = web_aware

def requires_authorization(owner: 'User', requester: 'User') -> bool:
	if owner is requester or not permissions(owner)['auth_required']:
		return False
	return requester.uuid not in (_store(owner).get('preauth') or [])

def record_preauth(owner: 'User', requester_uuid: str) -> None:
	preauth = _store(owner).setdefault('preauth', [])
	if requester_uuid not in preauth:
		preauth.append(requester_uuid)

def queue_auth_event(user: 'User', event: dict[str, Any]) -> None:
	queue = _store(user).setdefault('auth_events', [])
	queue.append(event)
	del queue[:-MAX_QUEUED_AUTH_EVENTS]

def take_auth_events(user: 'User') -> list[dict[str, Any]]:
	store = _store(user)
	queue = store.pop('auth_events', None)
	return queue if isinstance(queue, list) else []

def latin1(text: str) -> bytes:
	return text.encode('cp1252', errors = 'replace')

def from_latin1(data: bytes) -> str:
	try:
		return data.decode('cp1252')
	except UnicodeDecodeError:
		return data.decode('latin-1')
