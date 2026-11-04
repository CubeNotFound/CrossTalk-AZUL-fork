from typing import Any, TYPE_CHECKING

from core.models import User
from util import icq

from front.oscar.proto.names import uin_of

if TYPE_CHECKING:
	from core.backend import Backend

# a search hands back at most this many people
MAX_RESULTS = 20


def find(backend: 'Backend', uin: int) -> User | None:
	uuid = backend.util_get_uuid_from_uin(uin)
	return backend._load_user_record(uuid) if uuid is not None else None

def listed(user: User, viewer: User | None) -> bool:
	# the white pages only show someone who listed themselves in the member directory (or themselves, to themselves); the
	# same rule the OSCAR ICQ frontend goes by
	return user is viewer or bool(getattr(user, 'show_in_dir', False))

def _zip_number(text: str) -> int:
	# the old info packets carry the ZIP code as a number
	digits = ''.join(ch for ch in text if ch.isdigit())[:9]
	return int(digits) if digits else 0

def profile(user: User, viewer: User | None) -> dict[str, Any]:
	# everything the pre-OSCAR packets can show about `user`, as `viewer` may see it
	info = icq.basic_info(user)
	more = icq.more_info(user)
	work = icq.work_info(user)
	perms = icq.permissions(user)
	show = listed(user, viewer)
	uin = uin_of(user) or 0

	def shown(value: Any, blank: Any = '') -> Any:
		return value if show else blank

	affiliations = icq.affiliations(user)
	return {
		'uin': uin,
		'nick': info['nick'] or str(uin),
		'first': shown(info['first']),
		'last': shown(info['last']),
		# an e-mail address only ever goes out when its owner published it
		'email': info['email'] if info['publish_email'] or user is viewer else '',
		'publish_email': info['publish_email'],
		'city': shown(info['city']),
		'state': shown(info['state']),
		'phone': shown(info['phone']),
		'fax': shown(info['fax']),
		'address': shown(info['address']),
		'cell': shown(info['cell']),
		'zip': shown(info['zip']),
		'zip_number': shown(_zip_number(info['zip']), 0),
		'country': shown(info['country'], 0),
		'gmt': info['gmt'],
		'age': shown(icq.age(user), 0),
		'gender': shown(more['gender'], 0),
		'homepage': shown(more['homepage']),
		'birth_year': shown(more['birth_year'], 0),
		'birth_month': shown(more['birth_month'], 0),
		'birth_day': shown(more['birth_day'], 0),
		'lang1': more['lang1'],
		'lang2': more['lang2'],
		'lang3': more['lang3'],
		'notes': shown(icq.notes(user)),
		'work': { key: (value if show else (0 if isinstance(value, int) else '')) for key, value in work.items() },
		'work_zip_number': shown(_zip_number(work['zip']), 0),
		'interests': icq.interests(user) if show else [],
		'past_affiliations': affiliations['past'] if show else [],
		'affiliations': affiliations['current'] if show else [],
		'auth_required': perms['auth_required'],
		'web_aware': perms['web_aware'],
	}

def unknown_profile(uin: int) -> dict[str, Any]:
	# what the old info replies say about a UIN nobody has: its number for a nick, and nothing else
	return {
		'uin': uin, 'nick': str(uin), 'first': '', 'last': '', 'email': '', 'city': '', 'state': '', 'phone': '',
		'homepage': '', 'notes': '', 'country': 0, 'gmt': 0, 'age': 0, 'gender': 0, 'zip_number': 0, 'auth_required': False,
	}

def search(
	backend: 'Backend', *, email: str = '', first: str = '', last: str = '', nick: str = '',
) -> list[User]:
	# a directory search: only people who listed themselves, and only those an ICQ client can name (by UIN)
	criteria = { key: value for key, value in (('email', email), ('first_name', first), ('last_name', last), ('nickname', nick)) if value }
	if not criteria:
		return []
	users = []
	for uuid in backend.user_service.search_uuids(**criteria):
		user = backend._load_user_record(uuid)
		if user is not None and uin_of(user) is not None:
			users.append(user)
	return users[:MAX_RESULTS]
