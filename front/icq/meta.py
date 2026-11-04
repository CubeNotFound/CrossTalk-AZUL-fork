from typing import Any, Callable, TYPE_CHECKING

from core.models import User
from util import icq

from . import directory
from .packets import LE, Meta, MetaReply, MetaResult, Reader, Server

if TYPE_CHECKING:
	from .ctrl import LegacyCtrl
	from .wire import Header


# META_USER (0x064A), the V5 directory and profile requests: u16 subtype, then its data; every answer is a SRV_META_USER
# (0x03DE) of u16 reply subtype, u8 result and the reply's data, under the request's seq2

def handle(ctrl: 'LegacyCtrl', header: 'Header', data: bytes) -> None:
	# the ACK echoes both sequence numbers
	ctrl.ack(header, with_seq2 = True)
	if len(data) < 2:
		return
	reader = Reader(data)
	subtype = reader.u16()
	handler = HANDLERS.get(subtype)
	if handler is None:
		ctrl.logger.info('[Client] Unhandled META_USER request', hex(subtype))
		reply(ctrl, header, subtype, MetaResult.Ok)
		return
	ctrl.logger.info('[Client] META_USER', hex(subtype))
	try:
		handler(ctrl, header, reader)
	except ValueError:
		ctrl.logger.info('[Client] Malformed META_USER request', hex(subtype))

def reply(ctrl: 'LegacyCtrl', header: 'Header', subtype: int, result: int, body: bytes = b'') -> None:
	ctrl.send(Server.MetaUser, LE().u16(subtype).u8(result).raw(body if result == MetaResult.Ok else b'').bytes(), seq2 = header.seq2)

def _target(ctrl: 'LegacyCtrl', reader: Reader) -> User | None:
	return directory.find(ctrl.backend, reader.u32())

def _meta_auth(info: dict[str, Any]) -> int:
	# the META replies (like their OSCAR descendants): 0 means authorization required, 1 that anyone may add
	return 0 if info['auth_required'] else 1


# the info replies

def _basic_info3(info: dict[str, Any]) -> bytes:
	# nick, first, last, three e-mail addresses (primary, secondary, old), city, state, phone, fax, street, cell, ZIP,
	# u16 country, u16 GMT offset, u8 auth, u8 hide e-mail (1: hidden), three zero bytes
	body = LE().string(info['nick']).string(info['first']).string(info['last']).string(info['email']).string('').string('')
	for field in ('city', 'state', 'phone', 'fax', 'address', 'cell', 'zip'):
		body.string(info[field])
	body.u16(info['country']).u16(info['gmt']).u8(_meta_auth(info)).u8(0 if info['publish_email'] else 1).u8(0).u8(0).u8(0)
	return body.bytes()

def _basic_info_old(info: dict[str, Any]) -> bytes:
	# the older basic info (META_USER_FULLINFO's): u32 UIN, nick, first, last, e-mail, u8 auth
	return LE().u32(info['uin']).string(info['nick']).string(info['first']).string(info['last']).string(info['email']).u8(_meta_auth(info)).bytes()

def _more_info(info: dict[str, Any], *, full_year: bool) -> bytes:
	# u16 age, u8 gender, homepage, birth year (u16, or before ICQ 99b a u8 of the year less 1900), u8 month, u8 day, three
	# u8 languages
	body = LE().u16(info['age']).u8(info['gender']).string(info['homepage'])
	year = info['birth_year']
	if full_year:
		body.u16(year)
	else:
		body.u8(year - 1900 if year >= 1900 else year)
	body.u8(info['birth_month']).u8(info['birth_day']).u8(info['lang1']).u8(info['lang2']).u8(info['lang3'])
	return body.bytes()

def _homepage_category() -> bytes:
	# u8 enabled, u16 category, description, u8: nobody has one here
	return LE().u8(0).u16(0).string('').u8(0).bytes()

def _work_info(info: dict[str, Any], *, zip_string: bool) -> bytes:
	# city, state, phone, fax, street, ZIP (a string from ICQ 99b, before that a u32), u16 country, company, department,
	# position, u16 occupation, webpage
	work = info['work']
	body = LE()
	for field in ('city', 'state', 'phone', 'fax', 'address'):
		body.string(work[field])
	if zip_string:
		body.string(work['zip'])
	else:
		body.u32(info['work_zip_number'])
	body.u16(work['country']).string(work['company']).string(work['department']).string(work['position'])
	body.u16(work['occupation']).string(work['webpage'])
	return body.bytes()

def _pairs(pairs: list[list[Any]]) -> LE:
	body = LE().u8(len(pairs))
	for code, keyword in pairs:
		body.u16(int(code)).string(keyword)
	return body

def _padded(pairs: list[list[Any]], slots: int) -> list[list[Any]]:
	return (list(pairs) + [[0, '']] * slots)[:slots]

def _affiliations(info: dict[str, Any]) -> bytes:
	body = _pairs(_padded(info['past_affiliations'], icq.AFFILIATION_SLOTS)).raw(_pairs(_padded(info['affiliations'], icq.AFFILIATION_SLOTS)).bytes())
	return body.u16(0x0000).u16(0x0001).u8(0).bytes()

def _full_info(ctrl: 'LegacyCtrl', header: 'Header', user: User, *, newer: bool) -> None:
	# seven replies: basic, more, homepage category, work, about, interests, affiliations; ICQ 99b's requests (and the
	# login info) get the newer layouts
	info = directory.profile(user, ctrl.user)
	reply(ctrl, header, MetaReply.BasicInfo, MetaResult.Ok, _basic_info3(info) if newer else _basic_info_old(info))
	reply(ctrl, header, MetaReply.MoreInfo, MetaResult.Ok, _more_info(info, full_year = newer))
	reply(ctrl, header, MetaReply.HomepageCategory, MetaResult.Ok, _homepage_category())
	reply(ctrl, header, MetaReply.WorkInfo, MetaResult.Ok, _work_info(info, zip_string = newer))
	reply(ctrl, header, MetaReply.About, MetaResult.Ok, LE().string(info['notes']).bytes())
	reply(ctrl, header, MetaReply.Interests, MetaResult.Ok, _pairs(info['interests']).bytes())
	reply(ctrl, header, MetaReply.Affiliations, MetaResult.Ok, _affiliations(info))

def meta_login(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# answered with the subtype echoed, then u16 0 and u16 0x46 (no result byte)
	ctrl.send(Server.MetaUser, LE().u16(Meta.Login).u16(0x0000).u16(0x0046).bytes(), seq2 = header.seq2)

def meta_login_info(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# the client's own details after signing on (a UIN when it says whose)
	user = _target(ctrl, reader) if reader.remaining() >= 4 else ctrl.user
	if user is None:
		reply(ctrl, header, MetaReply.BasicInfo, MetaResult.Fail)
		return
	_full_info(ctrl, header, user, newer = True)

def meta_full_info(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	user = _target(ctrl, reader)
	if user is None:
		reply(ctrl, header, MetaReply.BasicInfo, MetaResult.Fail)
		return
	_full_info(ctrl, header, user, newer = False)

def meta_full_info2(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	user = _target(ctrl, reader)
	if user is None:
		reply(ctrl, header, MetaReply.BasicInfo, MetaResult.Fail)
		return
	_full_info(ctrl, header, user, newer = True)

def meta_short_info(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# nick, first, last, e-mail, u8 auth, u8 gender, u8 0
	user = _target(ctrl, reader)
	if user is None:
		reply(ctrl, header, MetaReply.ShortInfo, MetaResult.Fail)
		return
	info = directory.profile(user, ctrl.user)
	body = LE().string(info['nick']).string(info['first']).string(info['last']).string(info['email'])
	reply(ctrl, header, MetaReply.ShortInfo, MetaResult.Ok, body.u8(_meta_auth(info)).u8(info['gender']).u8(0).bytes())


# searches

def _record(info: dict[str, Any]) -> LE:
	# a hit: u32 UIN, nick, first, last, e-mail, u8 auth, u8 web aware
	record = LE().u32(info['uin']).string(info['nick']).string(info['first']).string(info['last']).string(info['email'])
	return record.u8(_meta_auth(info)).u8(1 if info['web_aware'] else 0)

def _search_results(ctrl: 'LegacyCtrl', header: 'Header', users: list[User]) -> None:
	# every hit but the last is USER_FOUND, the last LAST_USER_FOUND with u32 users left after it (outside its u16 length);
	# no hits at all is a failed LAST_USER_FOUND
	if not users:
		reply(ctrl, header, MetaReply.LastUserFound, MetaResult.Fail)
		return
	for index, user in enumerate(users):
		last = index == len(users) - 1
		record = _record(directory.profile(user, ctrl.user)).u8(0).bytes()
		body = LE().u16(len(record)).raw(record)
		if last:
			body.u32(0)
		reply(ctrl, header, MetaReply.LastUserFound if last else MetaReply.UserFound, MetaResult.Ok, body.bytes())

def _white_results(ctrl: 'LegacyCtrl', header: 'Header', users: list[User], *, length_prefixed: bool) -> None:
	# white pages hits are WHITE_FOUND/WHITE_LAST_FOUND: the first search's records have no length and only the last has
	# users left; the second's (0x0533) carry a u16 length and users left on every record
	if not users:
		reply_body = LE().u16(MetaReply.WhiteLastFound).u8(MetaResult.Fail).u32(0).bytes()
		ctrl.send(Server.MetaUser, reply_body, seq2 = header.seq2)
		return
	for index, user in enumerate(users):
		last = index == len(users) - 1
		record = _record(directory.profile(user, ctrl.user))
		if length_prefixed:
			payload = record.u8(0).bytes()
			body = LE().u16(len(payload)).raw(payload).u32(0)
		else:
			body = record
			if last:
				body.u32(0)
		reply(ctrl, header, MetaReply.WhiteLastFound if last else MetaReply.WhiteFound, MetaResult.Ok, body.bytes())

def meta_search_name(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# nick, first, last
	nick, first, last = reader.string(), reader.string(), reader.string()
	_search_results(ctrl, header, directory.search(ctrl.backend, nick = nick, first = first, last = last))

def meta_search_uin(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# finding someone by their exact number is how ICQ adds a contact, so it doesn't need a directory listing
	user = _target(ctrl, reader)
	_search_results(ctrl, header, [user] if user is not None else [])

def meta_search_email(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	email = reader.string()
	_search_results(ctrl, header, directory.search(ctrl.backend, email = email))

def meta_search_white(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# first, last, nick and e-mail lead it; the rest (ages, location, work, interests) narrows and isn't kept here
	first, last, nick, email = reader.string(), reader.string(), reader.string(), reader.string()
	users = directory.search(ctrl.backend, email = email, first = first, last = last, nick = nick)
	_white_results(ctrl, header, users, length_prefixed = False)

def meta_search_white2(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	first, last, nick, email = reader.string(), reader.string(), reader.string(), reader.string()
	users = directory.search(ctrl.backend, email = email, first = first, last = last, nick = nick)
	_white_results(ctrl, header, users, length_prefixed = True)


# profile changes

def _save(ctrl: 'LegacyCtrl') -> None:
	icq.save(ctrl.backend, ctrl.user)

def meta_set_basic(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# nick, first, last, three e-mail addresses (only the primary is kept), city, state, phone, fax, street, cell, ZIP,
	# u16 country, u8 GMT offset, u8 publish e-mail (0: yes)
	fields: dict[str, Any] = { field: reader.string() for field in ('nick', 'first', 'last', 'email') }
	reader.string()
	reader.string()
	for field in ('city', 'state', 'phone', 'fax', 'address', 'cell', 'zip'):
		fields[field] = reader.string()
	fields['country'] = reader.u16() if reader.remaining() >= 2 else 0
	fields['gmt'] = reader.u8() if reader.remaining() else 0
	fields['publish_email'] = (reader.u8() == 0) if reader.remaining() else False
	ctrl.set_nickname(fields['nick'])
	icq.set_basic(ctrl.user, fields)
	_save(ctrl)
	reply(ctrl, header, MetaReply.SetBasicAck, MetaResult.Ok)

def meta_set_work(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# city, state, phone, fax, street, ZIP, u16 country, company, department, position, u16 occupation, webpage
	fields: dict[str, Any] = { field: reader.string() for field in ('city', 'state', 'phone', 'fax', 'address', 'zip') }
	fields['country'] = reader.u16()
	for field in ('company', 'department', 'position'):
		fields[field] = reader.string()
	fields['occupation'] = reader.u16()
	fields['webpage'] = reader.string()
	icq.set_work(ctrl.user, fields)
	_save(ctrl)
	reply(ctrl, header, MetaReply.SetWorkAck, MetaResult.Ok)

def meta_set_more(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# u8 age (worked out from the birth date instead), u16 gender, homepage, u16 year, u8 month, u8 day, three languages
	reader.u8()
	fields: dict[str, Any] = { 'gender': reader.u16() & 0xFF, 'homepage': reader.string(), 'birth_year': reader.u16() }
	fields['birth_month'] = reader.u8()
	fields['birth_day'] = reader.u8()
	for lang in ('lang1', 'lang2', 'lang3'):
		fields[lang] = reader.u8() if reader.remaining() else 0
	icq.set_more(ctrl.user, fields)
	_save(ctrl)
	reply(ctrl, header, MetaReply.SetMoreAck, MetaResult.Ok)

def meta_set_about(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	icq.set_notes(ctrl.user, reader.string())
	_save(ctrl)
	reply(ctrl, header, MetaReply.SetAboutAck, MetaResult.Ok)

def _read_pairs(reader: Reader) -> list[list[Any]]:
	count = reader.u8()
	return [[reader.u16(), reader.string()] for _ in range(count)]

def meta_set_interests(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	icq.set_interests(ctrl.user, _read_pairs(reader))
	_save(ctrl)
	reply(ctrl, header, MetaReply.SetInterestsAck, MetaResult.Ok)

def meta_set_affiliations(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	past = _read_pairs(reader)
	current = _read_pairs(reader)
	icq.set_affiliations(ctrl.user, past, current)
	_save(ctrl)
	reply(ctrl, header, MetaReply.SetAffiliationsAck, MetaResult.Ok)

def meta_set_security(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# u8 authorization (0: required, 1: anyone may add), u8 web aware, u8 direct connection permissions, u8
	authorization = reader.u8()
	web_aware = reader.u8() if reader.remaining() else 0
	icq.set_permissions(ctrl.user, auth_required = authorization == 0, web_aware = web_aware == 1)
	_save(ctrl)
	reply(ctrl, header, MetaReply.SetSecurityAck, MetaResult.Ok)

def meta_set_password(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# every protocol's copy of the password comes from the one set on the website, so it isn't changed from here
	reply(ctrl, header, MetaReply.SetPasswordAck, MetaResult.Fail)

def meta_set_homepage_category(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# homepage categories aren't kept (nothing shows them but this client), but the client needs its answer
	reply(ctrl, header, MetaReply.SetHomepageCategoryAck, MetaResult.Ok)

def meta_unregister(ctrl: 'LegacyCtrl', header: 'Header', reader: Reader) -> None:
	# the account belongs to the website, which is where it can be closed
	reply(ctrl, header, MetaReply.UnregisterAck, MetaResult.Fail)


HANDLERS: dict[int, Callable[['LegacyCtrl', 'Header', Reader], None]] = {
	Meta.Login: meta_login,
	Meta.LoginInfo: meta_login_info,
	Meta.LoginInfo2: meta_login_info,
	Meta.FullInfo: meta_full_info,
	Meta.FullInfo2: meta_full_info2,
	Meta.ShortInfo: meta_short_info,
	Meta.SearchName: meta_search_name,
	Meta.SearchName2: meta_search_name,
	Meta.SearchUin: meta_search_uin,
	Meta.SearchUin2: meta_search_uin,
	Meta.SearchEmail: meta_search_email,
	Meta.SearchEmail2: meta_search_email,
	Meta.SearchWhite: meta_search_white,
	Meta.SearchWhite2: meta_search_white2,
	Meta.SetBasic: meta_set_basic,
	Meta.SetBasic2: meta_set_basic,
	Meta.SetWork: meta_set_work,
	Meta.SetWork2: meta_set_work,
	Meta.SetMore: meta_set_more,
	Meta.SetMore2: meta_set_more,
	Meta.SetAbout: meta_set_about,
	Meta.SetInterests: meta_set_interests,
	Meta.SetAffiliations: meta_set_affiliations,
	Meta.SetSecurity: meta_set_security,
	Meta.SetPassword: meta_set_password,
	Meta.SetHomepageCategory: meta_set_homepage_category,
	Meta.Unregister: meta_unregister,
}
