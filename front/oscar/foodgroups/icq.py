import struct

from datetime import datetime
from enum import IntEnum
from typing import Any

from core.models import OIM, User
from util import icq
from util.misc import Logger

from ..proto import names
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs, find_tlv


class ICQRequest(IntEnum):
	OfflineMessages = 0x003C
	DeleteOfflineMessages = 0x003E
	Meta = 0x07D0

class ICQReply(IntEnum):
	OfflineMessage = 0x0041
	OfflineMessagesDone = 0x0042
	Meta = 0x07DA

class ICQResult(IntEnum):
	Ok = 0x0A
	Fail = 0x32
	Error = 0x14

class ICQMeta(IntEnum):
	SetBasicInfo = 0x03EA
	SetWorkInfo = 0x03F3
	SetMoreInfo = 0x03FD
	SetNotes = 0x0406
	SetEmails = 0x040B
	SetInterests = 0x0410
	SetAffiliations = 0x041A
	SetPermissions = 0x0424
	FullInfo = 0x04B2
	ShortInfo = 0x04BA
	FullInfo2 = 0x04D0
	SearchByDetails = 0x0515
	SearchByUin = 0x051F
	SearchByEmail = 0x0529
	SearchWhitePages = 0x0533
	SearchWhitePages2 = 0x055F
	SearchByUin2 = 0x0569
	SearchByEmail3 = 0x0573
	SetIcqPhone = 0x0654
	XmlRequest = 0x0898
	SetFullInfo = 0x0C3A
	DirectoryQuery = 0x0FA0
	SetBasicInfoAck = 0x0064
	SetWorkInfoAck = 0x006E
	SetMoreInfoAck = 0x0078
	SetNotesAck = 0x0082
	SetEmailsAck = 0x0087
	SetInterestsAck = 0x008C
	SetAffiliationsAck = 0x0096
	SetPermissionsAck = 0x00A0
	BasicInfo = 0x00C8
	WorkInfo = 0x00D2
	MoreInfo = 0x00DC
	Notes = 0x00E6
	ExtEmails = 0x00EB
	Interests = 0x00F0
	Affiliations = 0x00FA
	ShortInfoReply = 0x0104
	HomepageCategory = 0x010E
	UserFound = 0x01A4
	LastUserFound = 0x01AE
	SetIcqPhoneAck = 0x031E
	SetFullInfoAck = 0x0C3F
	XmlReply = 0x08A2
	DirectoryResponse = 0x0FB4

# ICQ__TLV tags for the TLV-based requests (white pages 2, search by UIN 2/e-mail 3, set full info); values little endian
class ICQTag(IntEnum):
	Uin = 0x0136
	FirstName = 0x0140
	LastName = 0x014A
	Nickname = 0x0154
	Email = 0x015E
	Gender = 0x017C
	HomeCity = 0x0190
	HomeState = 0x019A
	HomeCountry = 0x01A4
	WorkCompany = 0x01AE
	WorkDepartment = 0x01B8
	WorkPosition = 0x01C2
	WorkOccupation = 0x01CC
	HomepageUrl = 0x0213
	OnlineOnly = 0x0230
	Birthday = 0x023A
	Notes = 0x0258
	HomeAddress = 0x0262
	HomeZip = 0x026C
	HomePhone = 0x0276
	HomeFax = 0x0280
	HomeCell = 0x028A
	WorkAddress = 0x0294
	WorkCity = 0x029E
	WorkState = 0x02A8
	WorkCountry = 0x02B2
	WorkZip = 0x02BC
	WorkPhone = 0x02C6
	WorkFax = 0x02D0
	WorkWebpage = 0x02DA
	Authorization = 0x02F8
	WebAware = 0x030C
	GmtOffset = 0x0316

# search hits' online status
DIR_STATUS_OFFLINE = 0
DIR_STATUS_ONLINE = 1
DIR_STATUS_HIDDEN = 2

MAX_SEARCH_RESULTS = 20


class LE:
	# a little-endian writer, the byte order the ICQ envelope inside foodgroup 0x15 uses
	__slots__ = ('data',)

	def __init__(self) -> None:
		self.data = b''

	def u8(self, value: int) -> 'LE':
		self.data += struct.pack('<B', value & 0xFF)
		return self

	def u16(self, value: int) -> 'LE':
		self.data += struct.pack('<H', value & 0xFFFF)
		return self

	def u32(self, value: int) -> 'LE':
		self.data += struct.pack('<L', value & 0xFFFFFFFF)
		return self

	def raw(self, value: bytes) -> 'LE':
		self.data += value
		return self

	def string(self, value: str) -> 'LE':
		# u16 length, then the text and its NUL; an empty string is just a zero length
		if not value:
			return self.u16(0)
		encoded = icq.latin1(value) + b'\x00'
		return self.u16(len(encoded)).raw(encoded)

class LEReader:
	__slots__ = ('data', 'pos')

	def __init__(self, data: bytes) -> None:
		self.data = data
		self.pos = 0

	def remaining(self) -> int:
		return len(self.data) - self.pos

	def _take(self, length: int) -> bytes:
		if self.pos + length > len(self.data):
			raise ValueError('truncated ICQ request')
		chunk = self.data[self.pos:self.pos + length]
		self.pos += length
		return chunk

	def u8(self) -> int:
		return self._take(1)[0]

	def u16(self) -> int:
		return struct.unpack('<H', self._take(2))[0]

	def u32(self) -> int:
		return struct.unpack('<L', self._take(4))[0]

	def string(self) -> str:
		raw = self._take(self.u16())
		if b'\x00' in raw:
			raw = raw[:raw.index(b'\x00')]
		return icq.from_latin1(raw)

	def rest(self) -> bytes:
		chunk = self.data[self.pos:]
		self.pos = len(self.data)
		return chunk

def parse_le_tlvs(data: bytes) -> list[tuple[int, bytes]]:
	# the TLV-based ICQ requests use little-endian TLVs
	tlvs = []
	reader = LEReader(data)
	while reader.remaining() >= 4:
		tag = reader.u16()
		length = reader.u16()
		if reader.remaining() < length:
			break
		tlvs.append((tag, reader._take(length)))
	return tlvs

def tlv_string(value: bytes) -> str:
	try:
		return LEReader(value).string()
	except ValueError:
		return ''

def tlv_int(value: bytes) -> int:
	if len(value) >= 4:
		return struct.unpack('<L', value[:4])[0]
	if len(value) >= 2:
		return struct.unpack('<H', value[:2])[0]
	return value[0] if value else 0


class ICQContext:
	# one ICQ__DB_QUERY being answered: who asked, under which SNAC request id and ICQ sequence number
	__slots__ = ('client', 'context', 'request_id', 'seq', 'uin')

	def __init__(self, client: OSCARClient, context: OSCARContext, request_id: int, seq: int) -> None:
		self.client = client
		self.context = context
		self.request_id = request_id
		self.seq = seq
		self.uin = names.uin_of(context.user) or 0

	def reply(self, reply_type: int, body: bytes, *, more: bool = False) -> None:
		# ICQ__DB_REPLY: TLV 0x01 holding a u16 (LE) length, then u32 UIN, u16 reply type, u16 sequence and the body
		envelope = LE().u32(self.uin).u16(reply_type).u16(self.seq).raw(body).data
		msg = SNACMessage(0x0015, 0x0003, 0x0001 if more else 0x0000, self.request_id)
		msg.write_tlv(TLV(0x0001, LE().u16(len(envelope)).raw(envelope).data))
		self.client.send_snac(msg)

	def meta(self, subtype: int, result: int, body: bytes = b'', *, more: bool = False) -> None:
		self.reply(ICQReply.Meta, LE().u16(subtype).u8(result).raw(body if result == ICQResult.Ok else b'').data, more = more)


@Foodgroup(0x0015)
class ICQFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def db_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		tlvs = unmarshal_tlvs(message.data)
		envelope_tlv = find_tlv(tlvs, 0x0001)
		if envelope_tlv is None or len(envelope_tlv.data) < 2:
			self.logger.info('[Client] ICQ__DB_QUERY without its envelope')
			return

		# TLV 0x01: u16 (LE) length, u32 UIN, u16 request type, u16 sequence, [u16 meta subtype], request data
		reader = LEReader(envelope_tlv.data)
		try:
			length = reader.u16()
			reader = LEReader(reader._take(min(length, reader.remaining())))
			reader.u32()
			request_type = reader.u16()
			seq = reader.u16()
		except ValueError:
			self.logger.info('[Client] Truncated ICQ__DB_QUERY')
			return

		query = ICQContext(client, context, message.request_id, seq)
		if request_type == ICQRequest.OfflineMessages:
			self.logger.info('[Client] ICQ__DB_QUERY offline messages')
			offline_messages(query)
		elif request_type == ICQRequest.DeleteOfflineMessages:
			self.logger.info('[Client] ICQ__DB_QUERY delete offline messages')
			delete_offline_messages(query)
		elif request_type == ICQRequest.Meta:
			try:
				subtype = reader.u16()
			except ValueError:
				return
			self.logger.info('[Client] ICQ__DB_QUERY meta', hex(subtype))
			handler = META_HANDLERS.get(subtype)
			if handler is None:
				self.logger.info('[Client] Unsupported ICQ meta request', hex(subtype))
				return
			try:
				handler(query, reader)
			except ValueError:
				self.logger.info('[Client] Malformed ICQ meta request', hex(subtype))
		else:
			self.logger.info('[Client] Unknown ICQ__DB_QUERY request type', hex(request_type))


# offline messages

def offline_messages(query: ICQContext) -> None:
	# reading the store is file work, done off the event loop
	query.context.backend.loop.create_task(_offline_messages(query))

async def _offline_messages(query: ICQContext) -> None:
	# each stored message from someone with a UIN goes back as an offline message record (0x41); the rest only an ICBM
	# can carry, since 0x41 has no room for a screen name. 0x42 ends it, and the messages go once the client deletes them
	context = query.context
	backend = context.backend
	bs = context.bs
	from .icbm import deliver_offline_messages
	oims = await backend.loop.run_in_executor(None, backend.user_service.get_oim_batch, context.user)
	if bs.closed:
		return
	pending = bs.front_data.setdefault('oscar0_offline_delivered', [])
	for oim in oims:
		sender = _oim_sender(backend, oim)
		uin = names.uin_of(sender) if sender is not None else None
		if uin is None:
			deliver_offline_messages(query.client.ctrl, [oim])
			continue
		sent = oim.sent if isinstance(oim.sent, datetime) else datetime.utcnow()
		body = LE().u32(uin).u16(sent.year).u8(sent.month).u8(sent.day).u8(sent.hour).u8(sent.minute)
		body.u8(0x01).u8(0x00).string((oim.message or '').replace('\r\n', '\n').replace('\n', '\r\n'))
		query.reply(ICQReply.OfflineMessage, body.data, more = True)
		pending.append(oim.uuid)
	query.reply(ICQReply.OfflineMessagesDone, LE().u8(0).data)

def delete_offline_messages(query: ICQContext) -> None:
	context = query.context
	delivered = context.bs.front_data.pop('oscar0_offline_delivered', [])
	if delivered:
		from .icbm import delete_stored_messages
		context.backend.loop.create_task(delete_stored_messages(context.backend, context.user.uuid, delivered))

def _oim_sender(backend: Any, oim: OIM) -> User | None:
	uuid = backend.util_get_uuid_from_username(oim.from_username) if oim.from_username else None
	if uuid is None and oim.from_email:
		uuid = backend.util_get_uuid_from_email(oim.from_email)
	return backend._load_user_record(uuid) if uuid is not None else None


# user info

def _find(backend: Any, uin: int) -> User | None:
	uuid = backend.util_get_uuid_from_uin(uin)
	return backend._load_user_record(uuid) if uuid is not None else None

def _listed(user: User, viewer: User | None = None) -> bool:
	# the white pages only show someone who listed themselves in the member directory (or themselves, to themselves)
	return user is viewer or bool(getattr(user, 'show_in_dir', False))

def _auth_flag(user: User) -> int:
	# 0 means authorization required, 1 that anyone may add this user
	return 0 if icq.permissions(user)['auth_required'] else 1

def basic_info_body(user: User, viewer: User | None = None) -> bytes:
	info = icq.basic_info(user)
	perms = icq.permissions(user)
	listed = _listed(user, viewer)
	body = LE().string(info['nick'])
	# real names and contact details only for people listed in the directory
	for field in ('first', 'last'):
		body.string(info[field] if listed else '')
	body.string(info['email'] if info['publish_email'] or user is viewer else '')
	for field in ('city', 'state', 'phone', 'fax', 'address', 'cell', 'zip'):
		body.string(info[field] if listed else '')
	body.u16(info['country'] if listed else 0).u8(info['gmt'])
	body.u8(_auth_flag(user)).u8(1 if perms['web_aware'] else 0).u8(0)
	# publish e-mail: 0 yes, 1 no
	body.u8(0 if info['publish_email'] else 1)
	return body.data

def more_info_body(user: User, viewer: User | None = None) -> bytes:
	more = icq.more_info(user)
	info = icq.basic_info(user)
	listed = _listed(user, viewer)
	body = LE().u16(icq.age(user) if listed else 0).u8(more['gender'] if listed else 0).string(more['homepage'] if listed else '')
	body.u16(more['birth_year'] if listed else 0).u8(more['birth_month'] if listed else 0).u8(more['birth_day'] if listed else 0)
	body.u8(more['lang1']).u8(more['lang2']).u8(more['lang3']).u16(0)
	body.string(info['city'] if listed else '').string(info['state'] if listed else '').u16(info['country'] if listed else 0)
	body.u8(info['gmt'])
	# trailing bytes ICQ 5 wants, or it reports "error 117"
	body.raw(bytes(4))
	return body.data

def work_info_body(user: User, viewer: User | None = None) -> bytes:
	work = icq.work_info(user) if _listed(user, viewer) else { field: '' for field in ('city', 'state', 'phone', 'fax', 'address', 'zip', 'company', 'department', 'position', 'webpage') }
	body = LE()
	for field in ('city', 'state', 'phone', 'fax', 'address', 'zip'):
		body.string(work[field])
	body.u16(work.get('country', 0) or 0)
	for field in ('company', 'department', 'position'):
		body.string(work[field])
	body.u16(work.get('occupation', 0) or 0).string(work['webpage'])
	return body.data

def _pairs_body(pairs: list[list[Any]]) -> LE:
	body = LE().u8(len(pairs))
	for code, keyword in pairs:
		body.u16(int(code)).string(keyword)
	return body

def short_info_body(user: User, viewer: User | None = None) -> bytes:
	info = icq.basic_info(user)
	listed = _listed(user, viewer)
	body = LE().string(info['nick']).string(info['first'] if listed else '').string(info['last'] if listed else '')
	body.string(info['email'] if info['publish_email'] or user is viewer else '').u8(_auth_flag(user)).u8(0)
	body.u8(icq.more_info(user)['gender'] if listed else 0)
	return body.data

def search_record(query: ICQContext, user: User) -> bytes:
	# a search hit: u16 length, then UIN, nick, first, last, e-mail, auth flag, online status, gender, age
	info = icq.basic_info(user)
	listed = _listed(user, query.context.user)
	record = LE().u32(names.uin_of(user) or 0).string(info['nick'])
	record.string(info['first'] if listed else '').string(info['last'] if listed else '')
	record.string(info['email'] if info['publish_email'] else '')
	record.u8(_auth_flag(user)).u16(_search_status(query, user))
	record.u8(icq.more_info(user)['gender'] if listed else 0).u16(icq.age(user) if listed else 0)
	return LE().u16(len(record.data)).raw(record.data).data

def _search_status(query: ICQContext, user: User) -> int:
	# someone not "web aware" shows as hidden whether or not they're on
	if not icq.permissions(user)['web_aware']:
		return DIR_STATUS_HIDDEN
	sessions = query.context.backend.util_get_sessions_by_user(user)
	return DIR_STATUS_ONLINE if sessions and not user.status.is_offlineish() else DIR_STATUS_OFFLINE

def search_results(query: ICQContext, users: list[User]) -> None:
	# every hit but the last is "user found" (with the trailing bytes ICQ 5 wants); the last says how many are left
	users = [user for user in users if names.uin_of(user) is not None][:MAX_SEARCH_RESULTS]
	if not users:
		query.meta(ICQMeta.LastUserFound, ICQResult.Fail)
		return
	for index, user in enumerate(users):
		if index < len(users) - 1:
			query.meta(ICQMeta.UserFound, ICQResult.Ok, search_record(query, user) + bytes(12), more = True)
		else:
			query.meta(ICQMeta.LastUserFound, ICQResult.Ok, search_record(query, user) + LE().u32(0).data + bytes(8))

def _users(backend: Any, uuids: list[str]) -> list[User]:
	users = []
	for uuid in uuids:
		user = backend._load_user_record(uuid)
		if user is not None:
			users.append(user)
	return users


def meta_short_info(query: ICQContext, reader: LEReader) -> None:
	user = _find(query.context.backend, reader.u32())
	if user is None:
		query.meta(ICQMeta.ShortInfoReply, ICQResult.Error)
		return
	query.meta(ICQMeta.ShortInfoReply, ICQResult.Ok, short_info_body(user, query.context.user))

def meta_full_info(query: ICQContext, reader: LEReader) -> None:
	# basic, more, extra e-mails, homepage category, work, notes, interests, affiliations: each part says more follow
	user = _find(query.context.backend, reader.u32())
	if user is None:
		query.meta(ICQMeta.BasicInfo, ICQResult.Error)
		return
	viewer = query.context.user
	listed = _listed(user, viewer)
	parts = [
		(ICQMeta.BasicInfo, basic_info_body(user, viewer)),
		(ICQMeta.MoreInfo, more_info_body(user, viewer)),
		(ICQMeta.ExtEmails, LE().u8(0).data),
		(ICQMeta.HomepageCategory, LE().u8(0).u16(0).string('').u8(0).data),
		(ICQMeta.WorkInfo, work_info_body(user, viewer)),
		(ICQMeta.Notes, LE().string(icq.notes(user) if listed else '').data),
		(ICQMeta.Interests, _pairs_body(icq.interests(user) if listed else []).data),
		(ICQMeta.Affiliations, (
			_pairs_body(icq.affiliations(user)['past'] if listed else []).data
			+ _pairs_body(icq.affiliations(user)['current'] if listed else []).data
		)),
	]
	for index, (subtype, body) in enumerate(parts):
		query.meta(subtype, ICQResult.Ok, body, more = index < len(parts) - 1)

def meta_search_by_uin(query: ICQContext, reader: LEReader) -> None:
	# finding someone by their exact number is how ICQ adds a contact, so it doesn't need a directory listing
	user = _find(query.context.backend, reader.u32())
	search_results(query, [user] if user is not None else [])

def meta_search_by_uin2(query: ICQContext, reader: LEReader) -> None:
	uin = next((tlv_int(value) for tag, value in parse_le_tlvs(reader.rest()) if tag == ICQTag.Uin), 0)
	user = _find(query.context.backend, uin) if uin else None
	search_results(query, [user] if user is not None else [])

def meta_search_by_email(query: ICQContext, reader: LEReader) -> None:
	email = reader.string()
	search_results(query, _users(query.context.backend, query.context.backend.user_service.search_uuids(email = email)))

def meta_search_by_email3(query: ICQContext, reader: LEReader) -> None:
	email = next((tlv_string(value) for tag, value in parse_le_tlvs(reader.rest()) if tag == ICQTag.Email), '')
	search_results(query, _users(query.context.backend, query.context.backend.user_service.search_uuids(email = email)) if email else [])

def meta_search_by_details(query: ICQContext, reader: LEReader) -> None:
	first, last, nick = reader.string(), reader.string(), reader.string()
	uuids = query.context.backend.user_service.search_uuids(first_name = first, last_name = last, nickname = nick)
	search_results(query, _users(query.context.backend, uuids))

def meta_search_white_pages(query: ICQContext, reader: LEReader) -> None:
	# the fixed-layout white pages search: first, last, nick and e-mail lead it, the rest narrows (and isn't kept here)
	first, last, nick, email = reader.string(), reader.string(), reader.string(), reader.string()
	uuids = query.context.backend.user_service.search_uuids(email = email, first_name = first, last_name = last, nickname = nick)
	search_results(query, _users(query.context.backend, uuids))

def meta_search_white_pages2(query: ICQContext, reader: LEReader) -> None:
	criteria = {}
	online_only = False
	uin = 0
	for tag, value in parse_le_tlvs(reader.rest()):
		if tag == ICQTag.Uin:
			uin = tlv_int(value)
		elif tag == ICQTag.FirstName:
			criteria['first_name'] = tlv_string(value)
		elif tag == ICQTag.LastName:
			criteria['last_name'] = tlv_string(value)
		elif tag == ICQTag.Nickname:
			criteria['nickname'] = tlv_string(value)
		elif tag == ICQTag.Email:
			criteria['email'] = tlv_string(value)
		elif tag == ICQTag.OnlineOnly:
			online_only = bool(tlv_int(value))
	backend = query.context.backend
	if uin:
		user = _find(backend, uin)
		users = [user] if user is not None else []
	else:
		users = _users(backend, backend.user_service.search_uuids(**{ k: v for k, v in criteria.items() if v }))
	if online_only:
		users = [user for user in users if _search_status(query, user) == DIR_STATUS_ONLINE]
	search_results(query, users)

def _save(query: ICQContext) -> None:
	icq.save(query.context.backend, query.context.user)

def meta_set_basic_info(query: ICQContext, reader: LEReader) -> None:
	fields = { field: reader.string() for field in ('nick', 'first', 'last', 'email', 'city', 'state', 'phone', 'fax', 'address', 'cell', 'zip') }
	fields['country'] = reader.u16()
	fields['gmt'] = reader.u8()
	# publish e-mail: 0 yes, 1 no
	fields['publish_email'] = reader.u8() == 0 if reader.remaining() else False
	_set_nickname(query, fields['nick'])
	icq.set_basic(query.context.user, fields)
	_save(query)
	query.meta(ICQMeta.SetBasicInfoAck, ICQResult.Ok)

def _set_nickname(query: ICQContext, nick: str) -> None:
	# the ICQ nickname is what other people see this account as, which elsewhere is its friendly name
	if nick and nick != query.context.user.status.name:
		query.context.bs.me_update({ 'name': nick })

def meta_set_work_info(query: ICQContext, reader: LEReader) -> None:
	fields: dict[str, Any] = { field: reader.string() for field in ('city', 'state', 'phone', 'fax', 'address', 'zip') }
	fields['country'] = reader.u16()
	for field in ('company', 'department', 'position'):
		fields[field] = reader.string()
	fields['occupation'] = reader.u16()
	fields['webpage'] = reader.string()
	icq.set_work(query.context.user, fields)
	_save(query)
	query.meta(ICQMeta.SetWorkInfoAck, ICQResult.Ok)

def meta_set_more_info(query: ICQContext, reader: LEReader) -> None:
	# u8 age (worked out from the birth date instead), u16 gender, homepage, u16 year, u8 month, u8 day, three languages
	reader.u8()
	fields = { 'gender': reader.u16() & 0xFF, 'homepage': reader.string(), 'birth_year': reader.u16(), 'birth_month': reader.u8() }
	fields['birth_day'] = reader.u8()
	for lang in ('lang1', 'lang2', 'lang3'):
		fields[lang] = reader.u8() if reader.remaining() else 0
	icq.set_more(query.context.user, fields)
	_save(query)
	query.meta(ICQMeta.SetMoreInfoAck, ICQResult.Ok)

def meta_set_notes(query: ICQContext, reader: LEReader) -> None:
	icq.set_notes(query.context.user, reader.string())
	_save(query)
	query.meta(ICQMeta.SetNotesAck, ICQResult.Ok)

def meta_set_emails(query: ICQContext, reader: LEReader) -> None:
	# extra e-mail addresses aren't kept, but the client needs its answer
	query.meta(ICQMeta.SetEmailsAck, ICQResult.Ok)

def _read_pairs(reader: LEReader) -> list[list[Any]]:
	count = reader.u8()
	return [[reader.u16(), reader.string()] for _ in range(count)]

def meta_set_interests(query: ICQContext, reader: LEReader) -> None:
	icq.set_interests(query.context.user, _read_pairs(reader))
	_save(query)
	query.meta(ICQMeta.SetInterestsAck, ICQResult.Ok)

def meta_set_affiliations(query: ICQContext, reader: LEReader) -> None:
	past = _read_pairs(reader)
	current = _read_pairs(reader)
	icq.set_affiliations(query.context.user, past, current)
	_save(query)
	query.meta(ICQMeta.SetAffiliationsAck, ICQResult.Ok)

def meta_set_permissions(query: ICQContext, reader: LEReader) -> None:
	# u8 authorization (0: required, 1: anyone may add), u8 web aware, u8 direct connection permissions, u8 unknown
	authorization = reader.u8()
	web_aware = reader.u8() if reader.remaining() else 0
	icq.set_permissions(query.context.user, auth_required = authorization == 0, web_aware = web_aware == 1)
	_save(query)
	query.meta(ICQMeta.SetPermissionsAck, ICQResult.Ok)

def meta_set_icq_phone(query: ICQContext, reader: LEReader) -> None:
	query.meta(ICQMeta.SetIcqPhoneAck, ICQResult.Ok)

def meta_set_full_info(query: ICQContext, reader: LEReader) -> None:
	# ICQ Lite's all-in-one update: only the fields it sends change
	basic: dict[str, Any] = {}
	more: dict[str, Any] = {}
	work: dict[str, Any] = {}
	user = query.context.user
	strings = {
		ICQTag.FirstName: (basic, 'first'), ICQTag.LastName: (basic, 'last'), ICQTag.Nickname: (basic, 'nick'),
		ICQTag.HomeCity: (basic, 'city'), ICQTag.HomeState: (basic, 'state'), ICQTag.HomeAddress: (basic, 'address'),
		ICQTag.HomePhone: (basic, 'phone'), ICQTag.HomeFax: (basic, 'fax'), ICQTag.HomeCell: (basic, 'cell'),
		ICQTag.HomepageUrl: (more, 'homepage'), ICQTag.WorkCompany: (work, 'company'), ICQTag.WorkDepartment: (work, 'department'),
		ICQTag.WorkPosition: (work, 'position'), ICQTag.WorkAddress: (work, 'address'), ICQTag.WorkCity: (work, 'city'),
		ICQTag.WorkState: (work, 'state'), ICQTag.WorkPhone: (work, 'phone'), ICQTag.WorkFax: (work, 'fax'),
		ICQTag.WorkWebpage: (work, 'webpage'),
	}
	for tag, value in parse_le_tlvs(reader.rest()):
		if tag in strings:
			section, field = strings[tag]
			section[field] = tlv_string(value)
		elif tag == ICQTag.Email and len(value) >= 2:
			basic['email'] = tlv_string(value)
		elif tag == ICQTag.HomeCountry:
			basic['country'] = tlv_int(value) & 0xFFFF
		elif tag == ICQTag.WorkCountry:
			work['country'] = tlv_int(value) & 0xFFFF
		elif tag == ICQTag.HomeZip:
			basic['zip'] = str(tlv_int(value))
		elif tag == ICQTag.WorkZip:
			work['zip'] = str(tlv_int(value))
		elif tag == ICQTag.WorkOccupation:
			work['occupation'] = tlv_int(value) & 0xFFFF
		elif tag == ICQTag.GmtOffset and value:
			basic['gmt'] = value[0]
		elif tag == ICQTag.Gender and value:
			more['gender'] = value[0]
		elif tag == ICQTag.Birthday and len(value) >= 6:
			# u16 year, u16 month, u16 day
			more['birth_year'], more['birth_month'], more['birth_day'] = struct.unpack('<HHH', value[:6])
		elif tag == ICQTag.Notes:
			icq.set_notes(user, tlv_string(value))
		elif tag == ICQTag.Authorization and value:
			icq.set_permissions(user, auth_required = value[0] == 0)
		elif tag == ICQTag.WebAware and value:
			icq.set_permissions(user, web_aware = value[0] == 1)
	if 'nick' in basic:
		_set_nickname(query, basic['nick'])
	icq.set_basic(user, basic)
	icq.set_more(user, more)
	icq.set_work(user, work)
	_save(query)
	query.meta(ICQMeta.SetFullInfoAck, ICQResult.Ok)

def meta_xml_request(query: ICQContext, reader: LEReader) -> None:
	# server-side XML data (ICQ's "what's new" and such) isn't something there is any of
	query.meta(ICQMeta.XmlReply, ICQResult.Error)

def meta_directory_query(query: ICQContext, reader: LEReader) -> None:
	# ICQ 6's directory protocol, a SNAC of its own (family 0x05B9) inside the request; it gets the empty answer Open
	# OSCAR Server sends for what it doesn't handle: the request's subtype, result 0, nothing found
	payload = reader.rest()
	if len(payload) < 2 + 10:
		return
	body = payload[2:]
	subtype, flags = struct.unpack('>HH', body[2:6])
	versioned = bool(flags & 0x8000)
	nested = struct.pack('>HHHHH', 0x05B9, subtype, 0x8000 if versioned else 0x0000, 0, 0)
	if versioned:
		# the version block the request came with, mirrored: TLV 0x01 = 2
		version = TLV(0x0001, struct.pack('>H', 0x0002)).marshal()
		nested += struct.pack('>H', len(version)) + version
	# u8 result, string16 error message, 10 bytes nothing, [6 more], u32 total, [u16 pages], u16 block count
	nested += struct.pack('>BH', 0, 0) + bytes(10)
	if versioned:
		nested += bytes(6)
	nested += struct.pack('>L', 0)
	if versioned:
		nested += struct.pack('>H', 0)
	nested += struct.pack('>H', 0)
	query.reply(ICQReply.Meta, LE().u16(ICQMeta.DirectoryResponse).u8(ICQResult.Ok).u16(len(nested)).raw(nested).data)


META_HANDLERS = {
	ICQMeta.ShortInfo: meta_short_info,
	ICQMeta.FullInfo: meta_full_info,
	ICQMeta.FullInfo2: meta_full_info,
	ICQMeta.SearchByUin: meta_search_by_uin,
	ICQMeta.SearchByUin2: meta_search_by_uin2,
	ICQMeta.SearchByEmail: meta_search_by_email,
	ICQMeta.SearchByEmail3: meta_search_by_email3,
	ICQMeta.SearchByDetails: meta_search_by_details,
	ICQMeta.SearchWhitePages: meta_search_white_pages,
	ICQMeta.SearchWhitePages2: meta_search_white_pages2,
	ICQMeta.SetBasicInfo: meta_set_basic_info,
	ICQMeta.SetWorkInfo: meta_set_work_info,
	ICQMeta.SetMoreInfo: meta_set_more_info,
	ICQMeta.SetNotes: meta_set_notes,
	ICQMeta.SetEmails: meta_set_emails,
	ICQMeta.SetInterests: meta_set_interests,
	ICQMeta.SetAffiliations: meta_set_affiliations,
	ICQMeta.SetPermissions: meta_set_permissions,
	ICQMeta.SetIcqPhone: meta_set_icq_phone,
	ICQMeta.SetFullInfo: meta_set_full_info,
	ICQMeta.XmlRequest: meta_xml_request,
	ICQMeta.DirectoryQuery: meta_directory_query,
}
