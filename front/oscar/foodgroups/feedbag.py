import time
import struct
import base64
import hashlib

from array import array
from core import error
from core.models import ContactList, Substatus, Contact, Group, User, _aim_pd_mode
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Any
from util.misc import Logger, is_valid_oscar_screenname

from .buddy import build_presence_notif # TODO(subpurple): move build_presence_notif out of buddy?
from .buddy import push_presence, push_buddy_list
from .pd import PDMode, PDStatus, apply_pd_info, pd_add, pd_remove
from ..proto import names
from ..proto import bart
from ..proto.delivery import oscar_sessions, feedbag_sessions
from ..proto.tlv import TLV, find_tlv, marshal_tlvs
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.buffer import Buffer
from util import icq

class FeedbagClass(IntEnum):
	Buddy = 0x0000,
	Group = 0x0001,
	Permit = 0x0002,
	Deny = 0x0003,
	PdInfo = 0x0004,
	BuddyPrefs = 0x0005
	NonBuddy = 0x0006
	TpaProvider = 0x0007
	TpaSubscription = 0x0008
	ClientPrefs = 0x0009
	Stock = 0x000A
	Weather = 0x000B
	WatchList = 0x000D
	IgnoreList = 0x000E
	DateTime = 0x000F
	ExternalUser = 0x0010
	RootCreator = 0x0011
	Fish = 0x0012
	ImportTimestamp = 0x0013
	Bart = 0x0014
	RbOrder = 0x0015
	Personality = 0x0016
	AlProf = 0x0017
	AlInfo = 0x0018
	Interaction = 0x0019
	VanityInfo = 0x001D
	FavoriteLocation = 0x001E
	BartPdInfo = 0x001F
	CustomEmoticons = 0x0024
	IcqStatusNote = 0x015C


class FeedbagAttributes(IntEnum):
	Order = 0x00C8,
	PdMode = 0x00CA,
	WirelessPdMode = 0x00D0,
	WirelessIgnoreMode = 0x00D1,
	FishPdMode = 0x00D2,
	FishIgnoreMode = 0x00D3,
	PdMask = 0x00CB,
	BuddyPrefs = 0x00C9
	Pending = 0x0066
	TimeT = 0x0067
	PdFlags = 0x00CC
	BartInfo = 0x00D5

class FeedbagStatus(IntEnum):
	Success = 0x0000,
	NotFound = 0x0002,
	AlreadyExists = 0x0003,
	BadRequest = 0x000A,
	OverLimit = 0x000C,
	BadLoginID = 0x0010,
	DbError = 0x0001
	Unavailable = 0x0005
	DbTimeOut = 0x000B
	NotExecuted = 0x000D
	AuthRequired = 0x000E
	AutoAuth = 0x000F
	OverBuddyLimit = 0x0011
	InsertSmartGroup = 0x0014
	Timeout = 0x001A

class FeedbagError(IntEnum):
	# unconfirmed on the NINA wiki, but the only FEEDBAG__ERR code it records
	BuddyListUnavailable = 0x0005

# limits mirror what FEEDBAG__RIGHTS_REPLY advertises
MAX_ID = 0x7FFF
MAX_ITEM_NAME_LEN = 97
MAX_ITEM_ATTRS_SIZE = 1698
MAX_BUDDIES = 1000
MAX_GROUPS = 100
MAX_BUDDIES_PER_GROUP = 600
MAX_CLIENT_ITEMS = 100
MIN_CLIENT_CLASS = 0x0400
MAX_REPLY_ITEM_BYTES = 0xE000

# everything the backend model has no native home for lives in user.settings under this key
SSI_KEY = 'AIM_SSI'

# the privacy mode/mask the permit/deny logic in core.models reads
PD_KEY = 'AIM_PD'

KNOWN_CLASSES = frozenset(int(c) for c in FeedbagClass)

# classes the wiki marks (R): only valid in the root group
ROOT_ONLY_CLASSES = frozenset({
	FeedbagClass.Permit, FeedbagClass.Deny, FeedbagClass.PdInfo, FeedbagClass.BuddyPrefs, FeedbagClass.NonBuddy,
	FeedbagClass.ClientPrefs, FeedbagClass.DateTime, FeedbagClass.Bart, FeedbagClass.RbOrder, FeedbagClass.Personality,
	FeedbagClass.AlProf, FeedbagClass.AlInfo, FeedbagClass.Interaction, FeedbagClass.VanityInfo,
	FeedbagClass.FavoriteLocation, FeedbagClass.BartPdInfo,
})

# classes limited to one item, which must have "" for a name
SINGLE_ITEM_CLASSES = frozenset({FeedbagClass.PdInfo, FeedbagClass.BuddyPrefs})

# every attribute tag registered in the FEEDBAG__ATTRIBUTES table (the server rejects unregistered tags below 0x2710)
REGISTERED_ATTRIBUTES = frozenset({
	0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006D, 0x006F,
	0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, 0x00D0, 0x00D1, 0x00D2, 0x00D3,
	0x00D4, 0x00D5, 0x00D6, 0x00D7, 0x00D8, 0x00D9,
	0x012C, 0x012D, 0x012E, 0x012F, 0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135, 0x0136, 0x0137,
	0x0138, 0x0139, 0x013A, 0x013B, 0x013C, 0x013D, 0x013E, 0x013F, 0x0140, 0x0141, 0x0142, 0x0143,
	0x0145, 0x0150, 0x0151, 0x0152, 0x0153, 0x0154, 0x0158, 0x0159, 0x015F, 0x0167, 0x016E,
})


@dataclass
class FeedbagItem:
	name: str
	group_id: int
	item_id: int
	class_id: int
	attributes: array[TLV]
	# for buddies and permit/deny entries: the screen name (lowercased) the item stands for, whatever form `name` is in
	key: Optional[str]

	def __init__(self, name: str, group_id: int, item_id: int, class_id: int, attributes: Optional[array[TLV]] = None, key: Optional[str] = None) -> None:
		self.name = name
		self.group_id = group_id
		self.item_id = item_id
		self.class_id = class_id
		self.attributes = attributes or []
		self.key = key

	def marshal(self) -> bytes:
		buf = Buffer()
		buf.write_string_u16(self.name)
		buf.write_u16(self.group_id)
		buf.write_u16(self.item_id)
		buf.write_u16(self.class_id)
		buf.write_tlv_l_block(self.attributes)

		return buf.data


def _get_store(user: User) -> dict[str, Any]:
	store = user.settings.get(SSI_KEY)
	if not isinstance(store, dict):
		store = {}
		user.settings[SSI_KEY] = store
	return store

def _attrs_to_json(attrs: list[TLV]) -> list[list[Any]]:
	return [[tlv.type, base64.b64encode(tlv.data).decode('ascii')] for tlv in attrs]

def _attrs_from_json(attrs: list[list[Any]]) -> list[TLV]:
	return [TLV(tag, base64.b64decode(data)) for tag, data in attrs]

def _to_int(value: str, default: int = 1) -> int:
	try:
		return int(value)
	except ValueError:
		return default

def _compress(name: str) -> str:
	# "abc", "a b c" and "aBc" are the same name as far as the uniqueness rules go
	return name.replace(' ', '').lower()

def _alloc_id(preferred: int, used: set[int]) -> int:
	# ids 0x8000 and above are reserved for the server
	candidate = preferred if 0 < preferred <= MAX_ID else 1
	while candidate in used:
		candidate = candidate + 1 if candidate < MAX_ID else 1
	used.add(candidate)
	return candidate

def _encode_order(ids: list[int]) -> bytes:
	return b''.join(struct.pack('>H', ident) for ident in ids)

def _decode_order(tlv: Optional[TLV]) -> list[int]:
	if tlv is None:
		return []
	return [struct.unpack('>H', tlv.data[i:i + 2])[0] for i in range(0, len(tlv.data) - 1, 2)]

def _apply_order(stored: list[str], entries: list[tuple[str, int]]) -> list[int]:
	# stored names first (in the client's order), then anything the client hasn't ordered yet
	by_name = dict(entries)
	ordered = [by_name[name] for name in dict.fromkeys(stored) if name in by_name]
	return ordered + [ident for _, ident in entries if ident not in ordered]

def _time_of(attrs: list[TLV]) -> int:
	tlv = find_tlv(attrs, FeedbagAttributes.TimeT)
	return struct.unpack('>L', tlv.data[:4])[0] if tlv is not None and len(tlv.data) >= 4 else 0

def _stamp_time(attrs: list[TLV], previous: int) -> list[TLV]:
	# the server always overrides TIME_T, and keeps it strictly increasing
	stamped = max(int(time.time()), previous + 1)
	return [tlv for tlv in attrs if tlv.type != FeedbagAttributes.TimeT] + [TLV(FeedbagAttributes.TimeT, struct.pack('>L', stamped))]


def get_items(context: OSCARContext) -> list[FeedbagItem]:
	user = context.user
	detail = user.detail
	store = _get_store(user)

	battrs: dict[str, list[list[Any]]] = store.get('battrs', {})
	gattrs: dict[str, list[list[Any]]] = store.get('gattrs', {})
	border: dict[str, list[str]] = store.get('border', {})
	misc: list[dict[str, Any]] = store.get('misc', [])
	permits: set[str] = set(store.get('permits', []))

	# only contacts whose screen name is representable over OSCAR ever show up here
	def valid(lst: ContactList) -> list[Contact]:
		return sorted(
			[ctc for ctc in detail.get_contacts_by_list(lst) if names.representable(ctc.head)],
			key = lambda ctc: ctc.head.id,
		)

	fl = valid(ContactList.FL)
	items: list[FeedbagItem] = []
	used_gids: set[int] = {0}
	used_iids: set[int] = {int(entry['i']) for entry in misc}
	group_entries: list[tuple[str, int]] = []

	def add_group(name: str, preferred: int, members: list[Contact]) -> None:
		gkey = name.lower()
		gid = _alloc_id(preferred, used_gids)
		buddy_entries: list[tuple[str, int]] = []
		for ctc in members:
			iid = _alloc_id(ctc.head.id, used_iids)
			# each client gets its buddies by the name it knows them by (a UIN for ICQ, a screen name for AIM)
			items.append(FeedbagItem(
				names.name_for(context.bs, ctc.head), gid, iid, FeedbagClass.Buddy,
				_attrs_from_json(battrs.get('{}:{}'.format(gkey, ctc.head.username.lower()), [])),
				key = ctc.head.username.lower(),
			))
			buddy_entries.append((ctc.head.username.lower(), iid))
		items.append(FeedbagItem(name, gid, 0, FeedbagClass.Group, [
			TLV(FeedbagAttributes.Order, _encode_order(_apply_order(border.get(gkey, []), buddy_entries))),
			*_attrs_from_json(gattrs.get(gkey, [])),
		]))
		group_entries.append((gkey, gid))

	for group in sorted(detail._groups_by_id.values(), key = lambda g: (len(g.id), g.id)):
		add_group(group.name, _to_int(group.id), [ctc for ctc in fl if ctc.is_in_group_id(group.id)])

	# deal with any ungrouped contacts left
	if ungrouped := [ctc for ctc in fl if not ctc._groups]:
		add_group("(No Group)", max(used_gids) + 1, ungrouped)

	# AL-only contacts are explicit permits; buddies are implicitly allowed unless the client permitted them itself
	for ctc in valid(ContactList.AL):
		if ctc.lists & ContactList.FL and ctc.head.username.lower() not in permits:
			continue
		items.append(FeedbagItem(names.name_for(context.bs, ctc.head), 0, _alloc_id(ctc.head.id, used_iids), FeedbagClass.Permit, key = ctc.head.username.lower()))

	for ctc in valid(ContactList.BL):
		items.append(FeedbagItem(names.name_for(context.bs, ctc.head), 0, _alloc_id(ctc.head.id, used_iids), FeedbagClass.Deny, key = ctc.head.username.lower()))

	# PD__SET_GROUP_PERMIT_MASK only touches the user's settings, so a stored PDINFO item picks the mask up here
	stored_pd = user.settings.get(PD_KEY)
	pd_mask_override = stored_pd.get('mask') if isinstance(stored_pd, dict) else None

	for entry in misc:
		attrs = _attrs_from_json(entry['a'])
		if entry['c'] == FeedbagClass.PdInfo and pd_mask_override is not None:
			attrs = [tlv for tlv in attrs if tlv.type != FeedbagAttributes.PdMask] + [
				TLV(FeedbagAttributes.PdMask, struct.pack('>L', int(pd_mask_override)))
			]
		items.append(FeedbagItem(entry['n'], entry['g'], entry['i'], entry['c'], attrs))

	present = {entry['c'] for entry in misc}

	# defaults are synthesised until the client first stores its own copy
	if FeedbagClass.PdInfo not in present:
		pd = _aim_pd_mode(user)
		if pd is not None:
			pd_mode = pd['mode']
			pd_mask = int(pd.get('mask', 0xFFFFFFFF))
		else:
			pd_mode = PDMode.DenySome if user.settings.get('BLP', 'AL') == 'AL' else PDMode.PermitOnList
			pd_mask = 0xFFFFFFFF
		items.append(FeedbagItem("", 0x0000, _alloc_id(0x0E63, used_iids), FeedbagClass.PdInfo, [
			TLV(FeedbagAttributes.PdMode,			struct.pack(">B", pd_mode)),
			TLV(FeedbagAttributes.WirelessPdMode,	struct.pack(">B", 0x0001)),
			TLV(FeedbagAttributes.WirelessIgnoreMode, struct.pack(">B", 0x0001)),
			TLV(FeedbagAttributes.FishPdMode,		struct.pack(">B", 0x0001)),
			TLV(FeedbagAttributes.FishIgnoreMode,	struct.pack(">B", 0x0001)),
			TLV(FeedbagAttributes.PdMask,			struct.pack(">L", pd_mask)),
			TLV(FeedbagAttributes.PdFlags,			struct.pack(">L", 0x00000001)),
		]))

	if FeedbagClass.BuddyPrefs not in present:
		items.append(FeedbagItem("", 0x0000, _alloc_id(0x4B1D, used_iids), FeedbagClass.BuddyPrefs, [
			TLV(FeedbagAttributes.BuddyPrefs, struct.pack(">L", 0x00000400))
		]))

	items.append(FeedbagItem("", 0x0000, 0x0000, FeedbagClass.Group, [
		TLV(FeedbagAttributes.Order, _encode_order(_apply_order(store.get('gorder', []), group_entries))),
	]))

	# FEEDBAG__REPLY items are ordered by group id, then item id (root group first)
	items.sort(key = lambda item: (item.group_id, item.item_id))
	return items


def marshal_items(items: array[FeedbagItem]) -> bytes:
	return b"".join([item.marshal() for item in items])


def _read_attributes(buf: Buffer) -> list[TLV]:
	# tlvLBlock; read here so a trailing empty TLV (COLLAPSED, PENDING) isn't dropped
	block = Buffer(buf.read_bytes(buf.read_u16()))
	tlvs: list[TLV] = []
	while len(block) >= 4:
		tag = block.read_u16()
		length = block.read_u16()
		tlvs.append(TLV(tag, block.read_bytes(length)))
	return tlvs


def unmarshal_items(item_bytes: bytes) -> array[FeedbagItem]:
	buf = Buffer(item_bytes)
	items = []

	# Minimum feedbag item size (in bytes):
	#   Name		= +2	 = 2
	#   Group ID	= +2	 = 4
	#   Item ID	 = +2	 = 6
	#   Class ID	= +2	 = 8
	#   Attributes  = +2	 = 10
	#
	while len(buf) >= 10:
		try:
			name = buf.read_string_u16()
			group_id = buf.read_u16()
			item_id = buf.read_u16()
			class_id = buf.read_u16()
			attributes = _read_attributes(buf)
		except (struct.error, UnicodeDecodeError):
			# a truncated or garbled item ends the list
			break

		items.append(FeedbagItem(name, group_id, item_id, class_id, attributes))

	return items


def _send_feedbag_status(client: OSCARClient, request_id: int, statuses: list) -> None:
	msg = SNACMessage(0x0013, 0x000E, 0x0000, request_id)
	for code in statuses:
		msg.write_u16(code)
	client.send_snac(msg)


def _resolve_group_backend_id(context: OSCARContext, client_group_id: int) -> Optional[str]:
	detail = context.user.detail
	if detail is None:
		return None
	if str(client_group_id) in detail._groups_by_id:
		return str(client_group_id)
	mapping = context.bs.front_data.get("oscar0_group_id_map", {})
	return mapping.get(client_group_id)

def _extended_info(version: int) -> bytes:
	# what SNAC flag 0x8000 puts ahead of the body: a TLV block (u16 length) holding the feedbag version in TLV 0x01
	return struct.pack('>H', 6) + TLV(0x0001, struct.pack('>H', version)).marshal()

def _string08(value: str) -> bytes:
	encoded = value.encode('latin-1', errors = 'replace')
	return struct.pack('>B', len(encoded)) + encoded

def _string16(value: str) -> bytes:
	encoded = value.encode('utf-8')
	return struct.pack('>H', len(encoded)) + encoded

def build_buddy_added_notif(adder_username: str) -> SNACMessage:
	# FEEDBAG__BUDDY_ADDED: extended info (feedbag version 4), string08 who added you, u16 0
	msg = SNACMessage(0x0013, 0x001C, 0x8000)
	msg.write_bytes(_extended_info(4))
	msg.write_bytes(_string08(adder_username))
	msg.write_u16(0)
	return msg


def send_feedbag_error(client: OSCARClient, request_id: int, code: int, *, subcode: Optional[int] = None) -> None:
	# SNAC(13,01): u16 error code, then an optional TLV(0x08) holding a u16 subcode
	msg = SNACMessage(0x0013, 0x0001, 0x0000, request_id)
	msg.write_u16(code)
	if subcode is not None:
		msg.write_tlv(TLV(0x0008, struct.pack('>H', subcode)))
	client.send_snac(msg)

def _send_feedbag_reply(client: OSCARClient, request_id: int, items: list[FeedbagItem], last_update: int) -> None:
	# a feedbag too big for one SNAC is split with flag 0x0001 on every part but the last, which alone carries the timestamp
	chunks: list[list[FeedbagItem]] = [[]]
	size = 0
	for item in items:
		item_len = len(item.marshal())
		if size + item_len > MAX_REPLY_ITEM_BYTES and chunks[-1]:
			chunks.append([])
			size = 0
		chunks[-1].append(item)
		size += item_len
	for index, chunk in enumerate(chunks):
		last = (index == len(chunks) - 1)
		msg = SNACMessage(0x0013, 0x0006, 0x0000 if last else 0x0001, request_id)
		msg.write_u8(0)						# feedbag protocol version - always 0
		msg.write_u16(len(chunk))			# no. of feedbag items
		msg.write_bytes(marshal_items(chunk))	# list of feedbag items
		if last:
			msg.write_u32(last_update)		# feedbag last change time - TODO: should pull from db
		client.send_snac(msg)

def _sync_modified(context: OSCARContext, items: list[FeedbagItem]) -> int:
	# the last-change time only moves when the marshalled feedbag actually changes (including changes made from other frontends)
	user = context.user
	store = _get_store(user)
	digest = hashlib.md5(marshal_items(items)).hexdigest()
	last_update = int(store.get('ts', 0))
	if store.get('digest') != digest or not last_update:
		last_update = max(int(time.time()), last_update + 1)
		store['ts'] = last_update
		store['digest'] = digest
		context.backend._mark_modified(user)
	return last_update

def _push_presence(client: OSCARClient, context: OSCARContext, name: str) -> None:
	# the server never pushed a freshly added buddy's presence to whoever added them, so they stayed offline until a relog
	contact_uuid = names.resolve(context.backend, name)
	contact = context.user.detail.contacts.get(contact_uuid) if contact_uuid is not None else None
	if contact is None or not context.bs.front_data.get('oscar0_ready'):
		return
	push_presence(context.bs, contact.head)

def _key_name(context: OSCARContext, name: str) -> str:
	# the screen name a client's name for someone stands for, which is what stored buddy attributes are filed under
	user = names.resolve_user(context.backend, name)
	return user.username.lower() if user is not None else names.normalize(name)


def _validate_item(item: FeedbagItem, *, check_attributes: bool, allow_pending: bool = False) -> Optional[FeedbagStatus]:
	if item.group_id > MAX_ID or item.item_id > MAX_ID or len(item.name) > MAX_ITEM_NAME_LEN:
		return FeedbagStatus.BadRequest
	if item.class_id < MIN_CLIENT_CLASS and item.class_id not in KNOWN_CLASSES:
		return FeedbagStatus.BadRequest
	if item.class_id == FeedbagClass.Group:
		if item.item_id != 0 or (item.group_id == 0 and item.name):
			return FeedbagStatus.BadRequest
	elif item.item_id == 0:
		return FeedbagStatus.BadRequest
	if item.class_id == FeedbagClass.Buddy and item.group_id == 0:
		return FeedbagStatus.BadRequest
	if item.class_id in ROOT_ONLY_CLASSES and item.group_id != 0:
		return FeedbagStatus.BadRequest
	if item.class_id in SINGLE_ITEM_CLASSES and item.name:
		return FeedbagStatus.BadRequest
	if check_attributes:
		if len(marshal_tlvs(item.attributes)) > MAX_ITEM_ATTRS_SIZE:
			return FeedbagStatus.BadRequest
		for tlv in item.attributes:
			if tlv.type < 0x0064:
				return FeedbagStatus.BadRequest
			if tlv.type <= 0x00C7:
				# server-only range; clients may only insert PENDING (and send TIME_T on DATE_TIME, which gets overridden)
				if tlv.type == FeedbagAttributes.Pending and allow_pending:
					continue
				if tlv.type == FeedbagAttributes.TimeT and item.class_id == FeedbagClass.DateTime:
					continue
				return FeedbagStatus.BadRequest
			if tlv.type <= 0x270F and tlv.type not in REGISTERED_ATTRIBUTES:
				return FeedbagStatus.BadRequest
	return None

def _resolve_group(context: OSCARContext, client_group_id: int) -> Optional[Group]:
	detail = context.user.detail
	backend_id = _resolve_group_backend_id(context, client_group_id)
	return detail._groups_by_id.get(backend_id) if backend_id is not None else None

def _generated_buddy_ids(context: OSCARContext, group_name: str) -> dict[int, str]:
	items = get_items(context)
	gid = next((i.group_id for i in items if i.class_id == FeedbagClass.Group and i.group_id != 0 and i.name == group_name), None)
	return {i.item_id: (i.key or i.name.lower()) for i in items if i.class_id == FeedbagClass.Buddy and i.group_id == gid}

def _store_order(context: OSCARContext, item: FeedbagItem) -> None:
	# the client's ORDER holds its own ids; translate them to names so they survive id regeneration
	order_tlv = find_tlv(item.attributes, FeedbagAttributes.Order)
	if order_tlv is None:
		return
	detail = context.user.detail
	store = _get_store(context.user)
	ids = _decode_order(order_tlv)
	if item.group_id == 0:
		names = []
		for cid in ids:
			backend_id = _resolve_group_backend_id(context, cid)
			group = detail._groups_by_id.get(backend_id) if backend_id is not None else None
			if group is not None:
				names.append(group.name.lower())
		store['gorder'] = names
		return
	group = _resolve_group(context, item.group_id)
	gname = group.name if group is not None else ("(No Group)" if item.name.lower() == '(no group)' else None)
	if gname is None:
		return
	known = _generated_buddy_ids(context, gname)
	iid_map = context.bs.front_data.get('oscar0_iid_map', {})
	names = []
	for iid in ids:
		name = iid_map.get((item.group_id, iid)) or known.get(iid)
		if name:
			names.append(name)
	store.setdefault('border', {})[gname.lower()] = names

def _rename_group_keys(store: dict[str, Any], old: str, new: str) -> None:
	for section in ('gattrs', 'border'):
		entries = store.get(section, {})
		if old in entries:
			entries[new] = entries.pop(old)
	battrs = store.get('battrs', {})
	for key in [key for key in battrs if key.startswith(old + ':')]:
		battrs[new + ':' + key[len(old) + 1:]] = battrs.pop(key)
	store['gorder'] = [new if name == old else name for name in store.get('gorder', [])]

def _drop_group_keys(store: dict[str, Any], key: str) -> None:
	store.get('gattrs', {}).pop(key, None)
	store.get('border', {}).pop(key, None)
	battrs = store.get('battrs', {})
	for stale in [stale for stale in battrs if stale.startswith(key + ':')]:
		battrs.pop(stale)
	store['gorder'] = [name for name in store.get('gorder', []) if name != key]

def _apply_pd_mode(context: OSCARContext, attrs: list[TLV]) -> None:
	# PD_MODE is a single byte and PD_MASK a dword; what they mean for the permit/deny rules is the PD foodgroup's business
	mode_tlv = find_tlv(attrs, FeedbagAttributes.PdMode)
	mask_tlv = find_tlv(attrs, FeedbagAttributes.PdMask)
	mode = mode_tlv.data[-1] if mode_tlv is not None and mode_tlv.data else None
	mask = struct.unpack('>L', mask_tlv.data)[0] if mask_tlv is not None and len(mask_tlv.data) == 4 else None
	apply_pd_info(context, mode, mask)


def _insert_group(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	bs = context.bs
	detail = context.user.detail
	store = _get_store(context.user)

	if item.group_id == 0 and item.item_id == 0:
		_store_order(context, item)
		return FeedbagStatus.Success
	if not item.name:
		return FeedbagStatus.BadRequest
	if item.name.lower() == '(no group)' or item.name.lower() in {g.name.lower() for g in detail._groups_by_id.values()}:
		return FeedbagStatus.AlreadyExists
	if str(item.group_id) in detail._groups_by_id:
		return FeedbagStatus.AlreadyExists
	if len(detail._groups_by_id) >= MAX_GROUPS:
		return FeedbagStatus.OverLimit

	try:
		group = bs.me_group_add(item.name)
	except error.GroupAlreadyExists:
		return FeedbagStatus.AlreadyExists
	except Exception:
		return FeedbagStatus.BadRequest

	bs.front_data.setdefault("oscar0_group_id_map", {})[item.group_id] = group.id
	logger.info("[Client] Added group:", item.name)

	attrs = [tlv for tlv in item.attributes if tlv.type != FeedbagAttributes.Order]
	if attrs:
		store.setdefault('gattrs', {})[group.name.lower()] = _attrs_to_json(attrs)
	_store_order(context, item)

	# buddies the client inserted before this group existed (the wiki's recommended insert order) join it now
	for contact_uuid, username, buddy_attrs in bs.front_data.get('oscar0_pending_buddies', {}).pop(item.group_id, []):
		try:
			bs.me_group_contact_add(group.id, contact_uuid)
		except Exception:
			continue
		if buddy_attrs:
			store.setdefault('battrs', {})['{}:{}'.format(group.name.lower(), username)] = buddy_attrs
	return FeedbagStatus.Success

def _insert_buddy(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	bs = context.bs
	detail = context.user.detail
	store = _get_store(context.user)

	if not item.name or not names.valid_name(item.name):
		return FeedbagStatus.BadLoginID
	contact_user = names.resolve_user(context.backend, item.name)
	if contact_user is None or contact_user is context.user:
		logger.info("[Client] Unknown buddy:", item.name)
		return FeedbagStatus.BadLoginID
	contact_uuid = contact_user.uuid
	key = contact_user.username.lower()

	pending = find_tlv(item.attributes, FeedbagAttributes.Pending) is not None
	if icq.requires_authorization(contact_user, context.user):
		if not pending:
			if names.is_icq_session(bs):
				return FeedbagStatus.AuthRequired
			item.attributes = list(item.attributes) + [TLV(FeedbagAttributes.Pending)]
			request_authorization(context.backend, context.user, contact_user, '')
	elif pending:
		# authorization has been granted since: the buddy goes on as an ordinary one
		item.attributes = [tlv for tlv in item.attributes if tlv.type != FeedbagAttributes.Pending]
	if names.is_icq_session(bs) and names.uin_of(contact_user) is None:
		# AIM can't take part in authorization, so an ICQ user adding an AIM user authorizes them back
		icq.record_preauth(context.user, contact_uuid)

	contact = detail.contacts.get(contact_uuid)
	is_buddy = contact is not None and bool(contact.lists & ContactList.FL)
	group = _resolve_group(context, item.group_id)

	if not is_buddy and len(detail.get_contacts_by_list(ContactList.FL)) >= MAX_BUDDIES:
		return FeedbagStatus.OverLimit
	if group is not None:
		if is_buddy and contact.is_in_group_id(group.id):
			return FeedbagStatus.AlreadyExists
		if len([c for c in detail.get_contacts_by_list(ContactList.FL) if c.is_in_group_id(group.id)]) >= MAX_BUDDIES_PER_GROUP:
			return FeedbagStatus.OverLimit

	attrs = _attrs_to_json(list(item.attributes))
	battr_key = '{}:{}'.format(group.name.lower(), key) if group is not None else None
	try:
		# the attributes go in first, so a PENDING_AUTH buddy is already marked when the add tells the other side
		if battr_key is not None and attrs:
			store.setdefault('battrs', {})[battr_key] = attrs
		if not is_buddy:
			bs.me_contact_add(contact_uuid, ContactList.FL | ContactList.AL)
		if group is not None:
			bs.me_group_contact_add(group.id, contact_uuid)
		else:
			bs.front_data.setdefault('oscar0_pending_buddies', {}).setdefault(item.group_id, []).append((contact_uuid, key, attrs))
	except error.ContactListIsFull:
		if battr_key is not None:
			store.get('battrs', {}).pop(battr_key, None)
		return FeedbagStatus.OverLimit
	except Exception:
		if battr_key is not None:
			store.get('battrs', {}).pop(battr_key, None)
		return FeedbagStatus.BadRequest

	bs.front_data.setdefault('oscar0_iid_map', {})[(item.group_id, item.item_id)] = key
	# whatever this client called the buddy (a UIN, a differently spaced screen name) is what it'll hear about them as
	names.remember(bs, contact_user, item.name)
	names.store_alias(bs, contact_user, item.name)
	logger.info("[Client] Added buddy:", item.name)
	return FeedbagStatus.Success

def _insert_list_entry(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	is_permit = (item.class_id == FeedbagClass.Permit)
	status = FeedbagStatus(int(pd_add(context, item.name, permit = is_permit)))
	if status == FeedbagStatus.Success:
		logger.info("[Client] Added {} entry:".format('permit' if is_permit else 'deny'), item.name)
	return status

def _insert_generic(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	store = _get_store(context.user)
	misc: list[dict[str, Any]] = store.setdefault('misc', [])

	# (groupId, itemId) is unique across everything in the feedbag
	if any(i.group_id == item.group_id and i.item_id == item.item_id and i.class_id != item.class_id for i in get_items(context)):
		return FeedbagStatus.AlreadyExists
	same_class = [entry for entry in misc if entry['c'] == item.class_id]
	if item.class_id in SINGLE_ITEM_CLASSES and same_class:
		return FeedbagStatus.OverLimit
	if item.group_id == 0 and any(_compress(entry['n']) == _compress(item.name) for entry in same_class):
		return FeedbagStatus.AlreadyExists
	if item.class_id >= MIN_CLIENT_CLASS and len([entry for entry in misc if entry['c'] >= MIN_CLIENT_CLASS]) >= MAX_CLIENT_ITEMS:
		return FeedbagStatus.OverLimit

	attrs = list(item.attributes)
	if item.class_id == FeedbagClass.DateTime:
		attrs = _stamp_time(attrs, 0)
	misc.append({ 'n': item.name, 'g': item.group_id, 'i': item.item_id, 'c': int(item.class_id), 'a': _attrs_to_json(attrs) })

	if item.class_id == FeedbagClass.PdInfo:
		_apply_pd_mode(context, attrs)
	logger.info("[Client] Stored item of class", hex(item.class_id))
	return FeedbagStatus.Success


def _update_group(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	bs = context.bs
	detail = context.user.detail
	store = _get_store(context.user)

	if item.group_id == 0 and item.item_id == 0:
		_store_order(context, item)
		return FeedbagStatus.Success

	group = _resolve_group(context, item.group_id)
	if group is None:
		# the synthesised "(No Group)" group has no backend group, but clients still reorder it
		if item.name.lower() == '(no group)':
			_store_order(context, item)
			return FeedbagStatus.Success
		return FeedbagStatus.NotFound

	if item.name and item.name != group.name:
		if item.name.lower() == '(no group)' or any(g.name.lower() == item.name.lower() and g.id != group.id for g in detail._groups_by_id.values()):
			return FeedbagStatus.AlreadyExists
		old_key = group.name.lower()
		try:
			bs.me_group_edit(group.id, new_name = item.name)
		except Exception:
			return FeedbagStatus.BadRequest
		_rename_group_keys(store, old_key, item.name.lower())
		logger.info("[Client] Renamed group to:", item.name)

	attrs = [tlv for tlv in item.attributes if tlv.type != FeedbagAttributes.Order]
	gattrs = store.setdefault('gattrs', {})
	if attrs:
		gattrs[group.name.lower()] = _attrs_to_json(attrs)
	else:
		gattrs.pop(group.name.lower(), None)
	_store_order(context, item)
	return FeedbagStatus.Success

def _update_buddy(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	detail = context.user.detail
	store = _get_store(context.user)

	if not item.name or not names.valid_name(item.name):
		return FeedbagStatus.BadLoginID
	contact_uuid = names.resolve(context.backend, item.name)
	if contact_uuid is None:
		return FeedbagStatus.BadLoginID

	group = _resolve_group(context, item.group_id)
	contact = detail.contacts.get(contact_uuid)
	if contact is None or not contact.lists & ContactList.FL:
		return FeedbagStatus.NotFound
	if group is not None:
		if not contact.is_in_group_id(group.id):
			return FeedbagStatus.NotFound
		gkey = group.name.lower()
	elif contact._groups:
		return FeedbagStatus.NotFound
	else:
		gkey = '(no group)'

	key = '{}:{}'.format(gkey, contact.head.username.lower())
	battrs = store.setdefault('battrs', {})
	had_pending = any(tag == FeedbagAttributes.Pending for tag, _ in battrs.get(key, []))
	invalid = _validate_item(item, check_attributes = True, allow_pending = had_pending)
	if invalid is not None:
		return invalid

	# the client sends every attribute it wants to keep, so this replaces the stored set
	if item.attributes:
		battrs[key] = _attrs_to_json(list(item.attributes))
	else:
		battrs.pop(key, None)
	logger.info("[Client] Updated buddy:", item.name)
	return FeedbagStatus.Success

def _update_list_entry(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	detail = context.user.detail
	lst = ContactList.AL if item.class_id == FeedbagClass.Permit else ContactList.BL

	if not item.name or not names.valid_name(item.name):
		return FeedbagStatus.BadLoginID
	contact_uuid = names.resolve(context.backend, item.name)
	if contact_uuid is None:
		return FeedbagStatus.BadLoginID

	contact = detail.contacts.get(contact_uuid)
	if contact is None or not contact.lists & lst:
		return FeedbagStatus.NotFound
	return FeedbagStatus.Success

def _update_generic(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	store = _get_store(context.user)
	misc: list[dict[str, Any]] = store.setdefault('misc', [])
	attrs = list(item.attributes)

	for entry in misc:
		if entry['g'] == item.group_id and entry['i'] == item.item_id and entry['c'] == item.class_id:
			if item.class_id == FeedbagClass.DateTime:
				attrs = _stamp_time(attrs, _time_of(_attrs_from_json(entry['a'])))
			entry['n'] = item.name
			entry['a'] = _attrs_to_json(attrs)
			if item.class_id == FeedbagClass.PdInfo:
				_apply_pd_mode(context, attrs)
			return FeedbagStatus.Success

	# the synthesised PDINFO/BUDDY_PREFS defaults only become stored items once the client first updates them
	if item.class_id in SINGLE_ITEM_CLASSES and not any(entry['c'] == item.class_id for entry in misc):
		misc.append({ 'n': item.name, 'g': item.group_id, 'i': item.item_id, 'c': int(item.class_id), 'a': _attrs_to_json(attrs) })
		if item.class_id == FeedbagClass.PdInfo:
			_apply_pd_mode(context, attrs)
		return FeedbagStatus.Success
	return FeedbagStatus.NotFound


def _delete_group(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	bs = context.bs
	store = _get_store(context.user)

	# the root group is never deleted
	if item.group_id == 0 and item.item_id == 0:
		return FeedbagStatus.BadRequest
	group = _resolve_group(context, item.group_id)
	if group is None:
		return FeedbagStatus.NotFound

	try:
		bs.me_group_remove(group.id)
	except Exception:
		return FeedbagStatus.NotFound

	mapping = bs.front_data.get("oscar0_group_id_map", {})
	for k in [k for k, v in mapping.items() if v == group.id]:
		del mapping[k]
	_drop_group_keys(store, group.name.lower())
	logger.info("[Client] Removed group:", item.name)
	return FeedbagStatus.Success

def _delete_buddy(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	bs = context.bs
	detail = context.user.detail
	store = _get_store(context.user)

	if not item.name or not names.valid_name(item.name):
		return FeedbagStatus.BadLoginID
	contact_uuid = names.resolve(context.backend, item.name)
	if contact_uuid is None:
		return FeedbagStatus.BadLoginID

	contact = detail.contacts.get(contact_uuid)
	if contact is None or not (contact.lists & ContactList.FL):
		return FeedbagStatus.NotFound
	group = _resolve_group(context, item.group_id)
	if group is not None and not contact.is_in_group_id(group.id):
		return FeedbagStatus.NotFound
	if group is None and contact._groups:
		return FeedbagStatus.NotFound

	try:
		if group is not None:
			bs.me_group_contact_remove(group.id, contact_uuid)
		store.get('battrs', {}).pop('{}:{}'.format(group.name.lower() if group is not None else '(no group)', contact.head.username.lower()), None)
		if not contact._groups:
			bs.me_contact_remove(contact_uuid, ContactList.FL)
			names.drop_alias(bs, contact_uuid)
			# AL was added alongside FL on insert; drop it unless the client also permitted this name explicitly
			if contact.head.username.lower() not in store.get('permits', []):
				try:
					bs.me_contact_remove(contact_uuid, ContactList.AL)
				except Exception:
					pass
	except Exception:
		return FeedbagStatus.BadRequest

	logger.info("[Client] Removed buddy:", item.name)
	return FeedbagStatus.Success

def _delete_list_entry(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	is_permit = (item.class_id == FeedbagClass.Permit)
	status = FeedbagStatus(int(pd_remove(context, item.name, permit = is_permit)))
	if status == FeedbagStatus.Success:
		logger.info("[Client] Removed {} entry:".format('permit' if is_permit else 'deny'), item.name)
	return status

def _delete_generic(logger: Logger, context: OSCARContext, item: FeedbagItem) -> FeedbagStatus:
	misc: list[dict[str, Any]] = _get_store(context.user).get('misc', [])
	for entry in misc:
		if entry['g'] == item.group_id and entry['i'] == item.item_id and entry['c'] == item.class_id:
			misc.remove(entry)
			return FeedbagStatus.Success
	return FeedbagStatus.NotFound


@Foodgroup(0x0013)
class FeedbagFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__RIGHTS_QUERY")

		response_msg = SNACMessage(0x0013, 0x0003)

		# https://ninawiki.preloading.dev/wiki/Protocols/OSCAR/SNAC/FEEDBAG_RIGHTS_REPLY#TLV_Class:_FEEDBAG_RIGHTS_REPLY_TAGS
		response_msg.write_tlvs([
			TLV(0x0002, struct.pack(">H", 254)),	# max class attrs
			TLV(0x0003, struct.pack(">H", 1698)),   # max item attrs

			# max items
			TLV(0x0004, struct.pack(f">{'H' * 67}",
									1000,   # max num of contacts
									100,	# max num of groups
									1000,   # max num of visible contacts
									1000,   # max num of invisible contacts
									1,	  # max vis/invis bitmasks
									1,	  # max presence info fields
									150,	# limit for item type 06
									12,	 # limit for item type 07
									12,	 # limit for item type 08
									3,	  # limit for item type 09
									50,	 # limit for item type 0a
									50,	 # limit for item type 0b
									0,	  # limit for item type 0c
									128,	# limit for item type 0d
									1000,   # max ignore list entries
									20,	 # limit for item type 0f
									200,	# limit for item 10
									1,	  # limit for item 11
									100,	# limit for item 12
									1,	  # limit for item 13
									25,	 # limit for item 14

									# These values are unknown but are here in the sake of keeping response
									# parity with NINA:
									1, 40, 1, 10, 200, 1, 60, 200, 1, 8, 20, 1, 10000, 1000, 1000, 50, 1, 5,
									500, 1, 8, 10000, 1, 1, 1, 10000, 0, 0, 1, 2000, 0, 60, 24, 10, 1, 0, 0,
									0, 0, 1, 1, 1, 1, 1000, 1, 1)),

			TLV(0x0005, struct.pack(">H", 100)),	# max client items
			TLV(0x0006, struct.pack(">H", 97)),	 # max item name len
			TLV(0x0007, struct.pack(">H", 2000)),   # max recent buddies
			TLV(0x0008, struct.pack(">H", 10)),	 # interaction buddies
			TLV(0x0009, struct.pack(">L", 432000)), # interaction half life - in 2^(-age/half_life) in seconds
			TLV(0x000A, struct.pack(">L", 14)),	 # interaction max score
			TLV(0x000B, struct.pack(">H", 0)),	  # unknown
			TLV(0x000C, struct.pack(">H", 600)),	# max buddies per group
			TLV(0x000D, struct.pack(">H", 200)),	# max allowed bot buddies
			TLV(0x000E, struct.pack(">H", 32))	  # max smart groups
		])

		self.logger.info("[Server] FEEDBAG__RIGHTS_REPLY")
		client.send_snac(response_msg)

	@Subgroup(0x0004)
	def query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__QUERY")

		try:
			items = get_items(context)
			last_update = _sync_modified(context, items)
		except Exception as ex:
			self.logger.error(ex)
			self.logger.info("[Server] FEEDBAG__ERR")
			send_feedbag_error(client, message.request_id, FeedbagError.BuddyListUnavailable)
			return

		self.logger.info("[Server] FEEDBAG__REPLY")
		_send_feedbag_reply(client, message.request_id, items, last_update)

	@Subgroup(0x0005)
	def query_if_modified(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__QUERY_IF_MODIFIED")

		# 66 51 29 47 00 0D
		#
		#   66 51 29 47 - u32 for unix timestamp of cached client-side feedbag
		#   00 0D	   - u16 for number of items in cached client-side feedbag
		cached_feedbag_timestamp = message.read_u32()
		cached_feedbag_num_items = message.read_u16()

		self.logger.info("[Client] Cached feedbag timestamp:", cached_feedbag_timestamp)
		self.logger.info("[Client] Cached feedbag items num:", cached_feedbag_num_items)

		try:
			current_items = get_items(context)
			last_update = _sync_modified(context, current_items)
		except Exception as ex:
			self.logger.error(ex)
			self.logger.info("[Server] FEEDBAG__ERR")
			send_feedbag_error(client, message.request_id, FeedbagError.BuddyListUnavailable)
			return

		# both the modification time and the item count have to match for the client's copy to count as current
		if cached_feedbag_timestamp == last_update and cached_feedbag_num_items == len(current_items):
			response_msg = SNACMessage(0x0013, 0x000F, 0x0000, message.request_id)
			response_msg.write_u32(last_update)
			response_msg.write_u16(len(current_items))

			self.logger.info("[Server] FEEDBAG__REPLY_NOT_MODIFIED")
			client.send_snac(response_msg)
		else:
			self.logger.info("[Server] FEEDBAG__REPLY")
			_send_feedbag_reply(client, message.request_id, current_items, last_update)

	@Subgroup(0x0007)
	def use(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__USE")

		bs = context.bs
		# from here on the stored buddy list is the one this client runs on
		bs.front_data['oscar0_feedbag'] = True
		_restore_bart_icon(context)

		# set our status to Online
		# (that's done at OSERVICE__CLIENT_READY, which every client sends: AIM sends this before it, ICQ 5 after, so ICQ 5
		# would otherwise come online before its privacy settings were in use)

		# notify the client if any contacts are online
		# cached statuses can lag behind, so recompute before deciding who is online
		if bs.front_data.get('oscar0_ready'):
			push_buddy_list(bs)

	# stubs because I cba to implement more of feedbag rn
	@Subgroup(0x0011)
	def start_cluster(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__START_CLUSTER (not implemented)")

	@Subgroup(0x0012)
	def end_cluster(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__END_CLUSTER (not implemented)")

	@Subgroup(0x0008)
	def insert_item(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__INSERT_ITEM")

		bs = context.bs
		before = bs.me_visibility_snapshot()
		statuses = []
		added = []
		bart_items = []

		for item in unmarshal_items(message.data):
			invalid = _validate_item(item, check_attributes = True, allow_pending = True)
			if invalid is not None:
				statuses.append(invalid)
			elif item.class_id == FeedbagClass.Group:
				statuses.append(_insert_group(self.logger, context, item))
			elif item.class_id == FeedbagClass.Buddy:
				status = _insert_buddy(self.logger, context, item)
				statuses.append(status)
				if status == FeedbagStatus.Success:
					added.append(item.name)
			elif item.class_id in (FeedbagClass.Permit, FeedbagClass.Deny):
				statuses.append(_insert_list_entry(self.logger, context, item))
			else:
				status = _insert_generic(self.logger, context, item)
				statuses.append(status)
				if status == FeedbagStatus.Success and item.class_id == FeedbagClass.Bart:
					bart_items.append(item)

		context.backend._mark_modified(context.user)
		bs.me_visibility_changed(before)

		self.logger.info("[Server] FEEDBAG__STATUS")
		_send_feedbag_status(client, message.request_id, statuses)

		# the buddy has to be in the client's list before its arrival means anything, so this goes after the STATUS
		for name in added:
			_push_presence(client, context, name)
		for item in bart_items:
			_set_bart_item(client, context, item)

	@Subgroup(0x0009)
	def update_item(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__UPDATE_ITEM")

		bs = context.bs
		before = bs.me_visibility_snapshot()
		statuses = []
		bart_items = []

		for item in unmarshal_items(message.data):
			# buddies validate their own attributes, since whether PENDING is allowed depends on what is already stored
			invalid = _validate_item(item, check_attributes = item.class_id != FeedbagClass.Buddy)
			if invalid is not None:
				statuses.append(invalid)
			elif item.class_id == FeedbagClass.Group:
				statuses.append(_update_group(self.logger, context, item))
			elif item.class_id == FeedbagClass.Buddy:
				statuses.append(_update_buddy(self.logger, context, item))
			elif item.class_id in (FeedbagClass.Permit, FeedbagClass.Deny):
				statuses.append(_update_list_entry(self.logger, context, item))
			else:
				status = _update_generic(self.logger, context, item)
				statuses.append(status)
				if status == FeedbagStatus.Success and item.class_id == FeedbagClass.Bart:
					bart_items.append(item)

		context.backend._mark_modified(context.user)
		bs.me_visibility_changed(before)

		self.logger.info("[Server] FEEDBAG__STATUS")
		_send_feedbag_status(client, message.request_id, statuses)

		for item in bart_items:
			_set_bart_item(client, context, item)

	@Subgroup(0x000A)
	def delete_item(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__DELETE_ITEM")

		bs = context.bs
		before = bs.me_visibility_snapshot()
		statuses = []

		for item in unmarshal_items(message.data):
			invalid = _validate_item(item, check_attributes = False)
			if invalid is not None:
				statuses.append(invalid)
			elif item.class_id == FeedbagClass.Group:
				statuses.append(_delete_group(self.logger, context, item))
			elif item.class_id == FeedbagClass.Buddy:
				statuses.append(_delete_buddy(self.logger, context, item))
			elif item.class_id in (FeedbagClass.Permit, FeedbagClass.Deny):
				statuses.append(_delete_list_entry(self.logger, context, item))
			else:
				status = _delete_generic(self.logger, context, item)
				statuses.append(status)
				# without its BART item the icon is gone
				if status == FeedbagStatus.Success and item.class_id == FeedbagClass.Bart and item.name in ('0', '1'):
					if bs.front_data.pop('oscar0_bart_icon', None) is not None:
						_announce_icon(client, context)

		context.backend._mark_modified(context.user)
		bs.me_visibility_changed(before)

		self.logger.info("[Server] FEEDBAG__STATUS")
		_send_feedbag_status(client, message.request_id, statuses)

	@Subgroup(0x0014)
	def pre_authorize_buddy(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# FEEDBAG__PRE_AUTHORIZE_BUDDY: string08 who, string16 message, u16 flags; they may add us without asking
		self.logger.info("[Client] FEEDBAG__PRE_AUTHORIZE_BUDDY")
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		text = _read_string16(message)
		target = names.resolve_user(context.backend, name)
		if target is None:
			return
		if target is context.user:
			client.ctrl.send_snac_error(0x0013, message.request_id, 0x0008)
			return
		grant_authorization(context.backend, context.user, target, text, pre = True)

	@Subgroup(0x0018)
	def request_authorize_to_host(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# FEEDBAG__REQUEST_AUTHORIZE_TO_HOST: string08 who, string16 reason, u16 unknown
		self.logger.info("[Client] FEEDBAG__REQUEST_AUTHORIZE_TO_HOST")
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		reason = _read_string16(message)
		target = names.resolve_user(context.backend, name)
		if target is None or target is context.user:
			return
		names.remember(context.bs, target, name)
		request_authorization(context.backend, context.user, target, reason)

	@Subgroup(0x001A)
	def respond_authorize_to_host(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# FEEDBAG__RESPOND_AUTHORIZE_TO_HOST: string08 who, u8 accepted, string16 reason
		self.logger.info("[Client] FEEDBAG__RESPOND_AUTHORIZE_TO_HOST")
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		accepted = message.read_u8() if len(message) > 0 else 0
		reason = _read_string16(message)
		requester = names.resolve_user(context.backend, name)
		if requester is None or requester is context.user:
			return
		if accepted:
			grant_authorization(context.backend, context.user, requester, reason)
		else:
			deny_authorization(context.backend, context.user, requester, reason)

	@Subgroup(0x0016)
	def remove_me(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__REMOVE_ME")

		# xx	byte	length of the uin string
		# xx ..	string	remote client uin string
		target_name = message.read_string_u8()

		# there is no server reply to this SNAC, whether or not it did anything
		if not names.valid_name(target_name):
			return

		backend = context.backend
		target_uuid = names.resolve(backend, target_name)
		if target_uuid is None:
			return
		target_user = backend._load_user_record(target_uuid)
		if target_user is None:
			return
		target_detail = backend._load_detail(target_user)
		contact = target_detail.contacts.get(context.user.uuid)
		if contact is None or not (contact.lists & ContactList.FL):
			return

		# we are the contact being removed, so this is Backend.me_contact_remove seen from the list owner's side:
		# drop us from their FL (and the AL their buddy add implied), then drop the matching RL we hold for them
		permitted = context.user.username.lower() in (target_user.settings.get(SSI_KEY) or {}).get('permits', [])
		unlink = [(target_user, context.user, ContactList.FL), (context.user, target_user, ContactList.RL)]
		if not permitted:
			unlink.insert(1, (target_user, context.user, ContactList.AL))

		for owner, head, lst in unlink:
			try:
				context.bs._remove_from_list(owner, head, lst, None)
			except Exception:
				self.logger.info("[Server] FEEDBAG__REMOVE_ME could not clear", lst.name, "between", owner.username, "and", head.username)

		self.logger.info(context.user.username, "removed themselves from", target_user.username + "'s Buddy List")

def _read_string16(message: SNACMessage) -> str:
	if len(message) < 2:
		return ''
	return message.read_bytes(message.read_u16()).decode('utf-8', errors = 'replace')

def _legacy_auth_request_text(requester: User, target: User, reason: str) -> str:
	# MSG_TYPE_AUTH_REQ text: nick, first, last, e-mail, whether the requester already authorizes the target, reason
	info = icq.basic_info(requester)
	authorized = 0 if icq.requires_authorization(requester, target) else 1
	email = info['email'] if info['publish_email'] else ''
	return '\xfe'.join([info['nick'], info['first'], info['last'], email, str(authorized), reason])

def _icq5_reason(reason: str) -> str:
	# ICQ 5 drops an authorization request that has more than one period in it
	first = reason.find('.')
	if first < 0:
		return reason
	return reason[:first + 1] + reason[first + 1:].replace('.', '')

def _deliver_auth_event(backend: Any, target: User, sender: User, event: str, text: str = '', *, sessions: Optional[list] = None) -> bool:
	# returns whether any session took it
	from .icbm import send_icq_system_message, ICQMessageType
	delivered = False
	for bs_t in (sessions if sessions is not None else backend.util_get_sessions_by_user(target)):
		if bs_t.closed:
			continue
		if bs_t.front_data.get('oscar0') and hasattr(bs_t.evt, 'oscar_on_snac'):
			ctrl = bs_t.evt.ctrl
			sender_name = names.name_for(bs_t, sender)
			if bs_t.front_data.get('oscar0_feedbag'):
				if event == 'request':
					msg = SNACMessage(0x0013, 0x0019, 0x8000)
					msg.write_bytes(_extended_info(2))
					msg.write_bytes(_string08(sender_name))
					msg.write_bytes(_string16(_icq5_reason(text)))
					msg.write_u16(0)
				elif event in ('granted', 'denied'):
					msg = SNACMessage(0x0013, 0x001B, 0x8000)
					msg.write_bytes(_extended_info(2))
					msg.write_bytes(_string08(sender_name))
					msg.write_u8(1 if event == 'granted' else 0)
					msg.write_bytes(_string16(text))
					msg.write_u16(0)
				elif event == 'preauth':
					msg = SNACMessage(0x0013, 0x0015)
					msg.write_bytes(_string08(sender_name))
					msg.write_bytes(_string16(text))
					msg.write_u16(0)
				elif event == 'added':
					msg = build_buddy_added_notif(sender_name)
				else:
					continue
				ctrl.send_snac(msg)
				delivered = True
			elif names.is_icq_session(bs_t) and names.uin_of(sender) is not None:
				kind = {
					'request': ICQMessageType.AuthRequest, 'denied': ICQMessageType.AuthDeny, 'granted': ICQMessageType.AuthGrant,
					'preauth': ICQMessageType.AuthGrant, 'added': ICQMessageType.Added,
				}.get(event)
				if kind is None:
					continue
				if event == 'request':
					body = _legacy_auth_request_text(sender, target, text)
				elif event == 'denied':
					body = text
				else:
					# grants and "you were added" carry no text over OSCAR
					body = ''
				send_icq_system_message(ctrl, sender, kind, body)
				delivered = True
		elif hasattr(bs_t.evt, 'icq_on_auth_event'):
			bs_t.evt.icq_on_auth_event(event, sender, text)
			delivered = True
	return delivered

def _queue_or_deliver(backend: Any, target: User, sender: User, event: str, text: str = '') -> None:
	if _deliver_auth_event(backend, target, sender, event, text):
		return
	icq.queue_auth_event(target, { 'type': event, 'from': sender.uuid, 'text': text })
	icq.save(backend, target)

def deliver_queued_auth_events(ctrl: Any) -> None:
	# everything held for this account while it wasn't on ICQ, handed to the session that just signed on
	bs = ctrl.bs
	if bs is None:
		return
	events = icq.take_auth_events(bs.user)
	if not events:
		return
	icq.save(ctrl.backend, bs.user)
	for event in events:
		sender = ctrl.backend._load_user_record(event.get('from') or '')
		if sender is None:
			continue
		_deliver_auth_event(ctrl.backend, bs.user, sender, str(event.get('type')), str(event.get('text') or ''), sessions = [bs])

def request_authorization(backend: Any, requester: User, target: User, reason: str) -> None:
	_queue_or_deliver(backend, target, requester, 'request', reason)

def _clear_pending(backend: Any, owner: User, contact: User) -> bool:
	# drop PENDING_AUTH from `owner`'s stored buddy entry for `contact`; returns whether there was one
	store = owner.settings.get(SSI_KEY)
	if not isinstance(store, dict):
		return False
	suffix = ':' + contact.username.lower()
	cleared = False
	for key, attrs in (store.get('battrs') or {}).items():
		if key.endswith(suffix) and any(tag == FeedbagAttributes.Pending for tag, _ in attrs):
			store['battrs'][key] = [[tag, data] for tag, data in attrs if tag != FeedbagAttributes.Pending]
			cleared = True
	if cleared:
		icq.save(backend, owner)
	return cleared

def _send_item_update(bs: Any, contact: User) -> None:
	# FEEDBAG__UPDATE_ITEM from the server, so the client's copy of a buddy item matches what's stored again
	from ..proto.snac import OSCARContext as _Context
	context = _Context(bs.backend, bs.client)
	context.bs = bs
	context.user = bs.user
	try:
		items = [item for item in get_items(context) if item.class_id == FeedbagClass.Buddy and item.key == contact.username.lower()]
	except Exception:
		return
	if not items:
		return
	msg = SNACMessage(0x0013, 0x0009)
	msg.write_bytes(marshal_items(items))
	bs.evt.oscar_on_snac(msg)

def grant_authorization(backend: Any, granter: User, requester: User, text: str = '', *, pre: bool = False) -> None:
	# `granter` lets `requester` add them: recorded, the requester's pending buddy cleared, both sides told
	icq.record_preauth(granter, requester.uuid)
	icq.save(backend, granter)
	if _clear_pending(backend, requester, granter):
		for bs_r in feedbag_sessions(backend, requester):
			_send_item_update(bs_r, granter)
		_queue_or_deliver(backend, requester, granter, 'granted', text)
		# now that it's settled, the granter hears they were added
		_deliver_auth_event(backend, granter, requester, 'added')
		for bs_r in oscar_sessions(backend, requester):
			if bs_r.front_data.get('oscar0_ready'):
				push_presence(bs_r, granter)
		return
	_queue_or_deliver(backend, requester, granter, 'preauth' if pre else 'granted', text)

def deny_authorization(backend: Any, denier: User, requester: User, reason: str) -> None:
	_queue_or_deliver(backend, requester, denier, 'denied', reason)

def auth_event_from_icq_message(backend: Any, sender: User, target: User, kind: int, text: str) -> None:
	# an ICQ client without a feedbag runs authorization through channel 4 messages; they become the same events
	from .icbm import ICQMessageType
	if kind == ICQMessageType.AuthRequest:
		fields = text.split('\xfe')
		request_authorization(backend, sender, target, fields[5] if len(fields) >= 6 else (fields[-1] if fields else ''))
	elif kind == ICQMessageType.AuthGrant:
		grant_authorization(backend, sender, target)
	elif kind == ICQMessageType.AuthDeny:
		deny_authorization(backend, sender, target, text)
	elif kind == ICQMessageType.Added:
		_deliver_auth_event(backend, target, sender, 'added')

def _restore_bart_icon(context: OSCARContext) -> None:
	# the buddy icon a feedbag client set last time is in its BART item; an icon the server has goes on show straight away
	for entry in _get_store(context.user).get('misc', []):
		if entry.get('c') != FeedbagClass.Bart or entry.get('n') not in ('0', '1'):
			continue
		attr = find_tlv(_attrs_from_json(entry['a']), FeedbagAttributes.BartInfo)
		info = bart.parse_bart_info(attr.data) if attr is not None else None
		if info is not None and bart.is_known(info[1]):
			context.bs.front_data['oscar0_bart_icon'] = (info[0] & ~bart.BARTFlags.Unknown, info[1])
		return

def _announce_icon(client: OSCARClient, context: OSCARContext) -> None:
	from .buddy import refresh_contact
	from .oservice import build_self_info
	client.send_snac(build_self_info(context.bs))
	refresh_contact(context.backend, context.user)

def _set_bart_item(client: OSCARClient, context: OSCARContext, item: FeedbagItem) -> None:
	# a BART item (named after its BART type) holds a BART_INFO in attribute 0xD5; an icon the server already has goes on
	# show, otherwise OSERVICE__BART_REPLY comes back flagged unknown (0x40) and the client uploads it over BART
	try:
		bart_type = int(item.name, 0)
	except ValueError:
		return
	attr = find_tlv(item.attributes, FeedbagAttributes.BartInfo)
	info = bart.parse_bart_info(attr.data) if attr is not None else None
	if info is None:
		return
	flags, hash = info
	known = bart.is_known(hash)
	if not known:
		flags |= bart.BARTFlags.Unknown
	icon = bart_type in (bart.BARTType.BuddyIconSmall, bart.BARTType.BuddyIcon)
	if icon:
		context.bs.front_data['oscar0_bart_icon'] = (flags, hash)

	reply = SNACMessage(0x0001, 0x0021)
	reply.write_bytes(bart.build_bart_id(bart_type, flags, hash))
	client.send_snac(reply)

	if icon and known:
		_announce_icon(client, context)
