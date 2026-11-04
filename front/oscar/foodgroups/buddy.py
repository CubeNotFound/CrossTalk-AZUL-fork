import struct

from typing import Any, List, Optional, TYPE_CHECKING

from core.models import AIM_SSI_KEY, Contact, ContactList, Substatus, User
from util.icq import requires_authorization
from util.misc import Logger

from ..proto import names
from ..proto.delivery import oscar_sessions
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV
from ..proto.userinfo import build_userinfo, pick_session

if TYPE_CHECKING:
	from core.backend import Backend, BackendSession

PENDING_ATTRIBUTE = 0x0066


def buddy_pending(viewer: User, contact: User) -> bool:
	# whether `viewer`'s feedbag still marks `contact` as waiting on authorization (stored like feedbag.py keeps it)
	store = viewer.settings.get(AIM_SSI_KEY)
	if not isinstance(store, dict):
		return False
	suffix = ':' + contact.username.lower()
	for key, attrs in (store.get('battrs') or {}).items():
		if key.endswith(suffix) and any(tag == PENDING_ATTRIBUTE for tag, _ in attrs):
			return True
	return False

def watching(bs: 'BackendSession', contact: User) -> bool:
	# whether this session's client has `contact` on its buddy list: the stored one for feedbag clients, its own otherwise
	if contact.uuid in bs.backend.util_get_watched(bs):
		return True
	if not bs.front_data.get('oscar0_feedbag'):
		return False
	detail = bs.user.detail
	ctc = detail.contacts.get(contact.uuid) if detail is not None else None
	return ctc is not None and bool(ctc.lists & ContactList.FL)

def build_presence_notif(contact: Contact, backend: Any = None, viewer: Optional['BackendSession'] = None) -> SNACMessage:
	# Packet dump from NINA's servers when a contact goes online:
	# ===
	# 0000   04 64 6b 61 79 00 00 00 07 00 30 00 04 67 19 67   .dkay.....0..g.g
	# 0010   4c 00 0d 00 c0 09 46 13 45 4c 7f 11 d1 82 22 44   L.....F.EL...."D
	# 0020   45 53 54 00 00 09 46 01 ff 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 0030   45 53 54 00 00 74 8f 24 20 62 87 11 d1 82 22 44   EST..t.$ b...."D
	# 0040   45 53 54 00 00 09 46 13 43 4c 7f 11 d1 82 22 44   EST...F.CL...."D
	# 0050   45 53 54 00 00 09 46 13 41 4c 7f 11 d1 82 22 44   EST...F.AL...."D
	# 0060   45 53 54 00 00 09 46 01 04 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 0070   45 53 54 00 00 09 46 01 05 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 0080   45 53 54 00 00 09 46 01 02 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 0090   45 53 54 00 00 09 46 01 03 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 00a0   45 53 54 00 00 09 46 01 01 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 00b0   45 53 54 00 00 09 46 13 4a 4c 7f 11 d1 82 22 44   EST...F.JL...."D
	# 00c0   45 53 54 00 00 09 46 13 46 4c 7f 11 d1 82 22 44   EST...F.FL...."D
	# 00d0   45 53 54 00 00 00 1d 00 12 00 01 00 05 02 01 d2   EST.............
	# 00e0   04 72 00 00 00 05 02 01 d2 04 72 00 01 00 02 00   .r........r.....
	# 00f0   08 00 03 00 04 67 19 67 4b 00 0f 00 04 00 00 00   .....g.gK.......
	# 0100   02 00 05 00 04 62 7c 7a cd						.....b|z.
	#
	# Buddy length: 0x04
	# Buddy name: dkay
	# TLVs (7):
	#   - TLV 0x3000: unknown (data = 67 19 67 4C)
	#   - TLV 0x000D: capability list
	#   - TLV 0x001D: BART info (data = 00 01 00 05 02 01 D2 04 72 00 00 00 05 02 01 D2 04 72
	#   - TLV 0x0001: user class (data = 00 00 00 08)
	#   - TLV 0x0003: account signon time (value = 1729718091, in UNIX time)
	#   - TLV 0x000F: session length (value = 2)
	#   - TLV 0x0005: account creation time (value = 1652325069, in UNIX time)
	#

	offline = contact.status.is_offlineish()

	if not offline and backend is not None and not backend.util_get_sessions_by_user(contact.head):
		offline = True
		contact.status.substatus = Substatus.Offline

	# a buddy whose authorization the viewer is still waiting on stays offline to them until it's granted
	if not offline and viewer is not None and buddy_pending(viewer.user, contact.head):
		offline = True

	# each client gets the name it knows the buddy by (a UIN for ICQ, a screen name for AIM)
	name = names.name_for(viewer, contact.head)
	msg = SNACMessage(0x0003, 0x000B if not offline else 0x000C)

	if offline:
		# BUDDY__DEPARTED: an OSERVICE__USERINFO with its TLV count; ICQ only takes it with a (zero) user class inside
		msg.write_string_u8(name)
		msg.write_u16(0)
		msg.write_tlv_block([TLV(0x0001, struct.pack('>H', 0x0000))])  # User class (bitfield)
		return msg

	bs = pick_session(backend, contact.head) if backend is not None else None
	msg.write_bytes(build_userinfo(
		contact.head, bs, substatus = contact.status.substatus, name = name, viewer_icq = names.is_icq_session(viewer),
	))

	return msg

def push_presence(bs: 'BackendSession', contact_user: User) -> None:
	# tell one session where `contact_user` stands right now (the arrival a buddy list add or a sign-on needs)
	from core.backend import _watch_contact
	ctrl = getattr(bs.evt, 'ctrl', None)
	if ctrl is None or contact_user is bs.user or not names.representable(contact_user):
		return
	detail = bs.user.detail
	ctc = detail.contacts.get(contact_user.uuid) if detail is not None else None
	if ctc is None or not ctc.lists & ContactList.FL:
		ctc = _watch_contact(contact_user, bs.user)
	else:
		ctc.compute_visible_status(bs.user)
	if ctc.status.is_offlineish():
		return
	ctrl.send_snac(build_presence_notif(ctc, bs.backend, bs))

def push_buddy_list(bs: 'BackendSession') -> None:
	# everyone on the client's buddy list who's online, at sign-on: the stored list for feedbag clients, the client's own
	# (BUDDY__ADD_BUDDIES) otherwise
	backend = bs.backend
	seen = set()
	if bs.front_data.get('oscar0_feedbag') and bs.user.detail is not None:
		for ctc in bs.user.detail.get_contacts_by_list(ContactList.FL):
			seen.add(ctc.head.uuid)
			push_presence(bs, ctc.head)
	for uuid in backend.util_get_watched(bs):
		if uuid in seen:
			continue
		contact_user = backend._load_user_record(uuid)
		if contact_user is not None:
			push_presence(bs, contact_user)

def refresh_contact(backend: 'Backend', user: User) -> None:
	# something only OSCAR shows (a buddy icon) changed for `user`: OSCAR sessions with them on their list get a new arrival
	detail = user.detail
	viewers = []
	if detail is not None:
		for ctc in detail.contacts.values():
			if ctc.lists & ContactList.RL:
				viewers.extend(oscar_sessions(backend, ctc.head))
	viewers.extend(bs for bs in backend.util_get_watchers(user.uuid) if bs.front_data.get('oscar0'))
	for bs in set(viewers):
		if bs.front_data.get('oscar0_ready') and watching(bs, user):
			push_presence(bs, user)
	for bs in oscar_sessions(backend, user):
		ctrl = getattr(bs.evt, 'ctrl', None)
		if ctrl is not None and bs.front_data.get('oscar0_ready'):
			from .oservice import build_self_info
			ctrl.send_snac(build_self_info(bs))

def _read_buddies(message: SNACMessage) -> List[str]:
	# BUDDY__ADD_BUDDIES and friends: string08 names, one after another until the SNAC runs out
	buddies = []
	while len(message) > 0:
		try:
			length = message.read_u8()
			buddies.append(message.read_bytes(length).decode('latin-1'))
		except struct.error:
			break
	return buddies

def add_buddies(client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
	bs = context.bs
	backend = context.backend
	rejected = []

	for name in _read_buddies(message):
		contact_user = names.resolve_user(backend, name)
		if contact_user is None or contact_user is bs.user:
			rejected.append(name)
			continue
		# a client-side list can't take part in ICQ authorization, so whoever asks to be asked first can't go on one
		if requires_authorization(contact_user, bs.user):
			rejected.append(name)
			continue
		names.remember(bs, contact_user, name)
		backend.util_watch(bs, contact_user.uuid)
		# before OSERVICE__CLIENT_READY the client would drop arrivals, so those wait for the sign-on push
		if bs.front_data.get('oscar0_ready'):
			push_presence(bs, contact_user)

	if rejected:
		# BUDDY__REJECT_NOTIFICATION: the names that didn't make it onto the list
		reply = SNACMessage(0x0003, 0x000A, 0x0000, message.request_id)
		for name in rejected:
			encoded = name.encode('latin-1', errors = 'replace')
			reply.write_u8(len(encoded))
			reply.write_bytes(encoded)
		client.send_snac(reply)

def del_buddies(client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
	bs = context.bs
	backend = context.backend
	for name in _read_buddies(message):
		uuid = names.resolve(backend, name)
		if uuid is not None:
			backend.util_unwatch(bs, uuid)


@Foodgroup(0x0003)
class BuddyFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BUDDY_RIGHTS_QUERY')

		response_msg = SNACMessage(0x0003, 0x0003, 0x0000, message.request_id)
		response_msg.write_tlvs([
			TLV(0x0001, struct.pack('>H', 1000)),  # max buddies
			TLV(0x0002, struct.pack('>H', 3000)),  # max watchers
			TLV(0x0003, struct.pack('>H', 1000)),  # max ICQ broadcast recipients
			TLV(0x0004, struct.pack('>H', 160))  # max temp buddies
		])

		self.logger.info('[Server] BUDDY_RIGHTS_REPLY')
		client.send_snac(response_msg)

	@Subgroup(0x0004)
	def add_buddies(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BUDDY__ADD_BUDDIES')
		add_buddies(client, context, message)

	@Subgroup(0x0005)
	def del_buddies(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BUDDY__DEL_BUDDIES')
		del_buddies(client, context, message)

	@Subgroup(0x000F)
	def add_temp_buddies(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# temp buddies only ever last the session, which is all a client-side buddy is here anyway
		self.logger.info('[Client] BUDDY__ADD_TEMP_BUDDIES')
		add_buddies(client, context, message)

	@Subgroup(0x0010)
	def del_temp_buddies(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BUDDY__DEL_TEMP_BUDDIES')
		del_buddies(client, context, message)