import struct

from core import error
from core.models import AIM_PD_KEY, AIM_SSI_KEY, ContactList, User
from enum import IntEnum
from typing import Optional
from util.misc import Logger, is_valid_oscar_screenname

from ..proto import names
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Subgroup


class PDMode(IntEnum):
	PermitAll = 0x01
	DenyAll = 0x02
	PermitSome = 0x03
	DenySome = 0x04
	PermitOnList = 0x05

class PDStatus(IntEnum):
	# values deliberately match FEEDBAG__STATUS_CODES, since the same list logic answers FEEDBAG permit/deny items
	Success = 0x0000
	NotFound = 0x0002
	AlreadyExists = 0x0003
	BadRequest = 0x000A
	OverLimit = 0x000C
	BadLoginID = 0x0010

MAX_PERMITS = 1000
MAX_DENIES = 1000
MAX_TEMP_PERMITS = 1000

PD_MODES = frozenset(int(m) for m in PDMode)


def _permit_names(user: User) -> list[str]:
	# explicit permits live in the same settings blob the feedbag keeps its extras in, so both frontends of the list agree
	store = user.settings.get(AIM_SSI_KEY)
	if not isinstance(store, dict):
		store = {}
		user.settings[AIM_SSI_KEY] = store
	return store.setdefault('permits', [])

def apply_pd_info(context: OSCARContext, mode: Optional[int], mask: Optional[int]) -> None:
	# the mode drives the permit/deny rules in core.models, and BLP is kept in step with it
	settings = context.user.settings
	pd = dict(settings.get(AIM_PD_KEY) or {})

	if mode is not None and mode in PD_MODES:
		blp = 'AL' if mode in (PDMode.PermitAll, PDMode.DenySome) else 'BL'
		settings['BLP'] = blp
		pd['mode'] = mode
		pd['blp'] = blp

	if mask is not None:
		pd['mask'] = mask

	if pd:
		settings[AIM_PD_KEY] = pd

def set_pd_mask(context: OSCARContext, mask: int) -> None:
	# PD__SET_GROUP_PERMIT_MASK; a mask without a mode still needs one to be enforced, so the one BLP implies is filled in
	user = context.user
	blp = user.settings.get('BLP', 'AL')
	pd = dict(user.settings.get(AIM_PD_KEY) or {})
	if pd.get('mode') not in PD_MODES or pd.get('blp') != blp:
		pd['mode'] = int(PDMode.DenySome if blp == 'AL' else PDMode.PermitOnList)
	pd['blp'] = blp
	pd['mask'] = mask
	user.settings[AIM_PD_KEY] = pd

def pd_add(context: OSCARContext, name: str, *, permit: bool) -> PDStatus:
	# shared by FEEDBAG permit/deny items and PD__ADD_PERM/DENY_LIST_ENTRIES
	bs = context.bs
	detail = context.user.detail
	lst = ContactList.AL if permit else ContactList.BL
	permits = _permit_names(context.user)

	if not name or not names.valid_name(name):
		return PDStatus.BadLoginID
	contact_uuid = names.resolve(context.backend, name)
	if contact_uuid is None:
		return PDStatus.BadLoginID
	contact_user = context.backend._load_user_record(contact_uuid)
	if contact_user is None:
		return PDStatus.BadLoginID
	# permits are kept by screen name whichever way the client named them (a UIN, say), since that's what the
	# permit/deny rules in core.models compare against
	name = contact_user.username

	contact = detail.contacts.get(contact_uuid)
	if contact is not None and contact.lists & lst:
		# a buddy is implicitly allowed, so an explicit permit for one is not a duplicate
		if not (permit and contact.lists & ContactList.FL and name.lower() not in permits):
			return PDStatus.AlreadyExists

	if permit:
		explicit = [c for c in detail.get_contacts_by_list(ContactList.AL) if not c.lists & ContactList.FL or c.head.username.lower() in permits]
		if len(explicit) >= MAX_PERMITS:
			return PDStatus.OverLimit
	elif len(detail.get_contacts_by_list(ContactList.BL)) >= MAX_DENIES:
		return PDStatus.OverLimit

	try:
		if contact is None or not contact.lists & lst:
			bs.me_contact_add(contact_uuid, lst)
		if permit:
			permits.append(name.lower())
	except error.ContactListIsFull:
		return PDStatus.OverLimit
	except Exception:
		return PDStatus.BadRequest

	return PDStatus.Success

def pd_remove(context: OSCARContext, name: str, *, permit: bool) -> PDStatus:
	bs = context.bs
	detail = context.user.detail
	lst = ContactList.AL if permit else ContactList.BL

	if not name or not names.valid_name(name):
		return PDStatus.BadLoginID
	contact_uuid = names.resolve(context.backend, name)
	if contact_uuid is None:
		return PDStatus.BadLoginID
	contact_user = context.backend._load_user_record(contact_uuid)
	if contact_user is None:
		return PDStatus.BadLoginID
	name = contact_user.username

	contact = detail.contacts.get(contact_uuid)
	if contact is None or not (contact.lists & lst):
		return PDStatus.NotFound

	try:
		if permit:
			permits = _permit_names(context.user)
			if name.lower() in permits:
				permits.remove(name.lower())
			# a buddy keeps the AL it was inserted with
			if not contact.lists & ContactList.FL:
				bs.me_contact_remove(contact_uuid, lst)
		else:
			bs.me_contact_remove(contact_uuid, lst)
	except Exception:
		return PDStatus.BadRequest

	return PDStatus.Success


def _read_entries(message: SNACMessage) -> list[str]:
	# Class: PD Entries; u8 length + string, repeated until the SNAC runs out
	entries = []
	while len(message) > 0:
		try:
			entries.append(message.read_bytes(message.read_u8()).decode('latin-1'))
		except (struct.error, UnicodeDecodeError):
			break
	return entries

def _apply_entries(context: OSCARContext, message: SNACMessage, *, permit: bool, add: bool) -> None:
	bs = context.bs
	before = bs.me_visibility_snapshot()
	entries = _read_entries(message)
	if add:
		if len(entries) == 1 and names.resolve(context.backend, entries[0]) == context.user.uuid:
			apply_pd_info(context, PDMode.DenyAll if permit else PDMode.PermitAll, None)
			entries = []
		elif entries:
			apply_pd_info(context, PDMode.PermitSome if permit else PDMode.DenySome, None)
	for name in entries:
		if not names.valid_name(name):
			continue
		if add:
			pd_add(context, name, permit = permit)
		else:
			pd_remove(context, name, permit = permit)
	context.backend._mark_modified(context.user)
	bs.me_visibility_changed(before)


# not registered as a foodgroup on its own; 0x0009 is registered once, in bos.py, which inherits these handlers
class PDHandlers:
	logger: Logger

	@Subgroup(0x0004)
	def set_group_permit_mask(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] PD__SET_GROUP_PERMIT_MASK')

		# xx xx xx xx	dword	group permission mask
		mask = message.read_u32()
		self.logger.info('[Client] Mask:', hex(mask))

		before = context.bs.me_visibility_snapshot()
		set_pd_mask(context, mask)
		context.backend._mark_modified(context.user)
		context.bs.me_visibility_changed(before)

	@Subgroup(0x0005)
	def add_perm_list_entries(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] PD__ADD_PERM_LIST_ENTRIES')
		_apply_entries(context, message, permit = True, add = True)

	@Subgroup(0x0006)
	def del_perm_list_entries(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] PD__DEL_PERM_LIST_ENTRIES')
		_apply_entries(context, message, permit = True, add = False)

	@Subgroup(0x0007)
	def add_deny_list_entries(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] PD__ADD_DENY_LIST_ENTRIES')
		_apply_entries(context, message, permit = False, add = True)

	@Subgroup(0x0008)
	def del_deny_list_entries(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] PD__DEL_DENY_LIST_ENTRIES')
		_apply_entries(context, message, permit = False, add = False)

	@Subgroup(0x000A)
	def add_temp_permit_list_entries(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] PD__ADD_TEMP_PERMIT_LIST_ENTRIES')

		# temp permits only live as long as the session, so they stay out of the persisted lists
		temp_permits = context.bs.front_data.setdefault('oscar0_temp_permits', set())
		for name in _read_entries(message):
			uuid = names.resolve(context.backend, name)
			if uuid is not None and len(temp_permits) < MAX_TEMP_PERMITS:
				temp_permits.add(uuid)

	@Subgroup(0x000B)
	def del_temp_permit_list_entries(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] PD__DEL_TEMP_PERMIT_LIST_ENTRIES')

		temp_permits = context.bs.front_data.setdefault('oscar0_temp_permits', set())
		for name in _read_entries(message):
			uuid = names.resolve(context.backend, name)
			if uuid is not None:
				temp_permits.discard(uuid)