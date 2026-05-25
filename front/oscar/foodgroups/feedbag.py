import time
import struct

from array import array
from core import error
from core.models import ContactList, Substatus
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional
from util.misc import Logger

from .buddy import build_presence_notif # TODO(subpurple): move build_presence_notif out of buddy?
from ..proto.tlv import TLV
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.buffer import Buffer


# I only put the classes I need in this IntEnum
#
# For a complete list of feedbag classes, see https://ninawiki.preloading.dev/wiki/Protocols/OSCAR/Foodgroups/FEEDBAG/Items#Class:_FEEDBAG_CLASS_IDS
class FeedbagClass(IntEnum):
	Buddy = 0x0000,
	Group = 0x0001,
	Permit = 0x0002,
	Deny = 0x0003,
	PdInfo = 0x0004,
	BuddyPrefs = 0x0005


class FeedbagAttributes(IntEnum):
	Order = 0x00C8,
	PdMode = 0x00CA,
	WirelessPdMode = 0x00D0,
	WirelessIgnoreMode = 0x00D1,
	FishPdMode = 0x00D2,
	FishIgnoreMode = 0x00D3,
	PdMask = 0x00CB,
	BuddyPrefs = 0x00C9

class FeedbagStatus(IntEnum):
	Success = 0x0000,
	NotFound = 0x0002,
	AlreadyExists = 0x0003,
	BadRequest = 0x000A,
	OverLimit = 0x000C,
	BadLoginID = 0x0010,

@dataclass
class FeedbagItem:
	name: str
	group_id: int
	item_id: int
	class_id: int
	attributes: array[TLV]

	def __init__(self, name: str, group_id: int, item_id: int, class_id: int, attributes: Optional[array[TLV]] = None) -> None:
		self.name = name
		self.group_id = group_id
		self.item_id = item_id
		self.class_id = class_id
		self.attributes = attributes or []

	def marshal(self) -> bytes:
		buf = Buffer()
		buf.write_string_u16(self.name)
		buf.write_u16(self.group_id)
		buf.write_u16(self.item_id)
		buf.write_u16(self.class_id)
		buf.write_tlv_l_block(self.attributes)

		return buf.data


def get_items(context: OSCARContext) -> array[FeedbagItem]:
	user = context.user
	detail = user.detail

	contacts = list({
		*detail.get_contacts_by_list(ContactList.AL),
		*detail.get_contacts_by_list(ContactList.FL)
	})

	group_feedbag = []
	group_order = b""

	contact_feedbag = []

	for id, group in detail._groups_by_id.items():
		order = b""

		for contact in contacts:
			user = contact.head

			for grp in contact._groups.copy():
				if grp.id == id:
					contact_feedbag.append(FeedbagItem(user.username, int(group.id), user.id, FeedbagClass.Buddy))
					order += struct.pack(">H", user.id)

		group_feedbag.append(FeedbagItem(group.name, int(group.id), 0x0000, FeedbagClass.Group, [
			TLV(FeedbagAttributes.Order, order)
		]))

		group_order += struct.pack(">H", int(group.id))

	# deal with any ungrouped contacts left
	if ungrouped_contacts := [contact for contact in contacts if not contact._groups]:
		no_group_gid = len(group_feedbag) + 1

		order = b""

		for contact in ungrouped_contacts:
			user = contact.head

			contact_feedbag.append(FeedbagItem(user.username, no_group_gid, user.id, FeedbagClass.Buddy))

			order += struct.pack(">H", user.id)

		group_feedbag.append(FeedbagItem("(No Group)", no_group_gid, 0x0000, FeedbagClass.Group, [
			TLV(FeedbagAttributes.Order, order)
		]))

	return [
		FeedbagItem("", 0x0000, 0x0000, FeedbagClass.Group, [
			TLV(FeedbagAttributes.Order, group_order)
		]),

		FeedbagItem("", 0x0000, 0x0E63, FeedbagClass.PdInfo, [
			TLV(FeedbagAttributes.PdMode,			struct.pack(">H", 0x0004)),
			TLV(FeedbagAttributes.WirelessPdMode,	struct.pack(">B", 0x0001)),
			TLV(FeedbagAttributes.WirelessIgnoreMode, struct.pack(">B", 0x0001)),
			TLV(FeedbagAttributes.FishPdMode,		struct.pack(">B", 0x0001)),
			TLV(FeedbagAttributes.FishIgnoreMode,	struct.pack(">B", 0x0001)),
			TLV(FeedbagAttributes.PdMask,			struct.pack(">H", 0xFFFF))
		]),

		FeedbagItem("", 0x0000, 0x4B1D, FeedbagClass.BuddyPrefs, [
			TLV(FeedbagAttributes.BuddyPrefs, struct.pack(">L", 0x00000400))
		]),

		*group_feedbag,
		*contact_feedbag
	]


def marshal_items(items: array[FeedbagItem]) -> bytes:
	return b"".join([item.marshal() for item in items])


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
	while len(buf) > 10:
		name = buf.read_string_u16()
		group_id = buf.read_u16()
		item_id = buf.read_u16()
		class_id = buf.read_u16()
		attributes = buf.read_tlv_l_block()

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

def build_buddy_added_notif(adder_username: str) -> SNACMessage:
	msg = SNACMessage(0x0013, 0x001C)
	username_bytes = adder_username.encode('ascii')
	msg.write_u8(len(username_bytes))
	msg.write_bytes(username_bytes)
	return msg

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

		items = get_items(context)

		response_msg = SNACMessage(0x0013, 0x0006, 0x0000, message.request_id)
		response_msg.write_u8(0)						# feedbag protocol version - always 0
		response_msg.write_u16(len(items))			  # no. of feedbag items
		response_msg.write_bytes(marshal_items(items))  # list of feedbag items
		response_msg.write_u32(int(time.time()))		# feedbag last change time - TODO: should pull from db

		self.logger.info("[Server] FEEDBAG__REPLY")
		client.send_snac(response_msg)

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

		current_items = get_items(context)

		if len(current_items) == cached_feedbag_num_items:
			response_msg = SNACMessage(0x0013, 0x000F, 0x0000, message.request_id)
			response_msg.write_u32(cached_feedbag_timestamp)
			response_msg.write_u16(cached_feedbag_num_items)

			self.logger.info("[Server] FEEDBAG__REPLY_NOT_MODIFIED")
			client.send_snac(response_msg)
		else:
			self.query(client, context, message)

	@Subgroup(0x0007)
	def use(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__USE")

		# set our status to Online
		context.bs.me_update({
			"substatus": Substatus.Online
		})

		# notify the client if any contacts are online
		user = context.user
		detail = user.detail

		contacts = list({
			*detail.get_contacts_by_list(ContactList.AL)
		})

		for contact in contacts:
			if not contact.status.is_offlineish():
				client.send_snac(build_presence_notif(contact))

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
		user = context.user
		detail = user.detail
		items = unmarshal_items(message.data)
		statuses = []

		for item in items:
			if item.class_id == FeedbagClass.Group:
				if item.group_id == 0 and item.item_id == 0:
					statuses.append(FeedbagStatus.Success)
					continue

				existing_names = {g.name.lower() for g in detail._groups_by_id.values()}
				if item.name.lower() in existing_names:
					statuses.append(FeedbagStatus.AlreadyExists)
					continue

				try:
					group = bs.me_group_add(item.name)
					mapping = bs.front_data.setdefault("oscar0_group_id_map", {})
					mapping[item.group_id] = group.id
					self.logger.info("[Client] Added group:", item.name)
					statuses.append(FeedbagStatus.Success)
				except Exception:
					statuses.append(FeedbagStatus.BadRequest)

			elif item.class_id == FeedbagClass.Buddy:
				if not item.name:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact_uuid = context.backend.util_get_uuid_from_username(item.name)
				if contact_uuid is None:
					self.logger.info("[Client] Unknown buddy:", item.name)
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact = detail.contacts.get(contact_uuid)
				if contact is not None and contact.lists & ContactList.FL:
					statuses.append(FeedbagStatus.AlreadyExists)
					continue

				try:
					bs.me_contact_add(contact_uuid, ContactList.FL | ContactList.AL)

					if item.group_id != 0:
						backend_group_id = _resolve_group_backend_id(context, item.group_id)
						if backend_group_id is not None:
							bs.me_group_contact_add(backend_group_id, contact_uuid)

					self.logger.info("[Client] Added buddy:", item.name)
					statuses.append(FeedbagStatus.Success)
				except error.ContactListIsFull:
					statuses.append(FeedbagStatus.OverLimit)
				except Exception:
					statuses.append(FeedbagStatus.BadRequest)

			elif item.class_id == FeedbagClass.Deny:
				if not item.name:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact_uuid = context.backend.util_get_uuid_from_username(item.name)
				if contact_uuid is None:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact = detail.contacts.get(contact_uuid)
				if contact is not None and contact.lists & ContactList.BL:
					statuses.append(FeedbagStatus.AlreadyExists)
					continue

				try:
					bs.me_contact_add(contact_uuid, ContactList.BL)
					self.logger.info("[Client] Added deny entry:", item.name)
					statuses.append(FeedbagStatus.Success)
				except Exception:
					statuses.append(FeedbagStatus.BadRequest)

			elif item.class_id == FeedbagClass.Permit:
				if not item.name:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact_uuid = context.backend.util_get_uuid_from_username(item.name)
				if contact_uuid is None:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact = detail.contacts.get(contact_uuid)
				if contact is not None and contact.lists & ContactList.AL:
					statuses.append(FeedbagStatus.AlreadyExists)
					continue

				try:
					bs.me_contact_add(contact_uuid, ContactList.AL)
					self.logger.info("[Client] Added permit entry:", item.name)
					statuses.append(FeedbagStatus.Success)
				except Exception:
					statuses.append(FeedbagStatus.BadRequest)

			else:
				statuses.append(FeedbagStatus.Success)

		self.logger.info("[Server] FEEDBAG__STATUS")
		_send_feedbag_status(client, message.request_id, statuses)

	@Subgroup(0x0009)
	def update_item(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__UPDATE_ITEM")

		bs = context.bs
		user = context.user
		detail = user.detail
		items = unmarshal_items(message.data)
		statuses = []

		for item in items:
			if item.class_id == FeedbagClass.Group:
				if item.group_id == 0 and item.item_id == 0:
					statuses.append(FeedbagStatus.Success)
					continue

				backend_group_id = _resolve_group_backend_id(context, item.group_id)
				if backend_group_id is None:
					statuses.append(FeedbagStatus.NotFound)
					continue

				group = detail._groups_by_id.get(backend_group_id)
				if group is None:
					statuses.append(FeedbagStatus.NotFound)
					continue

				if item.name and item.name != group.name:
					try:
						bs.me_group_edit(backend_group_id, new_name=item.name)
						self.logger.info("[Client] Renamed group to:", item.name)
						statuses.append(FeedbagStatus.Success)
					except Exception:
						statuses.append(FeedbagStatus.BadRequest)
				else:
					statuses.append(FeedbagStatus.Success)

			else:
				statuses.append(FeedbagStatus.Success)

		self.logger.info("[Server] FEEDBAG__STATUS")
		_send_feedbag_status(client, message.request_id, statuses)

	@Subgroup(0x000A)
	def delete_item(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info("[Client] FEEDBAG__DELETE_ITEM")

		bs = context.bs
		user = context.user
		detail = user.detail
		items = unmarshal_items(message.data)
		statuses = []

		for item in items:
			if item.class_id == FeedbagClass.Group:
				if item.group_id == 0 and item.item_id == 0:
					statuses.append(FeedbagStatus.BadRequest)
					continue

				backend_group_id = _resolve_group_backend_id(context, item.group_id)
				if backend_group_id is None:
					statuses.append(FeedbagStatus.NotFound)
					continue

				try:
					bs.me_group_remove(backend_group_id)
					mapping = bs.front_data.get("oscar0_group_id_map", {})
					for k in [k for k, v in mapping.items() if v == backend_group_id]:
						del mapping[k]
					self.logger.info("[Client] Removed group:", item.name)
					statuses.append(FeedbagStatus.Success)
				except Exception:
					statuses.append(FeedbagStatus.NotFound)

			elif item.class_id == FeedbagClass.Buddy:
				if not item.name:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact_uuid = context.backend.util_get_uuid_from_username(item.name)
				if contact_uuid is None:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact = detail.contacts.get(contact_uuid)
				if contact is None or not (contact.lists & ContactList.FL):
					statuses.append(FeedbagStatus.NotFound)
					continue

				try:
					if item.group_id != 0:
						backend_group_id = _resolve_group_backend_id(context, item.group_id)
						if backend_group_id is not None:
							bs.me_group_contact_remove(backend_group_id, contact_uuid)

					if not contact._groups:
						bs.me_contact_remove(contact_uuid, ContactList.FL)

					self.logger.info("[Client] Removed buddy:", item.name)
					statuses.append(FeedbagStatus.Success)
				except Exception:
					statuses.append(FeedbagStatus.BadRequest)

			elif item.class_id == FeedbagClass.Deny:
				if not item.name:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact_uuid = context.backend.util_get_uuid_from_username(item.name)
				if contact_uuid is None:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact = detail.contacts.get(contact_uuid)
				if contact is None or not (contact.lists & ContactList.BL):
					statuses.append(FeedbagStatus.NotFound)
					continue

				try:
					bs.me_contact_remove(contact_uuid, ContactList.BL)
					self.logger.info("[Client] Removed deny entry:", item.name)
					statuses.append(FeedbagStatus.Success)
				except Exception:
					statuses.append(FeedbagStatus.BadRequest)

			elif item.class_id == FeedbagClass.Permit:
				if not item.name:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact_uuid = context.backend.util_get_uuid_from_username(item.name)
				if contact_uuid is None:
					statuses.append(FeedbagStatus.BadLoginID)
					continue

				contact = detail.contacts.get(contact_uuid)
				if contact is None or not (contact.lists & ContactList.AL):
					statuses.append(FeedbagStatus.NotFound)
					continue

				try:
					bs.me_contact_remove(contact_uuid, ContactList.AL)
					self.logger.info("[Client] Removed permit entry:", item.name)
					statuses.append(FeedbagStatus.Success)
				except Exception:
					statuses.append(FeedbagStatus.BadRequest)

			else:
				statuses.append(FeedbagStatus.Success)

		self.logger.info("[Server] FEEDBAG__STATUS")
		_send_feedbag_status(client, message.request_id, statuses)