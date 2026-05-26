from enum import IntEnum
from typing import Dict

from core.backend import BackendSession
from core.models import ContactList, Contact


class CommandBitFlag(IntEnum):
	CallbackReply = 256,
	CallbackAction = 512,
	CallbackError = 1024


def get_grouped_contacts(bs: BackendSession) -> Dict[str, list[Contact]]:
	user = bs.user
	detail = user.detail

	contacts = list({
		*detail.get_contacts_by_list(ContactList.AL),
		*detail.get_contacts_by_list(ContactList.FL)
	})
	grouped_contacts = {}

	# loop through every contact group
	for group in detail._groups_by_id.values():
		grouped_contacts[group.name] = []

		# loop through every contact in this group
		for contact in contacts:
			for grp in contact._groups:
				if grp.id == group.id:
					grouped_contacts[group.name].append(contact)

	# handle any contacts that might not be apart of any group
	if ungrouped_contacts := [contact for contact in contacts if not contact._groups]:
		grouped_contacts['(No Group)'] = []

		for contact in ungrouped_contacts:
			grouped_contacts['(No Group)'].append(contact)

	return grouped_contacts


def get_contact_groups(bs: BackendSession) -> list[str]:
	groups = []

	user = bs.user
	detail = user.detail

	contacts = list({
		*detail.get_contacts_by_list(ContactList.AL),
		*detail.get_contacts_by_list(ContactList.FL)
	})

	for group in detail._groups_by_id.values():
		groups.append(group.name)

	# add a fake `(No Group)` group if there is any contacts not apart of any group
	if any(not contact._groups for contact in contacts):
		groups.append('(No Group)')

	return groups


def unmarshal_msim_dict(data: str) -> Dict:
	return dict(pair.split('=', 1) for pair in data.split('\x1c'))
