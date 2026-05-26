from typing import Dict, List
from uuid import uuid4

from core.models import ContactList
from core.db import Base, User, UserProfile, UserContact, Circle, CircleMembership, Sound
from core.conn import Conn
from util import misc, hash
import settings, random

usercontacts_by_id_by_uuid = {} # type: Dict[int, Dict[str, UserContact]]

def main() -> None:
	U = [] # type: List[User]
	
	for domain in ['example.com', 'yahoo.com', 'hotmail.com', 'live.com', 'aol.com', 'msn.com']:
		d = domain[0]
		for i in range(1, 5 + 1):
			name = "T{}{}".format(i, d)
			user = create_user('{}@{}'.format(name.lower(), domain), name.lower(), random.randint(100000,999999), 'Test', 'User', '123456', name, "{} msg".format(name), False, True)
			user.id = len(U)
			usercontacts_by_id_by_uuid[user.id] = {}
			U.append(user)
		for i in range(1, 5 + 1):
			name = "D{}{}".format(i, d)
			user = create_user('{}@{}'.format(name.lower(), domain), name.lower(), random.randint(100000,999999), 'Test', 'User', '123456', name, "{} msg".format(name), False, False)
			user.id = len(U)
			usercontacts_by_id_by_uuid[user.id] = {}
			U.append(user)
	
	for i in range(5):
		name = "bot{}".format(i)
		user = create_user('{}@crosstalk.net'.format(name.lower()), name.lower(), random.randint(100000,999999), 'Dummy', 'Bot', '123456', name, "{} msg".format(name), False, False)
		user.id = len(U)
		usercontacts_by_id_by_uuid[user.id] = {}
		U.append(user)

	for i in range(2):
		name = "BannedUser{}".format(i)
		user = create_user('{}@banned.net'.format(name.lower()), name.lower(), random.randint(100000,999999), 'Banned', 'Guy', '123456', name, "{} msg".format(name), True, False)
		user.id = len(U)
		usercontacts_by_id_by_uuid[user.id] = {}
		U.append(user)
	
	for i, u in enumerate(U):
		contacts_by_group: Dict[str, ContactList[User]] = {}
		
		x = randomish(u)
		for j in range(x % 4):
			contacts_by_group["" if j == 0 else "U{}G{}".format(i, j)] = []
		group_names = list(contacts_by_group.keys())
		for uc in U:
			y = x ^ randomish(uc)
			for k, group_name in enumerate(group_names):
				z = y ^ k
				if z % 2 < 1:
					contacts_by_group[group_name].append(uc)
		
		set_contacts(u, contacts_by_group)
		add_profile(u)
	
	tables = []
	
	for u in U:
		tables.append(u)
		tables.extend(usercontacts_by_id_by_uuid[u.id].values())
	
	conn = Conn(settings.DB)
	Base.metadata.create_all(conn.engine)
	with conn.session() as sess:
		sess.query(User).delete()
		sess.query(UserContact).delete()
		sess.query(UserProfile).delete()
		sess.query(Circle).delete()
		sess.query(CircleMembership).delete()
		sess.query(Sound).delete()
		sess.add_all(tables)

def create_user(email: str, username: str, uin: int, first_name: str, last_name: str, pw: str, name: str, message: str, suspended: bool = False, is_tester: bool = False, is_mvp: bool = False) -> User:
	user = User(
		uuid = str(uuid4()), email = email, username = username, first_name = first_name, last_name = last_name, uin = uin, verified_to_login = True,
		name = name, is_tester = is_tester, is_mvp = is_mvp, show_in_dir = True, friendly_name = name, message = message,
		groups = [], settings = {}, suspended = suspended
	)
	set_passwords(user, pw, support_old_msn = True, support_yahoo = True, support_old_aim = True)
	return user

def set_contacts(user: User, contacts_by_group: Dict[str, List[User]]) -> None:
	#user.contacts = {}
	user.groups = []
	
	for i, (group_name, group_users) in enumerate(contacts_by_group.items()):
		group_id = str(i + 1)
		group_uuid = str(uuid4())
		if group_name:
			user.groups.append({ 'id': group_id, 'uuid': group_uuid, 'name': group_name, 'is_favorite': False })
		for u in group_users:
			contact = add_contact_twosided(user, u)
			if group_name:
				contact.groups.append({ 'id': group_id, 'uuid': group_uuid })

def randomish(u: User) -> int:
	return int(u.uuid[:8], 16)

def add_contact_twosided(user: User, user_contact: User) -> UserContact:
	contact = add_contact_onesided(user, user_contact, ContactList.AL | ContactList.FL)
	add_contact_onesided(user_contact, user, ContactList.RL)
	return contact

def add_contact_onesided(user: User, user_contact: User, lst: ContactList) -> UserContact:
	if user_contact.id not in usercontacts_by_id_by_uuid[user.id]:
		usercontacts_by_id_by_uuid[user.id][user_contact.uuid] = create_usercontact(user, user_contact)
	contact = usercontacts_by_id_by_uuid[user.id][user_contact.uuid]
	contact.lists |= lst
	return contact

def create_usercontact(user: User, user_contact: User) -> UserContact:
	return UserContact(
		user_id = user.id, user_uuid = user.uuid, contact_id = user_contact.id, uuid = user_contact.uuid,
		index_id = str(len(usercontacts_by_id_by_uuid[user.id]) + 2),
		name = user_contact.friendly_name,
		lists = ContactList.Empty, groups = [], is_messenger_user = True,
	)

def add_profile(user: User) -> UserProfile:
	return UserProfile(user_id = user.id, bio = 'I am a dummy!', pronouns = 'it/its', website = 'http://example.com', socials = {}, streetaddr = '', city = '', state = '', zip = '', country = '', interests = {})

def set_passwords(user: User, pw: str, *, support_old_msn: bool = False, support_yahoo: bool = False,
				  support_old_aim: bool = False) -> None:
	user.password = hash.hasher.encode(pw)

	if support_old_msn:
		pw_md5 = hash.hasher_md5.encode(pw)
		user.set_front_data('msn', 'pw_md5', pw_md5)

	if support_yahoo:
		pw_md5_unsalted = hash.hasher_md5.encode(pw, salt='')
		user.set_front_data('ymsg', 'pw_md5_unsalted', pw_md5_unsalted)

		pw_md5crypt = hash.hasher_md5crypt.encode(pw, salt='$1$_2S43d5f')
		user.set_front_data('ymsg', 'pw_md5crypt', pw_md5crypt)

	if support_old_aim:
		pw_md5 = hash.hasher_md5.encode(pw, identifier='AOL Instant Messenger (SM)')
		user.set_front_data('aim', 'pw_md5', pw_md5)

if __name__ == '__main__':
	main()
