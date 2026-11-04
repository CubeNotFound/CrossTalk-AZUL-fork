from typing import Callable

from core import error, event
from core.backend import Chat
from core.models import ContactList, MessageData, MessageType, Substatus, User

from util.misc import is_valid_oscar_screenname

COMMANDS: dict[str, Callable] = {}

def command(name: str):
	def deco(func):
		COMMANDS[name] = func
		return func
	return deco

@command('toc_signon')
def _toc_signon(ctrl, args: list[str]) -> None:
	if len(args) < 4:
		ctrl.send_line('ERROR:980')
		return
	ctrl.sign_on(args[2], args[3], dialect = 1)

@command('toc2_signon')
def _toc2_signon(ctrl, args: list[str]) -> None:
	if len(args) < 4:
		ctrl.send_line('ERROR:980')
		return
	ctrl.sign_on(args[2], args[3], dialect = 2)

@command('toc_init_done')
def _toc_init_done(ctrl, args: list[str]) -> None:
	ctrl.init_done()

@command('toc_quit')
def _toc_quit(ctrl, args: list[str]) -> None:
	ctrl.close()

@command('toc_ping')
def _toc_ping(ctrl, args: list[str]) -> None:
	pass

@command('toc_add_buddy')
def _toc_add_buddy(ctrl, args: list[str]) -> None:
	if ctrl.bs is None: return
	for name in args:
		if not is_valid_oscar_screenname(name): continue
		uuid = ctrl.backend.util_get_uuid_from_username(name)
		if uuid is None: continue
		try:
			ctrl.bs.me_contact_add(uuid, ContactList.FL, name = name)
		except error.ClientError:
			pass

@command('toc_remove_buddy')
def _toc_remove_buddy(ctrl, args: list[str]) -> None:
	if ctrl.bs is None: return
	for name in args:
		if name == ':': continue
		uuid = ctrl.backend.util_get_uuid_from_username(name)
		if uuid is None: continue
		try:
			ctrl.bs.me_contact_remove(uuid, ContactList.FL)
		except error.ClientError:
			pass

@command('toc_add_permit')
def _toc_add_permit(ctrl, args: list[str]) -> None:
	_add_pd(ctrl, args, ContactList.AL)

@command('toc_add_deny')
def _toc_add_deny(ctrl, args: list[str]) -> None:
	_add_pd(ctrl, args, ContactList.BL)

def _add_pd(ctrl, args: list[str], lst) -> None:
	if ctrl.bs is None: return
	for name in args:
		if not is_valid_oscar_screenname(name): continue
		uuid = ctrl.backend.util_get_uuid_from_username(name)
		if uuid is None: continue
		try:
			ctrl.bs.me_contact_add(uuid, lst, name = name)
		except error.ClientError:
			pass

@command('toc_set_config')
def _toc_set_config(ctrl, args: list[str]) -> None:
	if ctrl.bs is None or not args: return
	for line in args[0].split('\n'):
		line = line.strip()
		if line.startswith('m '):
			try:
				mode = int(line[2:].strip())
			except ValueError:
				continue
			blp = 'AL' if mode in (1, 3, 5) else 'BL'
			ctrl.bs.me_update({'blp': blp})


@command('toc_set_away')
def _toc_set_away(ctrl, args: list[str]) -> None:
	if ctrl.bs is None: return
	message = args[0] if args else ''
	ctrl.bs.me_update({'message': message, 'substatus': Substatus.Away if message else Substatus.Online})

@command('toc_set_idle')
def _toc_set_idle(ctrl, args: list[str]) -> None:
	pass


@command('toc_send_im')
def _toc_send_im(ctrl, args: list[str]) -> None:
	if ctrl.bs is None or len(args) < 2: return
	receiver_name, message = args[0], args[1]

	if not is_valid_oscar_screenname(receiver_name):
		ctrl.send_line('ERROR:901:{}'.format(receiver_name))  # not available
		return
	receiver_uuid = ctrl.backend.util_get_uuid_from_username(receiver_name)
	if receiver_uuid is None:
		ctrl.send_line('ERROR:901:{}'.format(receiver_name))
		return

	try:
		cs, evt = _get_private_chat_with(ctrl, receiver_uuid)
	except error.ClientError:
		ctrl.send_line('ERROR:901:{}'.format(receiver_name))
		return

	md = MessageData(sender = ctrl.bs.user, type = MessageType.Chat, text = message)
	if not ctrl.backend.util_message_allowed(ctrl.bs.user, md):
		ctrl.send_line('ERROR:903')
		return
	evt._send_when_user_joins(receiver_uuid, md)

@command('toc_evil')
def _toc_evil(ctrl, args: list[str]) -> None:
	pass
	if ctrl.bs is None or not args: return
	name = args[0]
	target_uuid = ctrl.backend.util_get_uuid_from_username(name) if is_valid_oscar_screenname(name) else None
	target = ctrl.backend._load_user_record(target_uuid) if target_uuid is not None else None
	if (
		target is None or target is ctrl.bs.user or target.status.is_offlineish()
		or not ctrl.backend.util_get_sessions_by_user(target)
	):
		ctrl.send_line('ERROR:902:{}'.format(name))  # warning of <name> not currently available
		return
	anonymous = (len(args) > 1 and args[1].lower() == 'anon')
	if ctrl.backend.abuse.warn(ctrl.bs.user, target, anonymous = anonymous) is None:
		ctrl.send_line('ERROR:902:{}'.format(name))

@command('toc_chat_join')
def _toc_chat_join(ctrl, args: list[str]) -> None:
	if ctrl.bs is None or len(args) < 2: return
	room_name = args[1]
	chat = ctrl.backend.chat_create()
	chat.add_id('toc', chat.ids['main'])
	evt = TOCChatEventHandler(ctrl, ctrl.bs, room_name)
	cs = chat.join('toc', ctrl.bs, evt)
	chat_id = id(chat) & 0xFFFF
	ctrl.chats[chat_id] = (cs, evt)
	ctrl.send_line('CHAT_JOIN:{}:{}'.format(chat_id, room_name))

@command('toc_chat_send')
def _toc_chat_send(ctrl, args: list[str]) -> None:
	if len(args) < 2: return
	try:
		chat_id = int(args[0])
	except ValueError:
		return
	entry = ctrl.chats.get(chat_id)
	if entry is None: return
	cs, evt = entry
	md = MessageData(sender = ctrl.bs.user, type = MessageType.Chat, text = args[1])
	cs.send_message_to_everyone(md)

@command('toc_chat_leave')
def _toc_chat_leave(ctrl, args: list[str]) -> None:
	if not args: return
	try:
		chat_id = int(args[0])
	except ValueError:
		return
	entry = ctrl.chats.pop(chat_id, None)
	if entry is not None:
		entry[0].close()

@command('toc_chat_invite')
def _toc_chat_invite(ctrl, args: list[str]) -> None:
	if len(args) < 3: return
	try:
		chat_id = int(args[0])
	except ValueError:
		return
	entry = ctrl.chats.get(chat_id)
	if entry is None: return
	cs, evt = entry
	invite_msg = args[1]
	for name in args[2:]:
		if not is_valid_oscar_screenname(name): continue
		uuid = ctrl.backend.util_get_uuid_from_username(name)
		if uuid is None: continue
		invitee = ctrl.backend._load_user_record(uuid)
		if invitee is not None:
			try:
				cs.invite(invitee, invite_msg = invite_msg)
			except error.ClientError:
				pass

@command('toc_get_info')
def _toc_get_info(ctrl, args: list[str]) -> None:
	if args:
		ctrl.logger.info('[Client] toc_get_info for', args[0], '(no profile service configured)')

@command('toc_set_info')
def _toc_set_info(ctrl, args: list[str]) -> None:
	if ctrl.bs is None or not args: return
	ctrl.bs.me_update({'message': args[0]})

@command('toc_format_nickname')
def _toc_format_nickname(ctrl, args: list[str]) -> None:
	if ctrl.bs is None or not args: return
	ctrl.bs.me_update({'name': args[0], 'needs_notify': True, 'notify_self': True})
	ctrl.send_line('ADMIN_NICK_STATUS:0')

@command('toc_dir_search')
def _toc_dir_search(ctrl, args: list[str]) -> None:
	ctrl.send_line('DIR_STATUS:0:No matches found.')

@command('toc_set_caps')
def _toc_set_caps(ctrl, args: list[str]) -> None:
	pass

def build_config2(bs) -> str:
	detail = bs.user.detail
	assert detail is not None
	lines = []
	for grp in detail._groups_by_id.values():
		lines.append('g {}'.format(grp.name))
		for ctc in detail.get_contacts_by_list(ContactList.FL):
			if not is_valid_oscar_screenname(ctc.head.username): continue
			if any(g.id == grp.id for g in ctc._groups):
				lines.append('b {}'.format(ctc.head.username))
	for ctc in detail.get_contacts_by_list(ContactList.AL):
		if is_valid_oscar_screenname(ctc.head.username):
			lines.append('p {}'.format(ctc.head.username))
	for ctc in detail.get_contacts_by_list(ContactList.BL):
		if is_valid_oscar_screenname(ctc.head.username):
			lines.append('d {}'.format(ctc.head.username))
	mode = 3 if bs.user.settings.get('BLP', 'AL') == 'AL' else 4
	lines.append('m {}'.format(mode))
	return 'CONFIG2:{}'.format('\n'.join(lines))

def build_nick(user: User) -> str:
	return 'NICK:{}'.format(user.status.name or user.username)

def build_update_buddy(ctc, *, dialect: int) -> str:
	online = 'T' if not ctc.status.is_offlineish() else 'F'
	signon_time = int(ctc.head.date_login.timestamp()) if ctc.head.date_login else 0
	cmd = 'UPDATE_BUDDY2' if dialect == 2 else 'UPDATE_BUDDY'
	evil = max(0, min(999, int(ctc.head.evil_permanent or 0) + int(ctc.head.evil_temporary or 0))) // 10
	return '{}:{}:{}:{}:{}:0:'.format(cmd, ctc.head.username, online, evil, signon_time)


def _get_private_chat_with(ctrl, other_user_uuid: str):
	bs = ctrl.bs
	other_user = ctrl.backend._load_user_record(other_user_uuid)
	if other_user is None or not is_valid_oscar_screenname(other_user.username):
		raise error.ContactNotOnContactList()

	toc_chats = ctrl.front_data.setdefault('toc_chats', {})
	if other_user_uuid not in toc_chats:
		chat = ctrl.backend.chat_create()
		chat.front_data['toc'] = True
		evt = TOCChatEventHandler(ctrl, bs, other_user.username)
		cs = chat.join('toc', bs, evt)
		toc_chats[other_user_uuid] = (cs, evt)
		cs.invite(other_user)
	return toc_chats[other_user_uuid]


class TOCBackendEventHandler(event.BackendEventHandler):
	__slots__ = ('ctrl', 'bs')

	def __init__(self, ctrl) -> None:
		self.ctrl = ctrl

	def on_presence_notification(self, ctc, on_contact_add, old_substatus, **kwargs) -> None:
		if not is_valid_oscar_screenname(ctc.head.username):
			return
		self.ctrl.send_line(build_update_buddy(ctc, dialect = self.ctrl.dialect))

	def on_presence_self_notification(self, old_substatus, **kwargs) -> None:
		pass

	def on_chat_invite(self, chat: Chat, inviter: User, *, circle: bool = False, inviter_id = None, invite_msg: str = '') -> None:
		evt = TOCChatEventHandler(self.ctrl, self.bs, inviter.username)
		cs = chat.join('toc', self.bs, evt)
		chat_id = id(chat) & 0xFFFF
		self.ctrl.chats[chat_id] = (cs, evt)
		self.ctrl.front_data.setdefault('toc_chats', {})[inviter.uuid] = (cs, evt)

	def on_declined_chat_invite(self, chat: Chat, circle: bool = False) -> None:
		pass

	def on_added_me(self, user: User, *, adder_id = None, message = None) -> None:
		pass

	def on_removed_me(self, user: User) -> None:
		pass

	def on_contact_request_denied(self, user_added: User, message, *, contact_id = None) -> None:
		pass

	def on_oim_sent(self, oim) -> None:
		pass

	def on_login_elsewhere(self, option) -> None:
		self.ctrl.send_line('ERROR:982')  # signed on elsewhere
		self.ctrl.close()

	def on_circle_invite_revoked(self, chat_id: str) -> None: pass
	def on_accepted_circle_invite(self, circle) -> None: pass
	def on_circle_updated(self, circle) -> None: pass
	def on_left_circle(self, circle) -> None: pass
	def on_circle_role_updated(self, chat_id: str, role) -> None: pass
	def on_circle_created(self, circle) -> None: pass

	def on_maintenance_message(self, *args, **kwargs) -> None:
		pass

	def on_maintenance_boot(self) -> None:
		self.ctrl.close()

	def on_warning_level_changed(self, level: int, warner) -> None:
		previous = self.ctrl.front_data.get('toc_evil', 0)
		self.ctrl.front_data['toc_evil'] = level
		if level > previous:
			self.ctrl.send_line('EVILED:{}:{}'.format(level // 10, warner.username if warner is not None else ''))

	def on_close(self) -> None:
		self.ctrl.close()


class TOCChatEventHandler(event.ChatEventHandler):
	__slots__ = ('ctrl', 'bs', 'cs', 'peer_name', '_pending')

	def __init__(self, ctrl, bs, peer_name: str) -> None:
		self.ctrl = ctrl
		self.bs = bs
		self.peer_name = peer_name
		self._pending = []

	def on_participant_joined(self, cs_other, first_pop, initial_join) -> None:
		still = []
		for uuid, data in self._pending:
			if cs_other.user.uuid == uuid:
				self.cs.send_message_to_user(uuid, data)
			else:
				still.append((uuid, data))
		self._pending = still

	def on_participant_left(self, cs_other, last_pop) -> None:
		pass

	def on_chat_invite_declined(self, chat, invitee, *, invitee_id = None, message = None, circle = False) -> None:
		pass

	def on_chat_updated(self) -> None: pass
	def on_chat_roster_updated(self) -> None: pass
	def on_participant_status_updated(self, cs_other, first_pop, initial, old_substatus) -> None: pass

	def on_message(self, data: MessageData) -> None:
		if data.sender is self.bs.user:
			return
		auto_reply = 'T' if data.front_cache.get('away_response') else 'F'
		if self.ctrl.dialect == 2:
			self.ctrl.send_line('IM_IN2:{}:{}:0:0:{}'.format(data.sender.username, auto_reply, data.text or ''))
		else:
			self.ctrl.send_line('IM_IN:{}:{}:{}'.format(data.sender.username, auto_reply, data.text or ''))

	def _send_when_user_joins(self, user_uuid: str, data: MessageData) -> None:
		if self._user_in_chat(user_uuid):
			self.cs.send_message_to_user(user_uuid, data)
		else:
			self._pending.append((user_uuid, data))

	def _user_in_chat(self, user_uuid: str) -> bool:
		for cs_other in self.cs.chat.get_roster():
			if cs_other.user.uuid == user_uuid:
				return True
		return False