from typing import Any, TYPE_CHECKING

from core import event
from core.models import Circle, CircleRole, Contact, LoginOption, MessageData, MessageType, OIM, Substatus, TextWithData, User

from front.oscar.proto.names import uin_of

if TYPE_CHECKING:
	from core.backend import Chat, ChatSession
	from .ctrl import LegacyCtrl


class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('ctrl',)

	ctrl: 'LegacyCtrl'

	def __init__(self, ctrl: 'LegacyCtrl') -> None:
		self.ctrl = ctrl

	def on_close(self) -> None:
		self.ctrl.close()

	def on_maintenance_boot(self) -> None:
		self.ctrl.close()

	def on_presence_notification(
		self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
		trid: str | None = None, update_status: bool = True, update_info_other: bool = True,
		send_status_on_bl: bool = False, sess_id: int | None = None, updated_phone_info: dict[str, Any] | None = None,
	) -> None:
		# only the people on the client's own contact list, and only when their status is what changed
		if not update_status:
			return
		try:
			self.ctrl.on_presence(ctc)
		except Exception as ex:
			self.ctrl.logger.error(ex)

	def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True, update_info: bool = True) -> None:
		pass

	def on_chat_invite(
		self, chat: 'Chat', inviter: User, *, circle: bool = False, inviter_id: str | None = None, invite_msg: str = '',
	) -> None:
		if chat is None:
			chat = self.ctrl.backend.chat_create()
			chat.add_id('icq0', chat.ids['main'])
		self.ctrl.join_chat(chat, inviter)

	def on_declined_chat_invite(self, chat: 'Chat', circle: bool = False) -> None:
		pass

	def on_added_me(self, user: User, *, adder_id: str | None = None, message: TextWithData | None = None) -> None:
		# someone put this account on their (stored) contact list: ICQ's "you were added", unless they're still waiting on
		# this account's authorization
		if uin_of(user) is None:
			return
		from front.oscar.foodgroups.buddy import buddy_pending
		if buddy_pending(user, self.ctrl.user):
			return
		self.ctrl.on_auth_event('added', user, '')

	def on_removed_me(self, user: User) -> None:
		pass

	def on_contact_request_denied(self, user_added: User, message: str | None, *, contact_id: str | None = None) -> None:
		pass

	def on_login_elsewhere(self, option: LoginOption) -> None:
		self.ctrl.force_offline()

	def on_oim_sent(self, oim: OIM) -> None:
		self.ctrl.deliver_oim_now(oim)

	def icq_on_auth_event(self, event: str, sender: User, text: str) -> None:
		# authorization traffic from the OSCAR ICQ frontend's machinery (see `front.oscar.foodgroups.feedbag`)
		self.ctrl.on_auth_event(event, sender, text)

	def icq_on_message(self, sender: User, msg_type: int, text: str) -> None:
		# an ICQ-only message (chat/file request, plugin...) relayed from an OSCAR ICQ client
		uin = uin_of(sender)
		if uin is not None:
			self.ctrl.deliver_message(uin, msg_type, text)

	# circles are not a thing in ICQ
	def on_circle_invite_revoked(self, chat_id: str) -> None:
		pass

	def on_accepted_circle_invite(self, circle: Circle) -> None:
		pass

	def on_circle_updated(self, circle: Circle) -> None:
		pass

	def on_left_circle(self, circle: Circle) -> None:
		pass

	def on_circle_role_updated(self, chat_id: str, role: CircleRole) -> None:
		pass

	def on_circle_created(self, circle: Circle) -> None:
		pass


class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('ctrl', 'cs', '_pending')

	ctrl: 'LegacyCtrl'
	cs: 'ChatSession'
	_pending: list[tuple[str, MessageData]]

	def __init__(self, ctrl: 'LegacyCtrl') -> None:
		self.ctrl = ctrl
		self._pending = []

	def on_participant_joined(self, cs_other: 'ChatSession', first_pop: bool, initial_join: bool) -> None:
		still_pending = []
		for target_uuid, data in self._pending:
			if cs_other.user.uuid == target_uuid:
				self.cs.send_message_to_user(target_uuid, data)
			else:
				still_pending.append((target_uuid, data))
		self._pending = still_pending

	def on_participant_left(self, cs_other: 'ChatSession', last_pop: bool) -> None:
		# once the other side is gone this chat can't reach them again (they'd be invited to a new one), so it's let go
		if any(cs is not self.cs for cs in self.cs.chat.get_roster()):
			return
		for uuid, (cs, _) in list(self.ctrl.chats.items()):
			if cs is self.cs:
				del self.ctrl.chats[uuid]
		# (closed once the chat is done telling everyone, since it's still walking its roster)
		self.ctrl.backend.loop.call_soon(self.cs.close)

	def on_chat_invite_declined(
		self, chat: 'Chat', invitee: User, *, invitee_id: str | None = None, message: str | None = None, circle: bool = False,
	) -> None:
		pass

	def on_chat_updated(self) -> None:
		pass

	def on_chat_roster_updated(self) -> None:
		pass

	def on_participant_status_updated(self, cs_other: 'ChatSession', first_pop: bool, initial: bool, old_substatus: Substatus) -> None:
		pass

	def on_message(self, data: MessageData) -> None:
		# typing notifications and the like have no ICQ form before OSCAR; only messages go through
		if self.ctrl.bs is None or data.sender is self.ctrl.bs.user or data.type is not MessageType.Chat:
			return
		self.ctrl.deliver_chat_message(data)

	def send_when_joined(self, user_uuid: str, data: MessageData) -> None:
		if any(cs_other.user.uuid == user_uuid for cs_other in self.cs.chat.get_roster()):
			self.cs.send_message_to_user(user_uuid, data)
		else:
			self._pending.append((user_uuid, data))
