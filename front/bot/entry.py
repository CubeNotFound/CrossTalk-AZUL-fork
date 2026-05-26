from typing import Optional, Dict, Any
import asyncio, random

from core.client import Client
from core.models import (
	Substatus, ContactList, Contact, User, Circle, CircleRole, TextWithData,
	MessageData, MessageType, LoginOption, OIM,
)
from core.backend import Backend, BackendSession, Chat, ChatSession
from core import event
from util.misc import MultiDict

CLIENT = Client('ct-bot', 'testing', 'direct')
BOT_EMAIL = 'bot1@crosstalk.im'

def register(loop: asyncio.AbstractEventLoop, backend: Backend) -> None:
	uuid = backend.util_get_uuid_from_email(BOT_EMAIL)
	assert uuid is not None
	bs = backend.login(uuid, CLIENT, BackendEventHandler(loop), option = LoginOption.BootOthers)
	assert bs is not None

class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('loop', 'bs')
	
	loop: asyncio.AbstractEventLoop
	bs: BackendSession
	
	def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
		self.loop = loop
	
	def on_open(self) -> None:
		bs = self.bs
		
		bs.me_update({ 'substatus': Substatus.Online })
		print(f"[Bot] {bs.user.status.name} is now online!")
		
		detail = bs.user.detail
		assert detail is not None
	
	def on_maintenance_boot(self) -> None:
		pass
	
	def on_presence_notification(
		self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
		trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True,
		send_status_on_bl: bool = False, sess_id: Optional[int] = None, updated_phone_info: Optional[Dict[str, Any]] = None,
	) -> None:
		pass
	
	def on_presence_self_notification(
		self, old_substatus: Substatus, *, update_status: bool = True, update_info: bool = True,
	) -> None:
		pass
	
	def on_circle_created(self, circle: Circle) -> None:
		pass
	
	def on_circle_updated(self, circle: Circle) -> None:
		pass
	
	def on_left_circle(self, circle: Circle) -> None:
		pass
	
	def on_accepted_circle_invite(self, circle: Circle) -> None:
		pass
	
	def on_circle_invite_revoked(self, chat_id: str) -> None:
		pass
	
	def on_circle_role_updated(self, chat_id: str, role: CircleRole) -> None:
		pass
	
	def on_chat_invite(
		self, chat: Chat, inviter: User, *, circle: bool = False, inviter_id: Optional[str] = None, invite_msg: str = '',
	) -> None:
		cs = chat.join('ct-bot', self.bs, ChatEventHandler(self.loop, self.bs))
		chat.send_participant_joined(cs)
	
	def on_declined_chat_invite(self, chat: Chat, circle: bool = False) -> None:
		pass
	
	def on_added_me(self, user: User, *, adder_id: Optional[str] = None, message: Optional[TextWithData] = None) -> None:
		# Auto-remove people from pending list
		bs = self.bs
		detail = bs.user.detail
		assert detail is not None
		
		ctc = detail.contacts.get(user.uuid)
		if ctc is not None:
			bs.me_contact_remove(ctc.head.uuid, ContactList.PL)
	
	def on_removed_me(self, user: User) -> None:
		pass
	
	def on_contact_request_denied(self, user_added: User, message: Optional[str], *, contact_id: Optional[str] = None) -> None:
		pass
	
	def on_oim_sent(self, oim: 'OIM') -> None:
		pass
	
	def ymsg_on_p2p_msg_request(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_xfer_init(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_sent_ft_http(self, yahoo_id_sender: str, url_path: str, upload_time: float, message: str) -> None:
		pass
	
	def on_login_elsewhere(self, option: LoginOption) -> None:
		pass

class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('loop', 'bs', 'cs', '_sending')
	
	loop: asyncio.AbstractEventLoop
	bs: BackendSession
	cs: ChatSession
	_sending: bool
	
	def __init__(self, loop: asyncio.AbstractEventLoop, bs: BackendSession) -> None:
		self.loop = loop
		self.bs = bs
		self._sending = False
	
	def on_open(self) -> None:
		self.cs.send_message_to_everyone(MessageData(
			sender = self.cs.user,
			type = MessageType.Chat,
			text = "Hello, world!",
		))
	
	def on_participant_joined(self, cs_other: ChatSession, first_pop: bool, initial_join: bool) -> None:
		pass
	
	def on_participant_left(self, cs_other: ChatSession, last_pop: bool) -> None:
		pass
	
	def on_chat_invite_declined(
		self, chat: Chat, invitee: User, *, invitee_id: Optional[str] = None, message: Optional[str] = None, circle: bool = False,
	) -> None:
		pass
	
	def on_chat_updated(self) -> None:
		pass
	
	def on_chat_roster_updated(self) -> None:
		pass
	
	def on_participant_status_updated(self, cs_other: ChatSession, first_pop: bool, initial: bool, old_substatus: Substatus) -> None:
		pass
	
	def on_invite_declined(self, invited_user: User, *, invited_id: Optional[str] = None, message: str = '') -> None:
		pass
	
	def on_message(self, message: MessageData) -> None:
		if self._sending:
			return
		
		if message.sender.email.endswith('@crosstalk.im'):
			return
		
		me = self.cs.user
		self._sending = True
		
		typing_message = MessageData(sender = me, type = MessageType.Typing)
		self.cs.send_message_to_everyone(typing_message)
		
		self.loop.create_task(self._send_delayed(random.uniform(0.5, 1), MessageData(
			sender = me, type = MessageType.Chat,
			text = "You, {}, insist that \"{}\".".format(message.sender.status.name, message.text),
		)))
	
	async def _send_delayed(self, delay: float, message: MessageData) -> None:
		await asyncio.sleep(delay, loop = self.loop)
		self.cs.send_message_to_everyone(message)
		self._sending = False
