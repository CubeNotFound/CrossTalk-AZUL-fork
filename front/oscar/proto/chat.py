import asyncio
import secrets

from typing import Any, Optional
from core import event
from core.backend import BackendSession, ChatSession, Chat
from core.models import User, Substatus, MessageData, MessageType

from ..proto.snac import SNACMessage
from ..proto.tlv import TLV
from ..proto.buffer import Buffer
from ..foodgroups.icbm import ICBMChannel, messagedata_to_icbm

class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('loop', 'ctrl', 'bs', 'cs', 'cookie')

	loop: asyncio.AbstractEventLoop
	ctrl: Any
	bs: BackendSession
	cs: ChatSession
	cookie: bytes

	def __init__(self, loop: asyncio.AbstractEventLoop, ctrl: Any, bs: BackendSession) -> None:
		self.loop = loop
		self.ctrl = ctrl
		self.bs = bs
		self.cookie = secrets.token_bytes(8)

	def on_participant_joined(self, cs_other: 'ChatSession', first_pop: bool, initial_join: bool) -> None:
		self.ctrl.logger.info('on_participant_joined')
		pass

	def on_participant_left(self, cs_other: 'ChatSession', last_pop: bool) -> None:
		self.ctrl.logger.info('on_participant_left')
		pass

	def on_chat_invite_declined(self, chat: 'Chat', invitee: User, *, invitee_id: Optional[str] = None,
								message: Optional[str] = None, circle: bool = False) -> None:
		self.ctrl.logger.info('on_chat_invite_declined')
		pass

	def on_chat_updated(self) -> None:
		self.ctrl.logger.info('on_chat_updated')
		pass

	def on_chat_roster_updated(self) -> None:
		self.ctrl.logger.info('on_chat_roster_updated')
		pass

	def on_participant_status_updated(self, cs_other: 'ChatSession', first_pop: bool, initial: bool,
									  old_substatus: Substatus) -> None:
		self.ctrl.logger.info('on_participant_status_updated')
		pass

	def on_message(self, data: MessageData) -> None:

		self.ctrl.logger.info('Got a message from', data.sender.username, 'saying:')
		self.ctrl.logger.info(data.text.encode())

		self.ctrl.send_snac(messagedata_to_icbm(self.cookie, data, self.bs.user))

