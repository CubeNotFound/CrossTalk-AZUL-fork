import asyncio
import secrets
from typing import Any, Optional, List
from core import event
from core.backend import BackendSession, ChatSession, Chat
from core.models import User, Substatus, MessageData, MessageType
from ..proto.snac import SNACMessage
from ..proto.tlv import TLV
from ..proto.buffer import Buffer
from ..foodgroups.icbm import ICBMChannel, gen_cookie, messagedata_to_icbm, messagedata_to_icbm_event

class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('loop', 'ctrl', 'bs', 'cs', 'cookie', '_pending')
	loop: asyncio.AbstractEventLoop
	ctrl: Any
	bs: BackendSession
	cs: ChatSession
	cookie: bytes
	_pending: List

	def __init__(self, loop: asyncio.AbstractEventLoop, ctrl: Any, bs: BackendSession) -> None:
		self.loop = loop
		self.ctrl = ctrl
		self.bs = bs
		self.cookie = secrets.token_bytes(8)
		self._pending = []

	def on_participant_joined(self, cs_other: 'ChatSession', first_pop: bool, initial_join: bool) -> None:
		self.ctrl.logger.info('on_participant_joined')
		still_pending = []
		for (target_uuid, data) in self._pending:
			if cs_other.user.uuid == target_uuid:
				self.cs.send_message_to_user(target_uuid, data)
			else:
				still_pending.append((target_uuid, data))
		self._pending = still_pending

	def on_participant_left(self, cs_other: 'ChatSession', last_pop: bool) -> None:
		self.ctrl.logger.info('on_participant_left')
		# once the other side is gone this chat can't reach them again (they'd be invited to a new one), so it's let go
		if any(cs is not self.cs for cs in self.cs.chat.get_roster()):
			return
		chats = self.bs.front_data.get('oscar0_chats', {})
		for uuid, (cs, _) in list(chats.items()):
			if cs is self.cs:
				del chats[uuid]
		# (closed once the chat is done telling everyone, since it's still walking its roster)
		self.loop.call_soon(self.cs.close)

	def on_chat_invite_declined(self, chat: 'Chat', invitee: User, *, invitee_id: Optional[str] = None,
								message: Optional[str] = None, circle: bool = False) -> None:
		self.ctrl.logger.info('on_chat_invite_declined')

	def on_chat_updated(self) -> None:
		self.ctrl.logger.info('on_chat_updated')

	def on_chat_roster_updated(self) -> None:
		self.ctrl.logger.info('on_chat_roster_updated')

	def on_participant_status_updated(self, cs_other: 'ChatSession', first_pop: bool, initial: bool,
									  old_substatus: Substatus) -> None:
		self.ctrl.logger.info('on_participant_status_updated')

	def on_message(self, data: MessageData) -> None:
		if data.sender is self.bs.user:
			if data.front_cache.get('icbm_echo'):
				original_cookie = data.front_cache.get('icbm_cookie', self.cookie)
				self.ctrl.send_snac(messagedata_to_icbm(original_cookie, data, self.bs))
			return

		if data.type in (MessageType.Typing, MessageType.TypingDone):
			self.ctrl.send_snac(messagedata_to_icbm_event(data, self.bs))
			return
		elif data.type is MessageType.Chat:
			self.ctrl.logger.info('Got a message from', data.sender.username, 'saying:')
			self.ctrl.logger.info((data.text or '').encode())
			# an OSCAR sender's own message cookie travels with the message, so acks and replies line up on both ends; anything
			# else gets a fresh one, since clients take a repeated cookie for a repeated message
			self.ctrl.send_snac(messagedata_to_icbm(data.front_cache.get('icbm_cookie') or gen_cookie(), data, self.bs))
		else:
			pass

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