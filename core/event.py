from typing import TYPE_CHECKING, Optional, Dict, Any, List
from abc import ABCMeta, abstractmethod

from .models import User, Contact, OIM, Circle, CircleRole, MessageData, TextWithData, Substatus, LoginOption
from .alerts import Alert
from util.misc import MultiDict

if TYPE_CHECKING:
	from .backend import BackendSession, Chat, ChatSession

class BackendEventHandler(metaclass = ABCMeta):
	__slots__ = ('bs',)
	
	bs: 'BackendSession'
	
	# Note to subclassers, regarding `__init__`:
	# `bs` is assigned in `Backend.login`, before `BackendEventHandler.on_open` is called,
	# because of circular references.
	# Therefore, your `__init__` should be conspicuously missing an assignment to `bs`.
	
	def on_open(self) -> None:
		pass
	
	def on_close(self) -> None:
		pass
	
	def on_maintenance_message(self, *args: Any, **kwargs: Any) -> None:
		pass

	def on_client_alert(self, alert: Alert) -> bool:
		return False
	
	def on_maintenance_boot(self) -> None:
		pass

	def on_warning_level_changed(self, level: int, warner: Optional[User]) -> None:
		pass

	@abstractmethod
	def on_presence_notification(
		self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
		trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True,
		send_status_on_bl: bool = False, sess_id: Optional[int] = None, updated_phone_info: Optional[Dict[str, Any]] = None,
	) -> None: pass
	
	@abstractmethod
	def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True, update_info: bool = True) -> None: pass
	
	@abstractmethod
	def on_chat_invite(
		self, chat: 'Chat', inviter: User, *,
		circle: bool = False, inviter_id: Optional[str] = None, invite_msg: str = '',
	) -> None: pass
	
	@abstractmethod
	def on_declined_chat_invite(self, chat: 'Chat', circle: bool = False) -> None: pass
	
	# `user` added me to their FL, and they're now on my RL.
	@abstractmethod
	def on_added_me(self, user: User, *, adder_id: Optional[str] = None, message: Optional[TextWithData] = None) -> None: pass
	
	@abstractmethod
	def on_removed_me(self, user: User) -> None: pass
	
	# `user` didn't accept contact request
	@abstractmethod
	def on_contact_request_denied(self, user_added: User, message: str, *, contact_id: Optional[str] = None) -> None: pass
	
	@abstractmethod
	def on_login_elsewhere(self, option: LoginOption) -> None: pass
	
	@abstractmethod
	def on_oim_sent(self, oim: OIM) -> None: pass
	
	@abstractmethod
	def on_circle_created(self, circle: Circle) -> None: pass
	
	@abstractmethod
	def on_circle_invite_revoked(self, chat_id: str) -> None: pass
	
	@abstractmethod
	def on_accepted_circle_invite(self, circle: Circle) -> None: pass
	
	@abstractmethod
	def on_circle_updated(self, circle: Circle) -> None: pass
	
	@abstractmethod
	def on_left_circle(self, circle: Circle) -> None: pass
	
	@abstractmethod
	def on_circle_role_updated(self, chat_id: str, role: CircleRole) -> None: pass
	
	# TODO: Make these non-frontend-specific to allow interop
	
	def msn_on_oim_deletion(self, oims_deleted: int) -> None:
		pass
	
	def msn_on_uun_sent(
		self, sender: User, type: Optional[int], data: Optional[bytes], *,
		pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None, sdg: Optional[bytes] = None,
	) -> None:
		pass
	
	def msn_on_notify_ab(self) -> None:
		pass
	
	def msn_on_whats_new(self, publisher: User) -> None:
		pass
	
	def msn_on_notify_circle_ab(self, chat_id: str) -> None:
		pass

	def msn_on_page(self, sender: User, text: str) -> bool:
		return False

	
	def ymsg_on_p2p_msg_request(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_xfer_init(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_sent_ft_http(self, yahoo_id_sender: str, url_path: str, upload_time: float, message: str) -> None:
		pass
	
	def ymsg_on_upload_file_ft(self, recipient: str, message: str) -> None:
		pass
	
	def ymsg_on_friend_icon(self, yahoo_id_sender: str, yahoo_id_receiver: str, checksum: bytes) -> None:
		pass

	def ymsg_on_friend_icon_download(self, yahoo_id_sender: str, yahoo_id_receiver: str, url: str, checksum: bytes) -> None:
		pass

	def ymsg_on_friend_icon_file_transfer(self, yahoo_id_sender: str, yahoo_id_receiver: str, url: str, filename: str, ts: str) -> None:
		pass
	
	def ymsg_on_friend_icon_flag(self, yahoo_id_sender: str, yahoo_id_receiver: str, icon_flag: bytes) -> None:
		pass
	
	def ymsg_on_audible(self, sender: str, receiver: str, audible_id: bytes, text: bytes, checksum: bytes) -> None:
		pass
	
	def ymsg_on_im_panel_feature(self, sender: str, receiver: str, feature: bytes, state: bytes) -> None:
		pass
	
	def ymsg_on_im_session(self, sender: str, receiver: str, flag: bytes) -> None:
		pass
	
	def ymsg_on_message_ack(self, sender: str, receiver: str, msg_id: bytes) -> None:
		pass
	
	def ymsg_on_imvironment(self, sender: str, receiver: str, imv: bytes, state: bytes) -> None:
		pass

	def ymsg_on_buddy_response(self, buddy: User, accepted: bool, message: str = '') -> None:
		pass

	def ymsg_on_photo_add(
		self, sender: str, receiver: str, photo_id: bytes,
		name: Optional[bytes], thumbnail: Optional[bytes], url: Optional[bytes],
	) -> None:
		pass
	
	def ymsg_on_photo_ack(self, sender: str, receiver: str, photo_id: bytes) -> None:
		pass
	
	def ymsg_on_photo_select(self, sender: str, receiver: str, photo_id: bytes, action: bytes) -> None:
		pass
	
	def ymsg_on_photo_relay(
		self, sender: str, receiver: str, photo_id: bytes, token: bytes, *,
		relay_host: bytes, filesize: Optional[bytes], ack: bool,
	) -> None:
		pass
	
	def ymsg_on_ft_invite(self, sender: str, receiver: str, cookie: bytes, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_ft_setup(
		self, sender: str, receiver: str, cookie: bytes, *,
		filename: bytes, relay_host: bytes, peer_path: bytes, transfer_type: bytes,
	) -> None:
		pass
	
	def ymsg_on_ft_init(
		self, sender: str, receiver: str, cookie: bytes, yahoo_data: MultiDict[bytes, bytes], *, cancelled: bool = False,
	) -> None:
		pass
	
	def ymsg_on_sip_invite(self, caller: str, callee: str, call_id: str, sdp: str, *, video: bool = False) -> None:
		pass
	
	def ymsg_on_sip_bye(self, caller: str, callee: str, call_id: str) -> None:
		pass
class ChatEventHandler(metaclass = ABCMeta):
	__slots__ = ('cs',)
	
	cs: 'ChatSession'
	
	# Note to subclassers, regarding `__init__`:
	# `cs` is assigned in `Chat.join`, before `ChatEventHandler.on_open` is called,
	# because of circular references.
	# Therefore, your `__init__` should be conspicuously missing an assignment to `cs`.
	
	def on_open(self) -> None:
		pass
	
	def on_close(self) -> None:
		pass
	
	@abstractmethod
	def on_participant_joined(self, cs_other: 'ChatSession', first_pop: bool, initial_join: bool) -> None: pass
	
	@abstractmethod
	def on_participant_left(self, cs_other: 'ChatSession', last_pop: bool) -> None: pass
	
	@abstractmethod
	def on_chat_invite_declined(
		self, chat: 'Chat', invitee: User, *,
		invitee_id: Optional[str] = None, message: Optional[str] = None, circle: bool = False,
	) -> None: pass
	
	@abstractmethod
	def on_chat_updated(self) -> None: pass
	
	@abstractmethod
	def on_chat_roster_updated(self) -> None: pass
	
	@abstractmethod
	def on_participant_status_updated(self, cs_other: 'ChatSession', first_pop: bool, initial: bool, old_substatus: Substatus) -> None: pass
	
	@abstractmethod
	def on_message(self, data: MessageData) -> None: pass
