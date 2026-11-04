from typing import Tuple, Any, Optional, List, Set, Dict, cast
import time, asyncio
from email.parser import Parser

from util.misc import Logger, VoidTaskType, gen_uuid
from core.models import User, MessageData, MessageType, Substatus
from core.backend import Backend, BackendSession, ChatSession, Chat
from core import event, error
from .msnp import MSNPCtrl
from .misc import (
	Err, encode_capabilities_capabilitiesex, decode_email_pop, encode_email_pop, normalize_pop_id, get_session_capabilities,
	CAPABILITIESEX_P2PV2, DATACAST_MSNOBJ, DATACAST_ACTION, UNSUPPORTED_MESSAGE_TEXT, is_null_epid,
)
from .p2p_bridge import (
	get_p2p_state, chunk_p2p, translate_p2pv2_ack, build_sb_p2p_headers, sb_p2p_is_v2, neutralize_direct_p2p, sb_p2p_messages,
)
class MSNPCtrlSB(MSNPCtrl):
	__slots__ = ('backend', 'dialect', 'loop', 'counter_task', 'auth_sent', 'bs', 'cs', 'chunks')
	
	backend: Backend
	dialect: int
	loop: asyncio.AbstractEventLoop
	counter_task: Optional[VoidTaskType]
	auth_sent: bool
	bs: Optional[BackendSession]
	cs: Optional[ChatSession]
	chunks: Dict[str, Dict[str, Any]]
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.loop = backend.loop
		self.counter_task = None
		self.auth_sent = False
		self.bs = None
		self.cs = None
		self.chunks = {}
	
	def on_connect(self) -> None:
		self.counter_task = self.loop.create_task(self._conn_auth_limit_counter())
	
	def _on_close(self) -> None:
		if self.counter_task is not None:
			try:
				self.counter_task.cancel()
			except:
				pass
			self.counter_task = None
		if self.cs:
			self.cs.close()
	
	# State = Auth
	
	def _m_usr(self, trid: Optional[str], arg: Optional[str], token: Optional[str], *args: Any) -> None:
		backend = self.backend
		#>>> USR trid email@example.com token (MSNP < 16)
		#>>> USR trid email@example.com;{00000000-0000-0000-0000-000000000000} token (MSNP >= 16)
		self.auth_sent = True
		if trid is None or arg is None or token is None or len(args) > 0:
			self.close()
			return
		
		(email, pop_id) = decode_email_pop(arg)

		username, domain = email.split('@', 1)
				
		
		data = self.backend.auth_service.pop_token('sb/xfr', token) # type: Optional[Tuple[BackendSession, int]]
		if data is None:
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		
		bs, dialect = data
		bs_pop_id = bs.front_data.get('msn_pop_id') or ''
		if dialect == 2:
			uuid = backend.user_service.get_uuid_username(username)
			if uuid is None:
				self.send_reply(Err.AuthFail, trid)
				self.close()
				return
			user = backend.user_service.get(uuid)
			email = user.email
			
		alias_email = '{}@crosstalk.im'.format(bs.user.username).lower()
		valid_emails = (bs.user.email.lower(), alias_email)
		if email.lower() not in valid_emails or (bs.user.alias_active and email.lower() != alias_email) or (dialect >= 16 and pop_id is not None and bs_pop_id.lower() != normalize_pop_id(pop_id).lower()):
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		
		chat = self.backend.chat_create()
		
		try:
			if pop_id is not None:
				pop_id = normalize_pop_id(pop_id)
			cs = chat.join('msn', bs, ChatEventHandler(self), pop_id = pop_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
		self.dialect = dialect
		self.bs = bs
		self.cs = cs
		if self.counter_task is not None and not self.counter_task.cancelled():
			self.counter_task.cancel()
			self.counter_task = None
		self.send_reply('USR', trid, 'OK', arg, cs.user.status.name or cs.user.email)
	
	def _m_ans(self, trid: Optional[str], arg: Optional[str], token: Optional[str], sessid: Optional[int], *args: Any) -> None:
		#>>> ANS trid email@example.com token sessionid (MSNP < 16)
		#>>> ANS trid email@example.com;{00000000-0000-0000-0000-000000000000} token sessionid (MSNP >= 16)
		self.auth_sent = True
		if trid is None or arg is None or token is None or sessid is None or len(args) > 0:
			self.close()
			return
		
		(email, pop_id) = decode_email_pop(arg)
		
		data = self.backend.auth_service.get_token('sb/cal', token) # type: Optional[Tuple[BackendSession, int, Chat]]
		if data is None:
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		expiry = self.backend.auth_service.get_token_expiry('sb/cal', token) or 0
		self.backend.auth_service.pop_token('sb/cal', token)
		if round(time.time() - expiry) >= 60:
			self.close()
			return
		
		(bs, dialect, chat) = data
		bs_pop_id = bs.front_data.get('msn_pop_id') or ''
		alias_email = '{}@crosstalk.im'.format(bs.user.username).lower()
		valid_emails = (bs.user.email.lower(), alias_email)
		if email.lower() not in valid_emails or (bs.user.alias_active and email.lower() != alias_email) or (dialect >= 16 and pop_id is not None and bs_pop_id.lower() != normalize_pop_id(pop_id).lower()):
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		
		if chat is None or sessid != chat.ids.get('main'):
			self.close()
			return
		
		try:
			if pop_id is not None:
				pop_id = normalize_pop_id(pop_id)
			cs = chat.join('msn', bs, ChatEventHandler(self), pop_id = pop_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, dialect), trid)
			return
		self.dialect = dialect
		self.bs = bs
		self.cs = cs
		if self.counter_task and not self.counter_task.cancelled():
			self.counter_task.cancel()
			self.counter_task = None
		
		roster_chatsessions = list(chat.get_roster_single()) # type: List[ChatSession]
		
		if dialect >= 16:
			l = 0
			tmp = [] # type: List[ChatSession]
			seen_cses = set() # type: Set[ChatSession]
			for other_cs_primary in roster_chatsessions:
				if other_cs_primary in seen_cses or other_cs_primary is self.cs: continue
				for other_cs in chat.get_roster():
					if other_cs in seen_cses: continue
					if other_cs.user.email == other_cs_primary.user.email and not other_cs.primary_pop:
						seen_cses.add(other_cs)
						tmp.append(other_cs)
						l += 1
				seen_cses.add(other_cs_primary)
				tmp.append(other_cs_primary)
				if other_cs_primary.bs.front_data.get('msn_pop_id') is not None:
					l += 2
				else:
					l += 1
			i = 1
			for other_cs in tmp:
				other_user = other_cs.user
				other_user_display_email = self.backend.util_get_display_email(other_user)
				capabilities = encode_capabilities_capabilitiesex(*get_session_capabilities(other_cs.bs, dialect))
				self.send_reply(
					'IRO', trid, i, l, encode_email_pop(other_user_display_email, other_cs.bs.front_data.get('msn_pop_id')),
					_friendly_name(self.backend, other_user), capabilities,
				)
				if other_cs.primary_pop and other_cs.bs.front_data.get('msn_pop_id') is not None:
					i += 1
					self.send_reply('IRO', trid, i, l, other_user_display_email, _friendly_name(self.backend, other_user), capabilities)
				i += 1
		else:
			roster_one_per_user = [] # type: List[ChatSession]
			seen_users = { self.cs.user } # type: Set[User]
			for other_cs in roster_chatsessions:
				if other_cs.user in seen_users:
					continue
				roster_one_per_user.append(other_cs)
			l = len(roster_one_per_user)
			for i, other_cs in enumerate(roster_one_per_user):
				other_user = other_cs.user
				extra = () # type: Tuple[Any, ...]
				if dialect >= 12:
					# Capability flags in IRO were technically introduced by MSNP13, but there are MSNP12 logs that show that they
					# had been introduced in that protocol version by then
					extra = (get_session_capabilities(other_cs.bs, dialect)[0],)
				self.send_reply('IRO', trid, i + 1, l, self.backend.util_get_display_email(other_user), _friendly_name(self.backend, other_user), *extra)
						
		self.send_reply('ANS', trid, 'OK')
		
		chat.send_participant_joined(cs)
	
	# State = Live
	
	def _m_cal(self, trid: str, invitee_email: str) -> None:
		#>>> CAL trid email@example.com
		cs = self.cs
		assert cs is not None
		
		bs = self.bs
		assert bs is not None
		
		if '@' not in invitee_email:
			self.send_reply(Err.InvalidUser2, trid)
			return
		
		invitee_uuid = self.backend.util_get_uuid_from_email(invitee_email)
		if invitee_uuid is None:
			self.send_reply(Err.PrincipalNotOnline, trid)
			return
		
		chat = cs.chat
		try:
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			invitee = self.backend._load_user_record(invitee_uuid)
			if invitee is None:
				return
			if invitee_email != bs.user.email:
				ctc = detail.contacts.get(invitee_uuid)
				if ctc is not None:
					if ctc.status.is_offlineish():
						raise error.ContactNotOnline()
				else:
					if invitee.status.is_offlineish():
						raise error.ContactNotOnline()
			
			cs.invite(invitee)
		except Exception as ex:
			# WLM 2009 sends a `CAL` with the invitee being the owner when a SB session is first initiated. If there are no other
			# PoPs of the owner, send a `JOI` for now to fool the client.
			chat_roster_single = list(chat.get_roster_single())
			if (
				isinstance(ex, error.ContactAlreadyOnContactList) and invitee_email == bs.user.email
				and len(chat_roster_single) == 1 and chat_roster_single[0] is cs and self.dialect >= 16
			):
				self.send_reply('CAL', trid, 'RINGING', chat.ids['main'])
				cs.evt.on_participant_joined(cs, True, False)
				return
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
		else:
			self.send_reply('CAL', trid, 'RINGING', chat.ids['main'])
			if self.dialect >= 16 and invitee_email == bs.user.email:
				cs.evt.on_participant_joined(cs, True, False)
	
	def _m_msg(self, trid: str, ack: str, data: bytes) -> None:
		#>>> MSG trid [UNAD] len
		bs = self.bs
		assert bs is not None
		cs = self.cs
		assert cs is not None
		
		if ack not in ('U','N','A','D','S') or len(data) > 1664:
			self.close()
			return
		
		chunks = self._collect_chunk(data)
		if chunks is None:
			if ack in ('A', 'D'):
				self.send_reply('ACK', trid)
			return
		
		try:
			message = messagedata_from_msnp(cs.user, bs.front_data.get('msn_pop_id'), ack, b''.join(_chunk_body(chunk, i) for i, chunk in enumerate(chunks)) if len(chunks) > 1 else data)
		except error.SpecialMessageNotSentWithDType:
			self.close()
			return
		if len(chunks) > 1:
			message.front_cache['msnp_chunks'] = chunks
		
		if message.type is MessageType.MSNP2P:
			p2pv2 = sb_p2p_is_v2(message.front_cache.get('msn_p2p_dest'))
			message.front_cache['msn_p2pv2'] = p2pv2
			packet = neutralize_direct_p2p(cast(bytes, message.text), p2pv2)
			if packet != message.text:
				i = data.index(b'\r\n\r\n') + 4
				message.text = cast(Any, packet)
				message.front_cache['msnp'] = data[:i] + packet
		
		(p2p_dest, p2p_dest_pop_id) = decode_email_pop(message.front_cache.get('msn_p2p_dest') or '')
		if p2p_dest_pop_id is not None:
			p2p_dest_uuid = self.backend.util_get_uuid_from_email(p2p_dest)
			if p2p_dest_uuid is not None:
				message.text = translate_p2pv2_ack(message.text, get_p2p_state(cs.chat.front_data, p2p_dest_uuid, bs.user.uuid))
		delivered = cs.send_message_to_everyone(message)
		
		# TODO: Implement ACK/NAK
		if ack == 'U':
			return
		any_failed = not delivered
		if any_failed: # ADN
			self.send_reply('NAK', trid)
		elif ack != 'N': # AD
			self.send_reply('ACK', trid)
	
	def _collect_chunk(self, data: bytes) -> Optional[List[bytes]]:
		try:
			i = data.index(b'\r\n\r\n') + 4
			headers = Parser().parsestr(data[:i].decode('utf-8'))
		except (ValueError, UnicodeDecodeError):
			return [data]
		message_id = headers.get('Message-ID')
		if message_id is None or (headers.get('Chunks') is None and headers.get('Chunk') is None):
			return [data]
		pending = self.chunks.setdefault(str(message_id), { 'total': 0, 'parts': {} })
		try:
			if headers.get('Chunks') is not None:
				pending['total'] = int(str(headers.get('Chunks')))
				pending['parts'][0] = data
			else:
				pending['parts'][int(str(headers.get('Chunk')))] = data
		except ValueError:
			del self.chunks[str(message_id)]
			return [data]
		total = pending['total']
		if not total or len(pending['parts']) < total or total > MAX_CHUNKS:
			if total > MAX_CHUNKS or len(self.chunks) > MAX_CHUNKED_MESSAGES:
				del self.chunks[str(message_id)]
			return None
		del self.chunks[str(message_id)]
		return [pending['parts'][n] for n in range(total) if n in pending['parts']]
	
	async def _conn_auth_limit_counter(self) -> None:
		counter = 0
		
		while counter < 1:
			await asyncio.sleep(60)
			counter += 1
		
		if counter == 1:
			if not self.auth_sent:
				self.close()

class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('ctrl',)
	
	ctrl: MSNPCtrlSB
	
	def __init__(self, ctrl: MSNPCtrlSB) -> None:
		self.ctrl = ctrl
	
	def on_participant_joined(self, cs_other: ChatSession, first_pop: bool, initial_join: bool) -> None:
		ctrl = self.ctrl
		bs = ctrl.bs
		assert bs is not None
		cs = self.cs
		
		if (not first_pop or cs_other.user is cs.user) and ctrl.dialect < 16: return
		
		user = cs_other.user
		user_display_email = ctrl.backend.util_get_display_email(user)
		
		pop_id_other = cs_other.bs.front_data.get('msn_pop_id')
		if (
			(
				pop_id_other is not None
				and (pop_id_other != cs.bs.front_data.get('msn_pop_id') or cs_other.user is not cs.user)
			)
			and ctrl.dialect >= 16
		):
			email = '{};{}'.format(user_display_email, '{' + pop_id_other + '}')
		else:
			email = user_display_email
		
		# Capability flags in JOI were technically introduced by MSNP13, but there are MSNP12 logs that show that they
		# had been introduced in that protocol version by then
		if 12 <= ctrl.dialect <= 15:
			extra = (get_session_capabilities(cs_other.bs, ctrl.dialect)[0],) # type: Tuple[Any, ...]
		elif ctrl.dialect >= 16:
			extra = (encode_capabilities_capabilitiesex(*get_session_capabilities(cs_other.bs, ctrl.dialect)),)
		else:
			extra = ()
		ctrl.send_reply('JOI', email, _friendly_name(ctrl.backend, user), *extra)
		if cs_other.user is not cs.user and pop_id_other is not None and first_pop and ctrl.dialect >= 16:
			ctrl.send_reply('JOI', user_display_email, _friendly_name(ctrl.backend, user), *extra)
	
	def on_participant_left(self, cs_other: ChatSession, last_pop: bool) -> None:
		ctrl = self.ctrl
		if not last_pop and ctrl.dialect < 16: return
		user_display_email = ctrl.backend.util_get_display_email(cs_other.user)
		pop_id_other = cs_other.bs.front_data.get('msn_pop_id')
		if pop_id_other is not None and ctrl.dialect >= 16:
			email = '{};{}'.format(user_display_email, '{' + pop_id_other + '}')
		else:
			email = user_display_email
		self.ctrl.send_reply('BYE', email)
		if last_pop and pop_id_other is not None and ctrl.dialect >= 16:
			self.ctrl.send_reply('BYE', user_display_email)
	
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
	
	def on_message(self, data: MessageData) -> None:
		if data.type in (MessageType.TypingDone, MessageType.Ignored): return
		if data.type is MessageType.MSNP2P and 'msn_p2p' in data.front_cache:
			self._send_p2p(data)
			return
		ctrl = self.ctrl
		sender_email = ctrl.backend.util_get_display_email(data.sender)
		if 'msnp_chunks' in data.front_cache:
			for chunk in data.front_cache['msnp_chunks']:
				ctrl.send_reply('MSG', sender_email, data.sender.status.name, chunk)
			return
		payload = messagedata_to_msnp(data, sender_email = sender_email)
		if payload is None: return
		for chunk in chunk_msnp(payload):
			ctrl.send_reply('MSG', sender_email, data.sender.status.name, chunk)
	
	def _send_p2p(self, data: MessageData) -> None:
		ctrl = self.ctrl
		bs = ctrl.bs
		assert bs is not None
		
		pop_id = bs.front_data.get('msn_pop_id')
		dest_pop_id = data.front_cache.get('msn_p2p_dest_pop_id')
		if is_null_epid(dest_pop_id): dest_pop_id = None
		if dest_pop_id is not None and pop_id is not None and normalize_pop_id(dest_pop_id).lower() != pop_id.lower(): return
		
		sender_email = ctrl.backend.util_get_display_email(data.sender)
		user_email = ctrl.backend.util_get_display_email(bs.user)
		dest_email = data.front_cache.get('msn_p2p_dest_email')
		if dest_email is not None and dest_email.lower() not in (user_email.lower(), bs.user.email.lower()): return
		p2pv2 = data.front_cache.get('msn_p2pv2')
		if p2pv2 is None:
			p2pv2 = (ctrl.dialect >= 16 and bool(get_session_capabilities(bs, ctrl.dialect)[1] & CAPABILITIESEX_P2PV2))
		if p2pv2 and (ctrl.dialect < 16 or pop_id is None): return
		if p2pv2:
			dest = encode_email_pop(user_email, dest_pop_id or pop_id)
			src = encode_email_pop(sender_email, data.sender_pop_id) # type: Optional[str]
		else:
			dest = user_email
			src = None
		
		state = get_p2p_state(self.cs.chat.front_data, data.sender.uuid, bs.user.uuid)
		if data.front_cache.get('msn_sdg_pipe'):
			state['pipe'] = data.front_cache['msn_sdg_pipe']
		state['pop_id'] = data.sender_pop_id
		for packet in data.front_cache['msn_p2p']:
			for payload in sb_p2p_messages(packet, dest, src, p2pv2, state):
				ctrl.send_reply('MSG', sender_email, data.sender.status.name, payload)
	
	def on_close(self) -> None:
		self.ctrl.close()

def messagedata_from_msnp(sender: User, sender_pop_id: Optional[str], ack: str, data: bytes) -> MessageData:
	# TODO: Implement these `Content-Type`s:
	# voice:
	# b'MIME-Version: 1.0\r\nContent-Type: text/x-msmsgsinvite; charset=UTF-8\r\n\r\nInvitation-Command: CANCEL\r\n
	# Cancel-Code: TIMEOUT\r\nInvitation-Cookie: 126868552\r\nSession-ID: {CE64F989-2AAD-44C4-A780-2C55A812B0B6}\r\n
	# Conn-Type: Firewall\r\nSip-Capability: 1\r\n\r\n'
	# xfer:
	# 	b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Gt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00\xb2\x04\x00
	# 	\x00\x00\x00\x00\x00wn\xc5\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00INVITE MSNMSGR:t2h@hotmail.com MSNSLP/1.0\r\n
	# 	To: <msnmsgr:t2h@hotmail.com>\r\nFrom: <msnmsgr:t1h@hotmail.com>\r\nVia: MSNSLP/1.0/TLP ;
	# 	branch={CDE28DAF-B67C-4B2D-8186-D3F46EEF0916}\r\nCSeq: 0 \r\nCall-ID: {F87327A8-741F-4FEF-AB63-45D06F51A0C2}\r\n
	# 	Max-Forwards: 0\r\nContent-Type: application/x-msnmsgr-sessionreqbody\r\nContent-Length: 948\r\n\r\n
	# 	EUF-GUID: {5D3E02AB-6190-11D3-BBBB-00C04F795683}\r\nSessionID: 180646677\r\nAppID: 2\r\n
	# 	Context: fgIAAAMAAAAAAAAAAAAAAAEAAABhAC4AdAB4AHQAA...AAAAAAAAA/////wAAAAAAAAAAAAAAAAAAA\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Gt\xc4\n\xb2\x04\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00H\x00\x00\x00
	# 	\x00\x00\x00\x00wn\xc5\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	# 	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n\x00\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t1h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Wt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
	# 	\x02\x00\x00\x00Gt\xc4\nwn\xc5\n\xfa\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	# xfer decline:
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t1h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Xt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00
	# 	\x00\x00\x00N\x0b\xc7\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00MSNSLP/1.0 603 Decline\r\n
	# 	To: <msnmsgr:t1h@hotmail.com>\r\nFrom: <msnmsgr:t2h@hotmail.com>\r\nVia: MSNSLP/1.0/TLP ;
	# 	branch={CDE28DAF-B67C-4B2D-8186-D3F46EEF0916}\r\nCSeq: 1 \r\nCall-ID: {F87327A8-741F-4FEF-AB63-45D06F51A0C2}\r\n
	# 	Max-Forwards: 0\r\nContent-Type: application/x-msnmsgr-sessionreqbody\r\nContent-Length: 25\r\n\r\n
	# 	SessionID: 180646677\r\n\r\n\x00\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Ht\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
	# 	\x02\x00\x00\x00Xt\xc4\nN\x0b\xc7\nK\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	# etc.
	
	try:
		i = data.index(b'\r\n\r\n') + 4
		headers = Parser().parsestr(data[:i].decode('utf-8'))
		body_raw = data[i:]
	except Exception:
		message = MessageData(sender = sender, sender_pop_id = sender_pop_id, type = MessageType.Chat, text = UNSUPPORTED_MESSAGE_TEXT)
		message.front_cache['msnp'] = data
		return message
	
	front_cache: dict[str, Any] = {}
	text: Any = body_raw
	content_type = headers.get_content_type()
	if content_type == 'text/x-msmsgscontrol':
		type = MessageType.Typing
		text = ''
	elif content_type == 'text/x-msnmsgr-datacast':
		body = body_raw.decode('utf-8', 'replace')
		fields = _parse_body_fields(body)
		id = (fields.get('ID') or '').strip()
		if id == '1':
			type = MessageType.Nudge
			text = ''
		elif id in DATACAST_MSNOBJ:
			type = MessageType.Other
			text = (fields.get('Data') or '').strip()
		elif id == DATACAST_ACTION:
			type = MessageType.Chat
			front_cache['msn_action'] = (fields.get('Data') or '').strip()
			text = '* {} {}'.format(sender.status.name or sender.email, front_cache['msn_action'])
		else:
			type = MessageType.Chat
			text = UNSUPPORTED_MESSAGE_TEXT
	elif content_type == 'application/x-msnmsgrp2p':
		if ack != 'D':
			raise error.SpecialMessageNotSentWithDType()
		type = MessageType.MSNP2P
	elif content_type == 'text/x-msmsgsinvite':
		type = MessageType.MSNP2PInvite
	elif content_type in ('application/x-ms-ink', 'image/gif'):
		type = MessageType.Ink
	elif content_type in ('text/x-mms-emoticon', 'text/x-mms-animemoticon'):
		type = MessageType.Emoticon
	elif content_type == 'text/plain':
		type = MessageType.Chat
		text = body_raw.decode('utf-8', 'replace')
		im_format = headers.get('X-MMS-IM-Format')
		if im_format is not None:
			front_cache['msn_im_format'] = str(im_format)
	else:
		type = MessageType.Other

	message = MessageData(sender = sender, sender_pop_id = sender_pop_id, type = type, text = text)
	message.front_cache['msnp'] = data
	message.front_cache.update(front_cache)
	if type is MessageType.MSNP2P:
		message.front_cache['msn_p2p_dest'] = str(headers.get('P2P-Dest') or '')
	elif type is MessageType.Emoticon:
		message.front_cache['msn_emoticon'] = content_type
	elif type is MessageType.Other and content_type == 'text/x-msnmsgr-datacast':
		message.front_cache['msn_datacast'] = id
	elif type is MessageType.Chat and 'msn_action' in front_cache:
		message.front_cache['msn_datacast'] = DATACAST_ACTION
	return message

def messagedata_to_msnp(data: MessageData, *, sender_email: Optional[str] = None) -> Optional[bytes]:
	if 'msnp' not in data.front_cache:
		if data.type is MessageType.Typing:
			s = F'MIME-Version: 1.0\r\nContent-Type: text/x-msmsgscontrol\r\nTypingUser: {sender_email or data.sender.email}\r\n\r\n\r\n'
		elif data.type is MessageType.Nudge:
			s = 'MIME-Version: 1.0\r\nContent-Type: text/x-msnmsgr-datacast\r\n\r\nID: 1\r\n\r\n'
		elif data.type is MessageType.Other and 'msn_datacast' in data.front_cache:
			s = 'MIME-Version: 1.0\r\nContent-Type: text/x-msnmsgr-datacast\r\n\r\nID: {}\r\nData: {}\r\n\r\n'.format(data.front_cache['msn_datacast'], data.text)
		elif data.type is MessageType.Emoticon:
			emoticons = (data.text.decode('utf-8', 'replace') if isinstance(data.text, bytes) else (data.text or ''))
			s = 'MIME-Version: 1.0\r\nContent-Type: {}\r\n\r\n'.format(data.front_cache.get('msn_emoticon') or 'text/x-mms-emoticon') + emoticons
		elif data.type is MessageType.Chat and 'msn_action' in data.front_cache:
			s = 'MIME-Version: 1.0\r\nContent-Type: text/x-msnmsgr-datacast\r\n\r\nID: {}\r\nData: {}\r\n\r\n'.format(DATACAST_ACTION, data.front_cache['msn_action'])
		elif data.type is MessageType.Chat:
			im_format = data.front_cache.get('msn_im_format')
			s = 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n{}\r\n'.format(
				'X-MMS-IM-Format: {}\r\n'.format(im_format) if im_format else '',
			) + (data.text or '')
		else:
			return None
		data.front_cache['msnp'] = s.encode('utf-8')
	return data.front_cache['msnp']

def chunk_msnp(payload: bytes) -> List[bytes]:
	if len(payload) <= SB_MSG_LIMIT:
		return [payload]
	i = payload.index(b'\r\n\r\n') + 4
	headers = payload[:i - 2]
	body = payload[i:]
	message_id = '{' + gen_uuid().upper() + '}'
	room = SB_MSG_LIMIT - len(headers) - 80
	parts = [body[n:n + room] for n in range(0, len(body), room)]
	chunks = [headers + 'Message-ID: {}\r\nChunks: {}\r\n\r\n'.format(message_id, len(parts)).encode('ascii') + parts[0]]
	content_type = (b'Content-Type: ' + headers.split(b'Content-Type: ', 1)[1].split(b'\r\n', 1)[0] + b'\r\n') if b'Content-Type: ' in headers else b''
	for n, part in enumerate(parts[1:], 1):
		chunks.append(b'MIME-Version: 1.0\r\n' + content_type + 'Message-ID: {}\r\nChunk: {}\r\n\r\n'.format(message_id, n).encode('ascii') + part)
	return chunks

def _chunk_body(chunk: bytes, n: int) -> bytes:
	if n == 0: return chunk
	try:
		return chunk[chunk.index(b'\r\n\r\n') + 4:]
	except ValueError:
		return b''

def _parse_body_fields(body: str) -> Dict[str, str]:
	fields = {} # type: Dict[str, str]
	for line in body.split('\r\n'):
		if ':' not in line: continue
		key, value = line.split(':', 1)
		fields.setdefault(key.strip(), value.strip())
	return fields

SB_MSG_LIMIT = 1664
MAX_CHUNKS = 64
MAX_CHUNKED_MESSAGES = 16
	
def _encode_participant_capabilities(cs_other: ChatSession, dialect: int) -> int | str:
	if dialect < 16:
		return get_session_capabilities(cs_other.bs, dialect)[0]
	return encode_capabilities_capabilitiesex(*get_session_capabilities(cs_other.bs, dialect))

def _friendly_name(backend: Backend, user: User) -> str:
	return user.status.name or backend.util_get_display_email(user)