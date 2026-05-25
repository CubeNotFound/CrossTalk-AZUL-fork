import time, struct
import re
from html import unescape

from enum import IntEnum

from util.misc import Logger
from core.models import MessageData, MessageType, User

from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import find_tlv, unmarshal_tlvs, marshal_tlvs, TLV


class ICBMChannel(IntEnum):
	AOLIM	   = 0x0001
	Rendezvous  = 0x0002
	Mime		= 0x0003
	ICQ		 = 0x0004
	CoBrowser   = 0x0005

class ICBMEvent(IntEnum):
	Finished = 0x0000 
	Typed	= 0x0001
	Typing   = 0x0002
	Closed   = 0x000F

@Foodgroup(0x0004)
class ICBMFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def add_paramenters(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ICBM__ADD_PARAMENTERS (not implemented)')
		self.logger.info('[Client]', message.data.hex())

	@Subgroup(0x0004)
	def parameter_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ICBM__PARAMENTER_QUERY')

		response_msg = SNACMessage(0x0004, 0x0005)

		# Response from NINA's servers:
		# ==
		# 0000   2a 02 00 0a 00 1a 00 04 00 05 00 00 00 00 00 04   *...............
		#		[FLAP Header....] [SNAC Header................]
		# 0010   00 05 00 00 00 03 02 00 03 84 03 e7 00 00 03 e8   ................
		#
		# The response data are not TLVs and are instead WORD/DWORDs so I cannot fit
		# the names below the hex data.  See https://ninawiki.preloading.dev/wiki/Protocols/OSCAR/SNAC/ICBM_PARAMETER_REPLY and
		# https://ninawiki.preloading.dev/wiki/Protocols/OSCAR/SNAC/ICBM_ADD_PARAMETERS for more information.
		response_msg.write_u16(5)		 # maxSlots
		response_msg.write_u32(0x00003)   # icbmFlags (default)
		response_msg.write_u16(512)	   # maxIncomingICBMLen
		response_msg.write_u16(999)	   # maxSourceEvil
		response_msg.write_u16(999)	   # maxDestinationEvil
		response_msg.write_u32(1000)	  # minInterICBMInterval

		self.logger.info('[Server] ICBM__PARAMENTER_REPLY')
		client.send_snac(response_msg)

	@Subgroup(0x0006)
	def channel_msg_tohost(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		cookie = message.read_bytes(8)
		channel = message.read_u16()
		receiver = message.read_string_u8()
		tlvs = unmarshal_tlvs(message.data)

		self.logger.info('[Client] ICBM__CHANNEL_MSG_TOHOST')
		self.logger.info('[Client] Cookie:', cookie)
		self.logger.info('[Client] Channel:', hex(channel))
		self.logger.info('[Client] Message receiver:', receiver)

		for tlv in tlvs:
			self.logger.info('[Client] TLV', hex(tlv.type), '-', tlv.data)

		if channel != ICBMChannel.AOLIM:
			self.logger.info('[Client] Unsupported channel:', hex(channel))
			return

		im_data_tlv = find_tlv(tlvs, 0x0002)
		if im_data_tlv is None:
			self.logger.info('[Client] Missing IM data TLV')
			return

		im_tlvs = unmarshal_tlvs(im_data_tlv.data)
		im_text_tlv = find_tlv(im_tlvs, 0x0101)
		if im_text_tlv is None:
			self.logger.info('[Client] Missing IM text TLV inside IM data')
			return

		text = im_text_tlv.data[4:].decode('ascii', errors='replace')
		self.logger.info('[Client] Message text:', text)

		receiver_uuid = context.backend.util_get_uuid_from_username(receiver)
		if receiver_uuid is None:
			self.logger.info('[Client] Unknown receiver:', receiver)
			return

		try:
			cs, evt = client.ctrl._get_private_chat_with(receiver_uuid)
		except Exception as ex:
			self.logger.info('[Client] Could not create private chat:', str(ex))
			return

		ack = SNACMessage(0x0004, 0x000C)
		ack.request_id = message.request_id
		ack.write_bytes(cookie)
		ack.write_u16(channel)
		ack.write_string_u8(receiver)
		self.logger.info('[Server] ICBM__HOST_ACK')
		client.send_snac(ack)

		md = MessageData(sender=context.user, type=MessageType.Chat, text=strip_html_tags(text))
		md.front_cache['icbm_cookie'] = cookie
		md.front_cache['icbm_html'] = text
		evt._send_when_user_joins(receiver_uuid, md)

	@Subgroup(0x0014)
	def client_event(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		cookie   = message.read_bytes(8)
		channel  = message.read_u16()
		receiver = message.read_string_u8()
		event	= message.read_u16()

		self.logger.info('[Client] ICBM__CLIENT_EVENT')
		self.logger.info('[Client] Receiver:', receiver, '| Event:', hex(event))

		if channel != ICBMChannel.AOLIM:
			self.logger.info('[Client] Unsupported channel:', hex(channel))
			return

		receiver_uuid = context.backend.util_get_uuid_from_username(receiver)
		if receiver_uuid is None:
			self.logger.info('[Client] Unknown receiver:', receiver)
			return

		# map OSCAR events to respective MessageTypes
		if event == ICBMEvent.Typing:
			msg_type = MessageType.Typing
		elif event in (ICBMEvent.Finished, ICBMEvent.Typed, ICBMEvent.Closed):
			msg_type = MessageType.TypingDone
		else:
			self.logger.info('[Client] Unknown event type:', hex(event))
			return

		try:
			cs, evt = client.ctrl._get_private_chat_with(receiver_uuid)
		except Exception as ex:
			self.logger.info('[Client] Could not get private chat:', str(ex))
			return

		md = MessageData(sender=context.user, type=msg_type, text='')
		md.front_cache['icbm_cookie'] = cookie

		if evt._user_in_chat(receiver_uuid):
			cs.send_message_to_user(receiver_uuid, md)

def strip_html_tags(text: str) -> str:
	return unescape(re.compile(r'<[^>]+>').sub('', text))

def messagedata_to_icbm(cookie: bytes, data: MessageData, user: User) -> SNACMessage:
	#   cookie		 - 8 bytes, chat sess cookie
	#   channel		- u16, 0x0001 for plain text IM
	#   sender		 - string08 (u8 length prefix), sender's screen name
	#   warning level  - u16, always 0
	#   userinfo TLVs  - write_tlv_block (count-prefixed) containing:
	#					  TLV(0x0001) user class
	#					  TLV(0x0003) account signon time (unix time_t)
	#					  TLV(0x000F) session length in seconds
	#					  TLV(0x0005) account creation time (unix time_t)
	#   TLV(0x0002)	- IM data block containing nested TLVs:
	#					  TLV(0x0501) capabilities (1 byte = 0x01 for plain text)
	#					  TLV(0x0101) text: u16 encoding + u16 language + bytes
	sender = data.sender
	text = data.front_cache.get('icbm_html', data.text or '')

	date_created_unix = int(time.mktime(sender.date_created.timetuple()))
	date_login_unix = int(time.mktime(sender.date_login.timetuple())) if sender.date_login else 0

	msg = SNACMessage(0x0004, 0x0007)
	msg.write_bytes(cookie)
	msg.write_u16(ICBMChannel.AOLIM)
	msg.write_string_u8(sender.username)
	msg.write_u16(0)  # warning level

	# count-prefixed userinfo TLV block
	# usually would include TLV(0x001D) (BART info), but we don't support that yet
	msg.write_tlv_block([
		TLV(0x0001, struct.pack('>H', 0x0008)),			# user class
		TLV(0x0003, struct.pack('>L', date_login_unix)),   # account signon time
		TLV(0x000F, struct.pack('>L', 0)),				 # session length
		TLV(0x0005, struct.pack('>L', date_created_unix)), # account creation time
	])

	im_text = (text or '').encode('ascii', errors='replace')

	# IM data: TLV(0x0002) wrapping nested capability + text TLVs
	im_data = marshal_tlvs([
		TLV(0x0501, b'\x01'),							 # capabilities: plain text (1 byte)
		TLV(0x0101, struct.pack('>HH', 0, 0) + im_text), # encoding=ASCII, language=0, text
	])
	msg.write_tlv(TLV(0x0002, im_data))

	return msg

def messagedata_to_icbm_event(data: MessageData, receiver: User) -> SNACMessage:

	if data.type is MessageType.Typing:
		event = ICBMEvent.Typing
	else:
		event = ICBMEvent.Finished

	msg = SNACMessage(0x0004, 0x0014)
	msg.write_bytes(b'\x00' * 8)
	msg.write_u16(ICBMChannel.AOLIM)
	msg.write_string_u8(data.sender.username)
	msg.write_u16(event)
	return msg