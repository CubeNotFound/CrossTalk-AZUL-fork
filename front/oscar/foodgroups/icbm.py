import time, struct

from enum import IntEnum

from util.misc import Logger
from core.models import MessageData, MessageType, User

from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import unmarshal_tlvs, marshal_tlvs, TLV

class ICBMChannel(IntEnum):
	AOLIM = 0x0001,
	Rendezvous = 0x0002,
	Mime = 0x0003,
	ICQ = 0x0004,
	CoBrowser = 0x0005

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
		# the names below the hex data.  See https://wiki.nina.chat/wiki/Protocols/OSCAR/SNAC/ICBM_PARAMETER_REPLY and
		# https://wiki.nina.chat/wiki/Protocols/OSCAR/SNAC/ICBM_ADD_PARAMETERS for more information.
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
		# Client packet:
		# ===
		# 0000  44 42 38 35 30 35 00 00 00 01 04 74 65 73 74 00  DB8505.....test.
		# 0010  02 00 3F 05 01 00 03 01 01 02 01 01 00 34 00 00  ..?..........4..
		# 0020  00 00 3C 48 54 4D 4C 3E 3C 42 4F 44 59 20 42 47  ..<HTML><BODY BG
		# 0030  43 4F 4C 4F 52 3D 22 23 66 66 66 66 66 66 22 3E  COLOR="#ffffff">
		# 0040  74 65 73 74 3C 2F 42 4F 44 59 3E 3C 2F 48 54 4D  test</BODY></HTM
		# 0050  4C 3E 00 03 00 00								L>....
		#
		# [OSCAR] (ID: c245) [Client] ICBM__CHANNEL_MSG_TOHOST
		# [OSCAR] (ID: c245) [Client] Cookie: b'E67FA1\x00\x00'
		# [OSCAR] (ID: c245) [Client] Channel: 0x1
		# [OSCAR] (ID: c245) [Client] Message reciever: test
		# [OSCAR] (ID: c245) [Server] TLV 2 - b'\x05\x01\x00\x03\x01\x01\x02\x01\x01\x006\x00\x00\x00\x00<HTML><BODY BGCOLOR="#ffffff">123456</BODY></HTML>'
		cookie = message.read_bytes(8)
		channel = message.read_u16()
		reciever = message.read_string_u8()
		tlvs = unmarshal_tlvs(message.data)

		self.logger.info('[Client] ICBM__CHANNEL_MSG_TOHOST')
		self.logger.info('[Client] Cookie:', cookie)
		self.logger.info('[Client] Channel:', hex(channel))
		self.logger.info('[Client] Message reciever:', reciever)

		for tlv in tlvs:
			self.logger.info('[Client] TLV', hex(tlv.type), '-', tlv.data)

def messagedata_to_icbm(cookie: bytes, data: MessageData, user: User):
	# THIS SHIT DOESN'T WORK. WHY??? HAS I EVER!?!?!?
	if 'icbm' not in data.front_cache:
		type = data.type
		text = data.text
		sender = data.sender
		if type == MessageType.Chat:
			msg = SNACMessage(0x0004, 0x0007)
			msg.write_bytes(cookie)
			msg.write_u16(ICBMChannel.AOLIM)

			msg.write_string_u8(user.username)
			msg.write_u16(0)
			# we should not hardcode these
			capabilities = [
				"{09461345-4C7F-11D1-8222-444553540000}",   # Direct ICBM
				"{094601FF-4C7F-11D1-8222-444553540000}",   # Smart caps
				"{748F2420-6287-11D1-8222-444553540000}",   # Chat
				"{09461343-4C7F-11D1-8222-444553540000}",   # File transfer
				"{09461341-4C7F-11D1-8222-444553540000}",   # Voice chat
				"{09460104-4C7F-11D1-8222-444553540000}",   # RTC audio
				"{09460105-4C7F-11D1-8222-444553540000}",   # Unknown
				"{09460102-4C7F-11D1-8222-444553540000}",   # Camera
				"{09460103-4C7F-11D1-8222-444553540000}",   # Microphone
				"{09460101-4C7F-11D1-8222-444553540000}",   # RTC video
				"{0946134A-4C7F-11D1-8222-444553540000}",   # Games
				"{09461346-4C7F-11D1-8222-444553540000}"	# BART
			]
			capabilities_bytes = b''

			for capability in capabilities:
				capabilities_bytes += bytes.fromhex(capability
													.lstrip('{')
													.rstrip('}')
													.replace('-', ''))

			date_created_unix = int(time.mktime(user.date_created.timetuple()))
			date_login_unix = int(time.mktime(user.date_login.timetuple())) if user.date_login else 0

			# usually would include 0x001D (BART info), but CrossTalk doesn't support that yet
			pre = marshal_tlvs([
				TLV(0x3000, struct.pack('>L', 0x6719674C)),	  # Unknown
				TLV(0x000D, capabilities_bytes),					# Capability info
				TLV(0x0001, struct.pack('>H', 0x0008)),		  # User class (bitfield)
				TLV(0x0003, struct.pack('>L', date_login_unix)),	# Account signon time (unix time_t)
				TLV(0x000F, struct.pack('>L', 0)),				# Session length
				TLV(0x0005, struct.pack('>L', date_created_unix)),  # Account creation time (unix time_t)
			])


			im_text = data.text.encode('ascii')
			im_tag = 0x0101
			im_len = 2 + 2 + len(im_text)
			imdata_bytes = struct.pack('>HHHH', im_tag, im_len, 0, 0) + im_text

			msg.write_tlv_block([
				*unmarshal_tlvs(pre),
				TLV(0x0501, struct.pack('>L', 1)),
				TLV(0x0101, imdata_bytes)
			])

			return msg

