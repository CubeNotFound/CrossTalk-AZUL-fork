import struct
import time

from core.models import Contact
from util.misc import Logger

from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs


# should be piped to .ctrl.send_snac()
def build_presence_notif(contact: Contact) -> SNACMessage:
	# Packet dump from NINA's servers when a contact goes online:
	# ===
	# 0000   04 64 6b 61 79 00 00 00 07 00 30 00 04 67 19 67   .dkay.....0..g.g
	# 0010   4c 00 0d 00 c0 09 46 13 45 4c 7f 11 d1 82 22 44   L.....F.EL...."D
	# 0020   45 53 54 00 00 09 46 01 ff 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 0030   45 53 54 00 00 74 8f 24 20 62 87 11 d1 82 22 44   EST..t.$ b...."D
	# 0040   45 53 54 00 00 09 46 13 43 4c 7f 11 d1 82 22 44   EST...F.CL...."D
	# 0050   45 53 54 00 00 09 46 13 41 4c 7f 11 d1 82 22 44   EST...F.AL...."D
	# 0060   45 53 54 00 00 09 46 01 04 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 0070   45 53 54 00 00 09 46 01 05 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 0080   45 53 54 00 00 09 46 01 02 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 0090   45 53 54 00 00 09 46 01 03 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 00a0   45 53 54 00 00 09 46 01 01 4c 7f 11 d1 82 22 44   EST...F..L...."D
	# 00b0   45 53 54 00 00 09 46 13 4a 4c 7f 11 d1 82 22 44   EST...F.JL...."D
	# 00c0   45 53 54 00 00 09 46 13 46 4c 7f 11 d1 82 22 44   EST...F.FL...."D
	# 00d0   45 53 54 00 00 00 1d 00 12 00 01 00 05 02 01 d2   EST.............
	# 00e0   04 72 00 00 00 05 02 01 d2 04 72 00 01 00 02 00   .r........r.....
	# 00f0   08 00 03 00 04 67 19 67 4b 00 0f 00 04 00 00 00   .....g.gK.......
	# 0100   02 00 05 00 04 62 7c 7a cd						.....b|z.
	#
	# Buddy length: 0x04
	# Buddy name: dkay
	# TLVs (7):
	#   - TLV 0x3000: unknown (data = 67 19 67 4C)
	#   - TLV 0x000D: capability list
	#   - TLV 0x001D: BART info (data = 00 01 00 05 02 01 D2 04 72 00 00 00 05 02 01 D2 04 72
	#   - TLV 0x0001: user class (data = 00 00 00 08)
	#   - TLV 0x0003: account signon time (value = 1729718091, in UNIX time)
	#   - TLV 0x000F: session length (value = 2)
	#   - TLV 0x0005: account creation time (value = 1652325069, in UNIX time)
	#

	msg = SNACMessage(0x0003, 0x000B if not contact.status.is_offlineish() else 0x000C)

	msg.write_string_u8(contact.head.username)
	msg.write_u16(0)

	if contact.status.is_offlineish():
		msg.write_tlv(TLV(0x0001, struct.pack('>L', 0x0008)))  # User class (bitfield)
	else:
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

		date_created_unix = int(time.mktime(contact.head.date_created.timetuple()))
		date_login_unix = int(time.mktime(contact.head.date_login.timetuple())) if contact.head.date_login else 0

		# usually would include 0x001D (BART info), but since CrossTalk doesn't support
		# it rn I've decided to omit it
		msg.write_tlv_block([
			TLV(0x3000, struct.pack('>L', 0x6719674C)),		 # Unknown
			TLV(0x000D, capabilities_bytes),					# Capability info
			TLV(0x0001, struct.pack('>H', 0x0008)),			 # User class (bitfield)
			TLV(0x0003, struct.pack('>L', date_login_unix)),	# Account signon time (unix time_t)
			TLV(0x000F, struct.pack('>L', 0)),				  # Session length
			TLV(0x0005, struct.pack('>L', date_created_unix)),  # Account creation time (unix time_t)
		])

	print('Subgroup:', hex(msg.subgroup))
	print('TLVs:', unmarshal_tlvs(msg.data))

	return msg


@Foodgroup(0x0003)
class BuddyFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BUDDY_RIGHTS_QUERY')

		response_msg = SNACMessage(0x0003, 0x0003)
		response_msg.write_tlvs([
			TLV(0x0001, struct.pack('>H', 1000)),  # max buddies
			TLV(0x0002, struct.pack('>H', 3000)),  # max watchers
			TLV(0x0004, struct.pack('>H', 160))  # max temp buddies
		])

		self.logger.info('[Server] BUDDY_RIGHTS_REPLY')
		client.send_snac(response_msg)
