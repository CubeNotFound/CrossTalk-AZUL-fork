import struct

from util.misc import Logger

from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV

@Foodgroup(0x0002)
class LocateFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def client_versions(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] LOCATE__RIGHTS_QUERY')

		response_msg = SNACMessage(0x0002, 0x0003)

		# Response from NINA's servers:
		# ==
		# 0000   2a 02 00 07 00 28 00 02 00 03 00 00 00 00 00 02   *....(..........
		#		[FLAP Header....] [SNAC Header................]
		# 0010   00 01 00 02 10 00 00 02 00 02 00 80 00 03 00 02   ................
		#		[TLV 0x0001.....] [TLV 0x0002.....] [TLV 0x0003
		# 0020   00 1e 00 04 00 02 10 00 00 05 00 02 00 80		 ..............
		#		....] [TLV 0x0004.....] [TLV 0x0005.....]
		#
		# TLV 0x0001: client max profile len (data is 0x1000 = 256)
		# TLV 0x0002: max capabilities (CLSIDs) (data is 0x0080 = 128)
		# TLV 0x0003: unknown (data is 0x001E = 30)
		# TLV 0x0004: unknown (data is 0x1000 = 256)
		# TLV 0x0005: unknown (data is 0x0080 = 128)
		#
		response_msg.write_tlvs([
			TLV(0x0001, struct.pack('>H', 4096)),	# client max profile len
			TLV(0x0002, struct.pack('>H', 128)),	 # max capabilities (CLSIDs)
			TLV(0x0003, struct.pack('>H', 0x001E)),  # unknown
			TLV(0x0004, struct.pack('>H', 0x1000)),  # unknown
			TLV(0x0005, struct.pack('>H', 0x0080))   # unknown
		])

		self.logger.info('[Server] LOCATE__RIGHTS_REPLY')
		client.send_snac(response_msg)

	@Subgroup(0x0004)
	def set_info(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] LOCATE__SET_INFO (not implemented)')
		self.logger.info('[Client]', message.data.hex())

	@Subgroup(0x000B)
	def get_dir_info(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] LOCATE__GET_DIR_INFO')

		screen_name = message.read_string_u8()
		self.logger.info('[Client] Getting info for:', screen_name)

		# Response from NINA's servers:
		# ==
		# 0000   2A 02 00 0F 00 1A 00 02 00 0C 00 00 00 01 00 0B   *...............
		#		[FLAP Header....] [SNAC Header................]
		# 0010   00 01 00 01 00 1C 00 08 75 73 2D 61 73 63 69 69   ........us-ascii
		#		^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
		#
		# I have no idea what any of the values in the SNAC body mean, and the lack of documentation on NINA's wiki
		# don't help either: https://wiki.nina.chat/wiki/Protocols/OSCAR/SNAC/LOCATE_GET_DIR_REPLY
		response_msg = SNACMessage(0x0002, 0x000C)
		response_msg.write_u16(0x0001)
		response_msg.write_u16(0x0001)
		response_msg.write_u16(0x001C)
		response_msg.write_string_u16('us-ascii')

		self.logger.info('[Server] LOCATE__GET_DIR_REPLY')
		client.send_snac(response_msg)
