import struct

from util.misc import Logger

from .pd import PDHandlers
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV


@Foodgroup(0x0009)
class BOSFoodgroup(PDHandlers):
	logger: Logger

	subgroups = dict(PDHandlers.subgroups)

	@Subgroup(0x0002)
	def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BOS__RIGHTS_QUERY')

		response_msg = SNACMessage(0x0009, 0x0003, 0x0000, message.request_id)
		response_msg.write_tlvs([
			TLV(0x0001, struct.pack('>H', 1000)),   # max permits user is allowed
			TLV(0x0002, struct.pack('>H', 1000)),   # max deny entries user is allowed
			TLV(0x0003, struct.pack('>H', 1000))	# max temp permits user is allowed
		])

		self.logger.info('[Server] BOS__RIGHTS_REPLY')
		client.send_snac(response_msg)