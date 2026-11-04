import struct

from util.misc import Logger

from ..proto import names
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV

LOOKUP_TLV_SCREEN_NAME = 0x0001
LOOKUP_ERROR_NO_MATCH = 0x0014


@Foodgroup(0x000A)
class UserLookupFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def find_by_email(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] USER_LOOKUP__FIND_BY_EMAIL')

		# the SNAC body is the address itself; only people listed in the member directory can be found by it
		email = message.data.decode('latin-1').strip('\x00').strip()
		users = []
		for uuid in (context.backend.user_service.search_uuids(email = email) if email else []):
			user = context.backend._load_user_record(uuid)
			if user is not None and names.representable(user):
				users.append(user)

		if not users:
			msg = SNACMessage(0x000A, 0x0001, 0x0000, message.request_id)
			msg.write_u16(LOOKUP_ERROR_NO_MATCH)
			self.logger.info('[Server] USER_LOOKUP__ERR')
			client.send_snac(msg)
			return

		reply = SNACMessage(0x000A, 0x0003, 0x0000, message.request_id)
		reply.write_tlvs([TLV(LOOKUP_TLV_SCREEN_NAME, names.name_for(context.bs, user)) for user in users])
		self.logger.info('[Server] USER_LOOKUP__FIND_REPLY')
		client.send_snac(reply)
