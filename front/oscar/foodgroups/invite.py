from util.misc import Logger

from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup


@Foodgroup(0x0006)
class InviteFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def request_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# "invite a friend to AIM" (an e-mail address and a message); nothing is sent out
		self.logger.info('[Client] INVITE__REQUEST_QUERY (not sent)')
