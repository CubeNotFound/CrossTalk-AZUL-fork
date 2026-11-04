from util.misc import Logger

from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup

@Foodgroup(0x0018)
class EmailFoodgroup:
	logger: Logger

	@Subgroup(0x0006)
	def status_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] EMAIL__STATUS_REQUEST')
		# unread count. no mail yet, so it stays zero
		# 0x06 is ALERT__NOTIFY_CAPABILITIES, which takes no reply; answering it with an
		# ALERT__NOTIFY nobody asked for is what used to go back here
		self.logger.info('[Client] Alert capabilities:', message.data.hex())

	@Subgroup(0x0016)
	def activate(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] EMAIL__ACTIVATE (no reply expected)')
