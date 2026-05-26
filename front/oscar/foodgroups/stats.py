from util.misc import Logger

from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup


@Foodgroup(0x000B)
class StatsFoodgroup:
	logger: Logger

	@Subgroup(0x0003)
	def report_events(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] STATS__REPORT_EVENTS')

		# we don't really care for the info in the SNAC message's body for now, so just send
		# a STATS__REPORT_ACK
		self.logger.info('[Server] STATS__REPORT_ACK')
		client.send_snac(SNACMessage(0x000B, 0x0004))
