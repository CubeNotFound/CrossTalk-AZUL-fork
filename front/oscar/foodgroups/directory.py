import struct

from util.misc import Logger

from ..proto import names
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs, find_tlv

ODIR_FIRST_NAME = 0x0001
ODIR_LAST_NAME = 0x0002
ODIR_EMAIL = 0x0005
ODIR_COUNTRY = 0x0006
ODIR_STATE = 0x0007
ODIR_CITY = 0x0008
ODIR_SCREEN_NAME = 0x0009
ODIR_INTEREST = 0x000B
ODIR_NICKNAME = 0x000C

SEARCH_NAME_MISSING = 0x0004
SEARCH_OK = 0x0005

MAX_RESULTS = 20

@Foodgroup(0x000F)
class DirectoryFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def info_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] DIRECTORY__INFO_QUERY')

		# the search kind follows from the TLVs:
		# an e-mail address, an interest keyword, or a first or last name
		tlvs = unmarshal_tlvs(message.data)
		backend = context.backend

		def text(tag: int) -> str:
			tlv = find_tlv(tlvs, tag)
			return tlv.data.decode('latin-1') if tlv is not None else ''

		reply = SNACMessage(0x000F, 0x0003, 0x0000, message.request_id)
		if find_tlv(tlvs, ODIR_EMAIL) is not None:
			uuids = backend.user_service.search_uuids(email = text(ODIR_EMAIL), limit = MAX_RESULTS)
		elif find_tlv(tlvs, ODIR_INTEREST) is not None:
			uuids = []
		elif find_tlv(tlvs, ODIR_FIRST_NAME) is not None or find_tlv(tlvs, ODIR_LAST_NAME) is not None:
			uuids = backend.user_service.search_uuids(
				first_name = text(ODIR_FIRST_NAME), last_name = text(ODIR_LAST_NAME), nickname = text(ODIR_NICKNAME),
				limit = MAX_RESULTS,
			)
		else:
			# ODIR__INFO_REPLY: u16 status, u16 unknown, and with this status nothing else
			reply.write_u16(SEARCH_NAME_MISSING)
			reply.write_u16(0)
			self.logger.info('[Server] DIRECTORY__INFO_REPLY')
			client.send_snac(reply)
			return

		from .locate import dir_tlvs
		results = []
		for uuid in uuids:
			user = backend._load_user_record(uuid)
			if user is None or not names.representable(user):
				continue
			fields = { tlv.type: tlv for tlv in dir_tlvs(user) }
			results.append([
				fields.get(ODIR_FIRST_NAME, TLV(ODIR_FIRST_NAME, b'')),
				fields.get(ODIR_LAST_NAME, TLV(ODIR_LAST_NAME, b'')),
				fields.get(ODIR_STATE, TLV(ODIR_STATE, b'')),
				fields.get(ODIR_CITY, TLV(ODIR_CITY, b'')),
				fields.get(ODIR_COUNTRY, TLV(ODIR_COUNTRY, b'')),
				TLV(ODIR_SCREEN_NAME, names.name_for(context.bs, user)),
			])

		# u16 status, u16 unknown, u16 result count, each result a counted TLV block
		reply.write_u16(SEARCH_OK)
		reply.write_u16(0)
		reply.write_u16(len(results))
		for result in results:
			reply.write_tlv_block(result)
		self.logger.info('[Server] DIRECTORY__INFO_REPLY')
		client.send_snac(reply)

	@Subgroup(0x0004)
	def interests_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] DIRECTORY__INTERESTS_QUERY')

		# we don't yet have an interests directory, so the count stays zero.
		response_msg = SNACMessage(0x000F, 0x0005, 0x0000, message.request_id)
		response_msg.write_u16(1)
		response_msg.write_u16(0)

		self.logger.info('[Server] DIRECTORY__INTERESTS_LIST')
		client.send_snac(response_msg)
