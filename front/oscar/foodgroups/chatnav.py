import struct

from util.misc import Logger

from ..proto.buffer import Buffer
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs, find_tlv
from .chat import (
	EXCHANGE_PRIVATE, EXCHANGE_PUBLIC, ROOM_NAME, create_room, find_room, parse_room_info, room_info_update,
)

NAV_TLV_MAX_CONCURRENT_ROOMS = 0x0002
NAV_TLV_EXCHANGE_INFO = 0x0003
NAV_TLV_ROOM_INFO = 0x0004

NAV_ERROR_NOT_SUPPORTED = 0x0008
NAV_ERROR_NO_MATCH = 0x0014

MAX_CONCURRENT_ROOMS = 10


def exchange_info(exchange: int) -> bytes:
	# an exchange's description: u16 id, then a counted TLV block of its settings
	buf = Buffer()
	buf.write_u16(exchange)
	buf.write_tlv_block([
		TLV(0x0003, struct.pack('>B', MAX_CONCURRENT_ROOMS)),	# max concurrent rooms (aim 2.x-3.x want it)
		TLV(0x0002, struct.pack('>H', 0x0010)),				 # class permissions
		TLV(0x0004, struct.pack('>H', 100)),					 # max room name length
		TLV(0x00C9, struct.pack('>H', 15)),					  # flags: evilable, nav only, instancing, occupant peek
		TLV(0x00D5, struct.pack('>B', 2)),					   # who may create rooms
		TLV(0x00D6, 'us-ascii'),
		TLV(0x00D7, 'en'),
		TLV(0x00D8, 'us-ascii'),
		TLV(0x00D9, 'en'),
	])
	return buf.data

def nav_info(request_id: int, tlvs: list) -> SNACMessage:
	# CHAT_NAV__NAV_INFO: TLVs, no count
	msg = SNACMessage(0x000D, 0x0009, 0x0000, request_id)
	msg.write_tlvs(tlvs)
	return msg


@Foodgroup(0x000D)
class ChatNavFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def request_chat_rights(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] CHAT_NAV__REQUEST_CHAT_RIGHTS')
		client.send_snac(nav_info(message.request_id, [
			TLV(NAV_TLV_MAX_CONCURRENT_ROOMS, struct.pack('>B', MAX_CONCURRENT_ROOMS)),
			TLV(NAV_TLV_EXCHANGE_INFO, exchange_info(EXCHANGE_PRIVATE)),
			TLV(NAV_TLV_EXCHANGE_INFO, exchange_info(EXCHANGE_PUBLIC)),
		]))

	@Subgroup(0x0003)
	def request_exchange_info(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] CHAT_NAV__REQUEST_EXCHANGE_INFO')
		exchange = message.read_u16()
		if exchange not in (EXCHANGE_PRIVATE, EXCHANGE_PUBLIC):
			client.ctrl.send_snac_error(0x000D, message.request_id, NAV_ERROR_NOT_SUPPORTED)
			return
		client.send_snac(nav_info(message.request_id, [
			TLV(NAV_TLV_MAX_CONCURRENT_ROOMS, struct.pack('>B', MAX_CONCURRENT_ROOMS)),
			TLV(NAV_TLV_EXCHANGE_INFO, exchange_info(exchange)),
		]))

	@Subgroup(0x0004)
	def request_room_info(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# u16 exchange, string08 cookie, u16 instance, u8 detail level
		self.logger.info('[Client] CHAT_NAV__REQUEST_ROOM_INFO')
		info = parse_room_info(message.data)
		room = find_room(info['cookie']) if info is not None else None
		if room is None or room.exchange != info['exchange']:
			client.ctrl.send_snac_error(0x000D, message.request_id, NAV_ERROR_NO_MATCH)
			return
		client.send_snac(nav_info(message.request_id, [TLV(NAV_TLV_ROOM_INFO, room_info_update(room))]))

	@Subgroup(0x0008)
	def create_room(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# a CHAT__ROOM_INFO_UPDATE layout: u16 exchange, string08 cookie ("create"), u16 instance, u8 detail, TLV block
		self.logger.info('[Client] CHAT_NAV__CREATE_ROOM')
		buf = Buffer(message.data)
		try:
			exchange = buf.read_u16()
			buf.read_bytes(buf.read_u8())
			buf.read_u16()
			buf.read_u8()
			tlvs = buf.read_tlv_block()
		except (struct.error, AssertionError):
			client.ctrl.send_snac_error(0x000D, message.request_id, NAV_ERROR_NOT_SUPPORTED)
			return
		name_tlv = find_tlv(tlvs, ROOM_NAME)
		if exchange not in (EXCHANGE_PRIVATE, EXCHANGE_PUBLIC) or name_tlv is None or not name_tlv.data:
			client.ctrl.send_snac_error(0x000D, message.request_id, NAV_ERROR_NOT_SUPPORTED)
			return
		name = name_tlv.data.decode('utf-8', errors = 'replace')
		room = create_room(exchange, name, create = exchange == EXCHANGE_PRIVATE)
		if room is None:
			# public rooms are the operator's to make; there are none to join by name
			client.ctrl.send_snac_error(0x000D, message.request_id, NAV_ERROR_NO_MATCH)
			return
		client.send_snac(nav_info(message.request_id, [TLV(NAV_TLV_ROOM_INFO, room_info_update(room))]))
