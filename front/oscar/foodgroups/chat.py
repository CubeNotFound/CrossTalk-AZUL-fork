import struct
import time

from typing import Any

from util.misc import Logger

from ..proto import names
from ..proto.buffer import Buffer
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs, marshal_tlvs, find_tlv
from ..proto.userinfo import build_userinfo

EXCHANGE_PRIVATE = 0x0004
EXCHANGE_PUBLIC = 0x0005

ROOM_FULLY_QUALIFIED_NAME = 0x006A
ROOM_FLAGS = 0x00C9
ROOM_CREATE_TIME = 0x00CA
ROOM_MAX_MESSAGE_LENGTH = 0x00D1
ROOM_MAX_OCCUPANCY = 0x00D2
ROOM_NAME = 0x00D3
ROOM_CREATE_PERMISSIONS = 0x00D5
ROOM_MAX_VISIBLE_MESSAGE_LENGTH = 0x00DA

CHAT_TLV_PUBLIC_WHISPER = 0x0001
CHAT_TLV_WHISPER_TO = 0x0002
CHAT_TLV_SENDER = 0x0003
CHAT_TLV_MESSAGE = 0x0005
CHAT_TLV_REFLECT = 0x0006
MESSAGE_TEXT = 0x0001
MESSAGE_ENCODING = 0x0002
MESSAGE_LANGUAGE = 0x0003


class Room:
	__slots__ = ('exchange', 'name', 'cookie', 'created', 'members')

	exchange: int
	name: str
	cookie: str
	created: int
	# the chat service connections in the room, in the order they joined
	members: dict[Any, None]

	def __init__(self, exchange: int, name: str) -> None:
		self.exchange = exchange
		self.name = name
		# exchange-instance-name, the layout clients (Pidgin, at least) take the room name back out of
		self.cookie = '{}-{}-{}'.format(exchange, 0, name)
		self.created = int(time.time())
		self.members = {}

_rooms: dict[str, Room] = {}
_rooms_by_name: dict[tuple[int, str], Room] = {}


def find_room(cookie: str) -> Room | None:
	return _rooms.get(cookie)

def create_room(exchange: int, name: str, *, create: bool = True) -> Room | None:
	# a room exists while anyone is in it (or about to join), and is found again by name
	key = (exchange, name.lower())
	room = _rooms_by_name.get(key)
	if room is not None or not create:
		return room
	# rooms made but never joined don't hang around
	now = time.time()
	for stale in [other for other in _rooms.values() if not other.members and now - other.created > 300]:
		_drop_room(stale)
	room = Room(exchange, name)
	_rooms[room.cookie] = room
	_rooms_by_name[key] = room
	return room

def _drop_room(room: Room) -> None:
	_rooms.pop(room.cookie, None)
	_rooms_by_name.pop((room.exchange, room.name.lower()), None)

def room_tlvs(room: Room) -> list[TLV]:
	encoded = room.name.encode('utf-8')
	return [
		TLV(ROOM_FLAGS, struct.pack('>H', 15)),
		TLV(ROOM_CREATE_TIME, struct.pack('>L', room.created)),
		TLV(ROOM_MAX_MESSAGE_LENGTH, struct.pack('>H', 1024)),
		TLV(ROOM_MAX_OCCUPANCY, struct.pack('>H', 100)),
		TLV(ROOM_CREATE_PERMISSIONS, struct.pack('>B', 2)),
		TLV(ROOM_FULLY_QUALIFIED_NAME, encoded),
		TLV(ROOM_NAME, encoded),
		TLV(ROOM_MAX_VISIBLE_MESSAGE_LENGTH, struct.pack('>H', 1024)),
	]

def room_info_update(room: Room) -> bytes:
	# u16 exchange, string08 cookie, u16 instance, u8 detail level (Pidgin expects 2), counted TLV block
	cookie = room.cookie.encode('utf-8')
	buf = Buffer()
	buf.write_u16(room.exchange)
	buf.write_u8(len(cookie))
	buf.write_bytes(cookie)
	buf.write_u16(0)
	buf.write_u8(0x02)
	buf.write_tlv_block(room_tlvs(room))
	return buf.data

def parse_room_info(data: bytes) -> dict[str, Any] | None:
	# u16 exchange, string08 cookie, u16 instance (what OSERVICE__SERVICE_REQUEST and CHAT_NAV name a room by)
	if len(data) < 3 or len(data) < 3 + data[2]:
		return None
	exchange = struct.unpack('>H', data[:2])[0]
	cookie = data[3:3 + data[2]].decode('utf-8', errors = 'replace')
	instance = struct.unpack('>H', data[3 + data[2]:5 + data[2]])[0] if len(data) >= 5 + data[2] else 0
	return { 'exchange': exchange, 'cookie': cookie, 'instance': instance }

def _userinfo(member: Any, viewer: Any) -> bytes:
	return build_userinfo(
		member.bs.user, member.bs, name = names.name_for(viewer.bs, member.bs.user), viewer_icq = names.is_icq_session(viewer.bs),
	)

def _users_snac(subgroup: int, members: list[Any], viewer: Any) -> SNACMessage:
	# CHAT__USERS_JOINED / CHAT__USERS_LEFT: USERINFOs back to back
	msg = SNACMessage(0x000E, subgroup)
	for member in members:
		msg.write_bytes(_userinfo(member, viewer))
	return msg

def join_room(ctrl: Any) -> None:
	# on the chat connection's OSERVICE__CLIENT_READY, in the order the macOS 4.0.9 client needs (or it drops the room
	# seconds later): who's in it, the room's info, then everyone else hears about the newcomer
	info = ctrl.room
	room = find_room(info['cookie']) if info is not None else None
	if room is None:
		ctrl.close()
		return
	room.members[ctrl] = None
	members = list(room.members)
	ctrl.send_snac(_users_snac(0x0003, members, ctrl))
	update = SNACMessage(0x000E, 0x0002)
	update.write_bytes(room_info_update(room))
	ctrl.send_snac(update)
	for other in members:
		if other is not ctrl:
			other.send_snac(_users_snac(0x0003, [ctrl], other))

def leave_room(ctrl: Any) -> None:
	info = ctrl.room
	ctrl.room = None
	room = find_room(info['cookie']) if info is not None else None
	if room is None or ctrl not in room.members:
		return
	del room.members[ctrl]
	for other in list(room.members):
		other.send_snac(_users_snac(0x0004, [ctrl], other))
	if not room.members:
		_drop_room(room)


@Foodgroup(0x000E)
class ChatFoodgroup:
	logger: Logger

	@Subgroup(0x0005)
	def channel_msg_tohost(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] CHAT__CHANNEL_MSG_TOHOST')

		ctrl = client.ctrl
		info = ctrl.room
		room = find_room(info['cookie']) if info is not None else None
		if room is None or ctrl not in room.members:
			return

		# cookie, u16 channel, TLVs
		cookie = message.read_bytes(8)
		channel = message.read_u16()
		tlvs = unmarshal_tlvs(message.data)
		if channel == 0xFFFF:
			# the macOS 4.0.9 client sends a broken channel; it means the MIME channel
			channel = 0x0003

		message_tlv = find_tlv(tlvs, CHAT_TLV_MESSAGE)
		if message_tlv is None:
			return
		# only the text, its encoding and language get passed on: extra TLVs from newer clients (AIM 5.9's) crash older
		# ones (macOS AIM 2.x)
		parts = []
		for tlv in unmarshal_tlvs(message_tlv.data):
			if tlv.type == MESSAGE_ENCODING and tlv.data == b'ISO 8859':
				# Kopete's encoding name leaves the message blank in Windows AIM
				tlv = TLV(MESSAGE_ENCODING, 'ISO-8859-1')
			if tlv.type in (MESSAGE_TEXT, MESSAGE_ENCODING, MESSAGE_LANGUAGE):
				parts.append(tlv)
		public_whisper = find_tlv(tlvs, CHAT_TLV_PUBLIC_WHISPER) is not None
		whisper_tlv = find_tlv(tlvs, CHAT_TLV_WHISPER_TO)

		def build(viewer: Any) -> SNACMessage:
			# CHAT__CHANNEL_MSG_TOCLIENT: cookie, channel, then (in this order, or AIM 2.x loses the names) the sender,
			# the public whisper flag, the message
			out = SNACMessage(0x000E, 0x0006)
			out.write_bytes(cookie)
			out.write_u16(channel)
			out_tlvs = [TLV(CHAT_TLV_SENDER, _userinfo(ctrl, viewer))]
			if public_whisper:
				out_tlvs.append(TLV(CHAT_TLV_PUBLIC_WHISPER))
			out_tlvs.append(TLV(CHAT_TLV_MESSAGE, marshal_tlvs(parts)))
			out.write_tlvs(out_tlvs)
			return out

		if whisper_tlv is not None and not public_whisper:
			# a whisper goes to just the one person
			target = names.resolve(context.backend, whisper_tlv.data.decode('latin-1'))
			for member in room.members:
				if member is not ctrl and member.bs is not None and member.bs.user.uuid == target:
					member.send_snac(build(member))
		else:
			for member in room.members:
				if member is not ctrl:
					member.send_snac(build(member))

		if find_tlv(tlvs, CHAT_TLV_REFLECT) is not None:
			reflected = build(ctrl)
			reflected.request_id = message.request_id
			ctrl.send_snac(reflected)
