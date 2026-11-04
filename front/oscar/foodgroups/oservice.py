import os
import calendar
import struct
import time
import settings

from datetime import datetime, timezone

from core.models import ContactList, Substatus
from util.misc import Logger, is_valid_oscar_screenname

from ..proto import names
from ..proto.backend import FOODGROUP_VERSIONS, SERVICE_FOODGROUPS, ServiceCookie, issue_cookie, bos_cookies
from ..proto.buffer import Buffer
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs, find_tlv
from ..proto.userinfo import build_userinfo, substatus_from_icq_status, ICQ_DC_INFO_EMPTY
from .buddy import build_presence_notif, push_buddy_list

RATE_CLASSES = (
	(1, 80, 2500, 2000, 1500, 800, 6000),
	(2, 80, 3000, 2000, 1500, 1000, 6000),
	(3, 20, 5100, 5000, 4000, 3000, 6000),
	(4, 20, 5500, 5300, 4200, 3000, 8000),
	(5, 10, 5500, 5300, 4200, 3000, 8000),
)

RATE_GROUPS = {
	0x0001: (0x0023, {}),
	0x0002: (0x0015, {0x0005: 3, 0x0009: 4, 0x000B: 4}),
	0x0003: (0x0010, {0x0004: 2, 0x0005: 2}),
	0x0004: (0x0014, {0x0006: 3}),
	0x0005: (0x0003, {}),
	0x0006: (0x0003, {}),
	0x0007: (0x0009, {}),
	0x0008: (0x0002, {}),
	0x0009: (0x000B, {0x0005: 2, 0x0006: 2, 0x0007: 2, 0x0008: 2}),
	0x000A: (0x0003, {}),
	0x000B: (0x0004, {}),
	0x000C: (0x0003, {}),
	0x000D: (0x0009, {}),
	0x000E: (0x0009, {0x0005: 2}),
	0x000F: (0x0004, {}),
	0x0010: (0x0006, {}),
	0x0013: (0x0028, {}),
	0x0015: (0x0003, {}),
	0x0017: (0x000C, {}),
	0x0018: (0x0017, {}),
}
RATE_GROUP_GAPS = {
	0x0003: (0x000D, 0x000E),
	0x0010: (0x0003, 0x0005),
	0x0017: (0x0003, 0x0005, 0x0007, 0x0009, 0x000B),
	0x0018: (0x0003, 0x0005, 0x0009, 0x000B, 0x000C, 0x0013, 0x0014),
}

MIN_STATS_REPORT_INTERVAL = 1200

REQUESTABLE_SERVICES = frozenset({0x0007, 0x000D, 0x000E, 0x000F, 0x0010, 0x0018})

def build_rate_params(oservice_version: int) -> bytes:
	buf = Buffer()
	buf.write_u16(len(RATE_CLASSES))
	now = int(time.time())
	for ident, window, clear, alert, limit, disconnect, max_level in RATE_CLASSES:
		buf.write_u16(ident)
		for value in (window, clear, alert, limit, disconnect, max_level, max_level):
			buf.write_u32(value)
		# OSERVICE v2 and up add when the last SNAC came in and whether SNACs are being dropped
		if oservice_version > 1:
			buf.write_u32(now - 1)
			buf.write_u8(0)
	for ident, *_ in RATE_CLASSES:
		pairs = []
		for foodgroup, (last, exceptions) in RATE_GROUPS.items():
			gaps = RATE_GROUP_GAPS.get(foodgroup, ())
			for subgroup in range(0x0001, last + 1):
				if subgroup in gaps:
					continue
				if exceptions.get(subgroup, 1) == ident:
					pairs.append((foodgroup, subgroup))
		buf.write_u16(ident)
		buf.write_u16(len(pairs))
		for foodgroup, subgroup in pairs:
			buf.write_u16(foodgroup)
			buf.write_u16(subgroup)
	return buf.data

def build_self_info(bs) -> SNACMessage:
	# OSERVICE__USER_INFO_UPDATE, under the name the client signed on with
	msg = SNACMessage(0x0001, 0x000F)
	msg.write_bytes(build_userinfo(bs.user, bs, name = names.self_name(bs), viewer_icq = names.is_icq_session(bs)))
	return msg

def initial_substatus(bs) -> Substatus:
	# what a client asked for before it was ready: an ICQ status (SNAC(01,1E)), an away message (LOCATE__SET_INFO)
	raw = bs.front_data.get('oscar0_icq_status')
	if raw is not None:
		return substatus_from_icq_status(raw)
	if bs.front_data.get('oscar0_away'):
		return Substatus.Away
	return Substatus.Online


@Foodgroup(0x0001)
class OSERVICEFoodgroup:
	logger: Logger

	@Subgroup(0x0017)
	def client_versions(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__CLIENT_VERSIONS')

		versions = {}
		while len(message) >= 4:
			foodgroup = message.read_u16()
			version = message.read_u16()
			versions[foodgroup] = version
		client.ctrl.versions = versions

		response_msg = SNACMessage(0x0001, 0x0018, 0x0000, message.request_id)
		for foodgroup, version in versions.items():
			response_msg.write_u16(foodgroup)
			response_msg.write_u16(version)

		self.logger.info('[Server] OSERVICE__HOST_VERSIONS')
		client.send_snac(response_msg)

		if getattr(settings, 'OSCAR_MOTD_ENABLED', False):
			# OSERVICE__MOTD: u16 message type (4: the message of the day), then TLV 0x0B with its text
			motd = SNACMessage(0x0001, 0x0013)
			motd.write_u16(0x0004)
			motd.write_tlv(TLV(0x000B, getattr(settings, 'OSCAR_MOTD_TEXT', 'Welcome to CrossTalk!')))
			self.logger.info('[Server] OSERVICE__MOTD')
			client.send_snac(motd)

	@Subgroup(0x0002)
	def client_ready(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__CLIENT_READY')

		ctrl = client.ctrl
		if ctrl.is_service:
			# a chat room connection is where the room is joined; the other services have nothing more to do
			if ctrl.service == 0x000E:
				from .chat import join_room
				join_room(ctrl)
			return

		bs = context.bs
		if bs.front_data.get('oscar0_ready'):
			return
		bs.front_data['oscar0_ready'] = True

		detail = context.backend._load_detail(context.user)
		if detail is None:
			return

		# the client is signed on now: going online is what tells everyone with it on their list
		bs.me_update({ 'substatus': initial_substatus(bs) })

		# cached statuses can lag behind, so recompute before deciding who is online
		push_buddy_list(bs)

		# This SNAC as seen from NINA's servers:
		# ==
		# 0000   2a 02 00 0e 00 0e 00 0b 00 02 00 00 e7 19 67 3c   *.............g
		#		[FLAP Header....] [SNAC Header................]
		# 0010   00 01 00 00									   ....
		#		^^^^^^^^^^^
		msg = SNACMessage(0x000B, 0x0002)
		msg.write_u16(MIN_STATS_REPORT_INTERVAL)

		self.logger.info('[Server] STATS__SET_MIN_REPORT_INTERVAL')
		client.send_snac(msg)

		# authorization requests and answers that came in while this account wasn't on ICQ
		from .feedbag import deliver_queued_auth_events
		deliver_queued_auth_events(client.ctrl)

		# AIM before 6.0 never asks for its offline IMs (ICBM__OFFLINE_RETRIEVE), so they're handed over now; ICQ asks
		# through its own foodgroup once it's ready for them
		if not names.is_icq_session(bs):
			from .icbm import deliver_stored_messages
			deliver_stored_messages(client.ctrl)

	@Subgroup(0x0006)
	def rate_params_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__RATE_PARAMS_QUERY')

		oservice_version = getattr(client.ctrl, 'versions', {}).get(0x0001, 1)
		response_msg = SNACMessage(0x0001, 0x0007, 0x0000, message.request_id, build_rate_params(oservice_version))

		self.logger.info('[Server] OSERVICE__RATE_PARAMS_REPLY')
		client.send_snac(response_msg)

	@Subgroup(0x0008)
	def rate_params_sub_add(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__RATE_PARAMS_SUB_ADD (not implemented)')

		# since i don't have rate limits properly implemented *yet*, i won't do anything here

	@Subgroup(0x000E)
	def user_info_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__USER_INFO_QUERY')

		date_created = context.bs.user.date_created
		date_login = context.bs.user.date_login
		now = datetime.now(tz=timezone.utc)

		date_created_unix = int(calendar.timegm(date_created.timetuple()))
		date_login_unix = int(calendar.timegm(date_login.timetuple())) if date_login else 0
		session_len = int(now.timestamp()) - date_login_unix if date_login else 0

		self.logger.info('Date created:', date_created)
		self.logger.info('Date created (UNIX time):', date_created_unix)
		self.logger.info('Date logged in:', date_login or 'Never')

		self.logger.info('Date logged in (UNIX time):', date_login_unix)
		self.logger.info('Current time:', int(now.timestamp()))
		self.logger.info('Session length:', session_len)

		self.logger.info('Client IP:', client.get_ip())

		# OSERVICE__USERINFO: displayId, warning level, then the OSERVICE__USER_INFO_TAGS block
		response_msg = build_self_info(context.bs)
		response_msg.request_id = message.request_id

		self.logger.info('[Server] OSERVICE__USER_INFO_UPDATE')
		client.send_snac(response_msg)

		#if settings.OSCAR_MOTD_ENABLED:
		#	self.logger.info('[Server] OSERVICE__MOTD')
		#	motd = SNACMessage(0x0001, 0x0013, 0x0000, 0x0000)
		#	motd.write_u8(4)
		#	motd.write_u8(0) # filler
		#	motd.write_tlv(TLV(0x000B, "Welcome to CrossTalk! OSCAR support is currently in pre-alpha. You should use MSN Messenger or Yahoo Messenger for now."))
		#	client.send_snac(motd)

	@Subgroup(0x0011)
	def idle_notification(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__IDLE_NOTIFICATION')

		idle_time = message.read_u32()
		if idle_time == 0:
			self.logger.info(context.bs.user.username, 'is no longer idle')
			context.bs.front_data.pop('oscar0_idle_since', None)
		else:
			self.logger.info(context.bs.user.username, 'has been idle for', str(idle_time), 'seconds')
			context.bs.front_data['oscar0_idle_since'] = time.time() - idle_time

		# contacts need a fresh arrival so the idle time in the userinfo gets refreshed on their end
		context.bs.me_update({
			'needs_notify': True,
			'notify_status': True,
		})

	@Subgroup(0x0014)
	def set_privacy_flags(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# u32 flags: 0x01 lets others see idle time, 0x02 the member since date; nothing here hides either yet
		flags = message.read_u32() if len(message) >= 4 else 0
		self.logger.info('[Client] OSERVICE__SET_PRIVACY_FLAGS', hex(flags))

	@Subgroup(0x0016)
	def noop(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# a keep-alive; there is no reply
		self.logger.info('[Client] OSERVICE__NOOP')

	@Subgroup(0x001E)
	def set_user_info_fields(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__SET_USERINFO_FIELDS')

		bs = context.bs
		tlvs = unmarshal_tlvs(message.data)

		# TLV 0x0C: ICQ direct connection info, passed on in this user's arrivals so ICQ peers can connect directly
		if (dc_tlv := find_tlv(tlvs, 0x000C)) is not None and len(dc_tlv.data) >= len(ICQ_DC_INFO_EMPTY):
			bs.front_data['oscar0_icq_dc'] = dc_tlv.data[:len(ICQ_DC_INFO_EMPTY)]

		# TLV 0x06: u32 status (the low word is the ICQ status, the high word flags like web aware)
		if (status_tlv := find_tlv(tlvs, 0x0006)) is not None and len(status_tlv.data) >= 4:
			status = struct.unpack('>L', status_tlv.data[:4])[0]
			bs.front_data['oscar0_icq_status'] = status
			self.logger.info('[Client] Status:', hex(status))
			# before OSERVICE__CLIENT_READY this is only what the client wants to come online as
			if bs.front_data.get('oscar0_ready'):
				substatus = substatus_from_icq_status(status)
				if substatus is context.user.status.substatus:
					bs.me_update({ 'needs_notify': True, 'notify_status': True })
				else:
					bs.me_update({ 'substatus': substatus })

		client.send_snac(build_self_info(bs))

	@Subgroup(0x001F)
	def probe_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# some ICQ clients probe a connection before using it; OSERVICE__PROBE_ACK has no body
		self.logger.info('[Client] OSERVICE__PROBE_REQ')
		client.send_snac(SNACMessage(0x0001, 0x0020, 0x0000, message.request_id))

	@Subgroup(0x0004)
	def service_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__SERVICE_REQUEST')

		foodgroup = message.read_u16()
		tlvs = unmarshal_tlvs(message.data)
		self.logger.info('[Client] Foodgroup:', hex(foodgroup))

		if foodgroup not in REQUESTABLE_SERVICES:
			# OSERVICE__ERR, service unavailable
			client.ctrl.send_snac_error(0x0001, message.request_id, 0x0005)
			return

		room = None
		if foodgroup == 0x000E:
			# TLV 0x01: the room to connect to (u16 exchange, string08 cookie, u16 instance)
			from .chat import parse_room_info, find_room
			room_tlv = find_tlv(tlvs, 0x0001)
			room = parse_room_info(room_tlv.data) if room_tlv is not None else None
			if room is None or find_room(room['cookie']) is None:
				client.ctrl.send_snac_error(0x0001, message.request_id, 0x0005)
				return

		# generate BOS cookie and add it to array
		bos_cookie = issue_cookie(ServiceCookie(
			bs = context.bs, service = foodgroup, room = room, multi_conn = client.ctrl.multi_conn,
		))

		response_msg = SNACMessage(0x0001, 0x0005, 0x0000, message.request_id)
		response_msg.write_tlvs([
			TLV(0x000D, struct.pack('>H', foodgroup)),
			TLV(0x0005, f'{settings.TARGET_IP}:5190'),
			TLV(0x0006, bos_cookie),
			TLV(0x008E, struct.pack('>B', 0))
		])

		client.send_snac(response_msg)
