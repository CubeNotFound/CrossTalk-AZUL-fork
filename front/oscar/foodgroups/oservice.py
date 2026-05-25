import os
import calendar
import struct
import settings

from datetime import datetime, timezone

from util.misc import Logger

from ..proto.backend import FOODGROUP_VERSIONS, bos_cookies
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs


@Foodgroup(0x0001)
class OSERVICEFoodgroup:
	logger: Logger

	@Subgroup(0x0017)
	def client_versions(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__CLIENT_VERSIONS')

		response_msg = SNACMessage(0x0001, 0x0018, 0x0000, 0x0000)
		for foodgroup, version in FOODGROUP_VERSIONS.items():
			response_msg.write_u16(foodgroup)
			response_msg.write_u16(version)

		self.logger.info('[Server] OSERVICE__HOST_VERSIONS')
		client.send_snac(response_msg)

	@Subgroup(0x0006)
	def rate_params_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__RATE_PARAMS_QUERY')

		hex = """
		00 05 00 01 00 00 00 50  00 00 09 C4 00 00 07 D0
		00 00 05 DC 00 00 03 20  00 00 0D 69 00 00 17 70
		00 00 00 00 00 00 02 00  00 00 50 00 00 0B B8 00
		00 07 D0 00 00 05 DC 00  00 03 E8 00 00 17 70 00
		00 17 70 00 00 F9 0B 00  00 03 00 00 00 14 00 00
		13 EC 00 00 13 88 00 00  0F A0 00 00 0B B8 00 00
		11 47 00 00 17 70 00 00  5C D8 00 00 04 00 00 00
		14 00 00 15 7C 00 00 14  B4 00 00 10 68 00 00 0B
		B8 00 00 17 70 00 00 1F  40 00 00 F9 0B 00 00 05
		00 00 00 0A 00 00 15 7C  00 00 14 B4 00 00 10 68
		00 00 0B B8 00 00 17 70  00 00 1F 40 00 00 F9 0B
		00 00 01 00 91 00 01 00  01 00 01 00 02 00 01 00
		03 00 01 00 04 00 01 00  05 00 01 00 06 00 01 00
		07 00 01 00 08 00 01 00  09 00 01 00 0A 00 01 00
		0B 00 01 00 0C 00 01 00  0D 00 01 00 0E 00 01 00
		0F 00 01 00 10 00 01 00  11 00 01 00 12 00 01 00
		13 00 01 00 14 00 01 00  15 00 01 00 16 00 01 00
		17 00 01 00 18 00 01 00  19 00 01 00 1A 00 01 00
		1B 00 01 00 1C 00 01 00  1D 00 01 00 1E 00 01 00
		1F 00 01 00 20 00 01 00  21 00 02 00 01 00 02 00
		02 00 02 00 03 00 02 00  04 00 02 00 06 00 02 00
		07 00 02 00 08 00 02 00  0A 00 02 00 0C 00 02 00
		0D 00 02 00 0E 00 02 00  0F 00 02 00 10 00 02 00
		11 00 02 00 12 00 02 00  13 00 02 00 14 00 02 00
		15 00 03 00 01 00 03 00  02 00 03 00 03 00 03 00
		06 00 03 00 07 00 03 00  08 00 03 00 09 00 03 00
		0A 00 03 00 0B 00 03 00  0C 00 04 00 01 00 04 00
		02 00 04 00 03 00 04 00  04 00 04 00 05 00 04 00
		07 00 04 00 08 00 04 00  09 00 04 00 0A 00 04 00
		0B 00 04 00 0C 00 04 00  0D 00 04 00 0E 00 04 00
		0F 00 04 00 10 00 04 00  11 00 04 00 12 00 04 00
		13 00 04 00 14 00 06 00  01 00 06 00 02 00 06 00
		03 00 08 00 01 00 08 00  02 00 09 00 01 00 09 00
		02 00 09 00 03 00 09 00  04 00 09 00 09 00 09 00
		0A 00 09 00 0B 00 0A 00  01 00 0A 00 02 00 0A 00
		03 00 0B 00 01 00 0B 00  02 00 0B 00 03 00 0B 00
		04 00 0C 00 01 00 0C 00  02 00 0C 00 03 00 13 00
		01 00 13 00 02 00 13 00  03 00 13 00 04 00 13 00
		05 00 13 00 06 00 13 00  07 00 13 00 08 00 13 00
		09 00 13 00 0A 00 13 00  0B 00 13 00 0C 00 13 00
		0D 00 13 00 0E 00 13 00  0F 00 13 00 10 00 13 00
		11 00 13 00 12 00 13 00  13 00 13 00 14 00 13 00
		15 00 13 00 16 00 13 00  17 00 13 00 18 00 13 00
		19 00 13 00 1A 00 13 00  1B 00 13 00 1C 00 13 00
		1D 00 13 00 1E 00 13 00  1F 00 13 00 20 00 13 00
		21 00 13 00 22 00 13 00  23 00 13 00 24 00 13 00
		25 00 13 00 26 00 13 00  27 00 13 00 28 00 15 00
		01 00 15 00 02 00 15 00  03 00 02 00 06 00 03 00
		04 00 03 00 05 00 09 00  05 00 09 00 06 00 09 00
		07 00 09 00 08 00 03 00  02 00 02 00 05 00 04 00
		06 00 04 00 02 00 02 00  09 00 02 00 0B 00 05 00
		00
		"""
		cleaned_hex = (hex
					   .strip()
					   .replace(" ", "")
					   .replace("\r\n", "\n")
					   .replace("\n", ""))

		response_msg = SNACMessage(0x0001, 0x0007, 0x0000, 0x0000, bytes.fromhex(cleaned_hex))

		self.logger.info('[Server] OSERVICE__RATE_PARAMS_REPLY')
		client.send_snac(response_msg)

	@Subgroup(0x0008)
	def rate_params_sub_add(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__RATE_PARAMS_SUB_ADD (not implemented)')

		# since i don't have rate limits properly implemented *yet*, i won't do anything here

	@Subgroup(0x000E)
	def user_info_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__USER_INFO_QUERY')

		response_msg = SNACMessage(0x0001, 0x000F)
		response_msg.write_string_u8(context.bs.user.username)  # Screen name
		response_msg.write_u16(0)							   # Warning level

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

		response_msg.write_tlv_block([
			TLV(0x0001, struct.pack('>L', 0x0100)),			 # User class (bitfield)
			TLV(0x0003, struct.pack('>L', date_login_unix)),	# Account signon time (unix time_t)
			TLV(0x0005, struct.pack('>L', date_created_unix)),  # Accout creation time (unix time_t)
			TLV(0x000F, struct.pack('>L', session_len))		 # Session length
		])

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
		else:
			self.logger.info(context.bs.user.username, 'has been idle for', str(idle_time), 'seconds')

		# This SNAC as seen from NINA's servers:
		# ==
		# 0000   2a 02 00 0e 00 0e 00 0b 00 02 00 00 e7 19 67 3c   *.............g<
		#		[FLAP Header....] [SNAC Header................]
		# 0010   00 01 00 00									   ....
		#		^^^^^^^^^^^
		msg = SNACMessage(0x000B, 0x0002)
		msg.write_u32(0x010000)

		self.logger.info('[Server] STATS__SET_MIN_REPORT_INTERVAL')
		client.send_snac(msg)

	@Subgroup(0x0004)
	def service_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] OSERVICE__SERVICE_REQUEST')

		foodgroup = message.read_u16()
		self.logger.info('[Client] Foodgroup:', hex(foodgroup))

		# generate BOS cookie and add it to array
		bos_cookie = os.urandom(256)
		bos_cookies.append({
			bos_cookie: context.bs
		})

		response_msg = SNACMessage(0x0001, 0x0005, 0x0000, message.request_id)
		response_msg.write_tlvs([
			TLV(0x0001, struct.pack('>H', 3)),
			TLV(0x0005, f'{settings.TARGET_IP}:5190'),
			TLV(0x0006, bos_cookie),
			TLV(0x000D, struct.pack('>H', foodgroup)),
			TLV(0x008E, struct.pack('>B', 0))
		])

		client.send_snac(response_msg)
