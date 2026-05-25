from core.client import Client
from util.misc import Logger
from util.hash import gen_salt

from ..proto.backend import login, LoginError
from ..proto.buffer import Buffer
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import unmarshal_tlvs, find_tlv

pw_change_url_format = 'http://aim.aol.com/redirects/password/change_password.adp?ScreenName={}&ccode=us&lang=en'


@Foodgroup(0x0017)
class BUCPFoodgroup:
	logger: Logger

	@Subgroup(0x0006)
	def challenge_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BUCP__CHALLENGE_REQUEST')

		tlvs = unmarshal_tlvs(message.data)
		screen_name_tlv = find_tlv(tlvs, 0x0001)
		screen_name = screen_name_tlv.data.decode()

		salt = context.backend.user_service.aim_get_md5_salt(screen_name)

		if salt is None:
			# screen name doesn't exist or user did not enable OSCAR
			salt = gen_salt()

		response_msg = SNACMessage(0x0001, 0x0007)
		response_msg.write_u16(len(salt))
		response_msg.write_string(salt)

		self.logger.info('[Server] BUCP__CHALLENGE_RESPONSE (salt:', salt + ')')
		client.send_snac(response_msg)

	@Subgroup(0x0002)
	def login_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BUCP__LOGIN_REQUEST')

		tlvs = unmarshal_tlvs(message.data)

		screen_name_tlv = find_tlv(tlvs, 0x0001)
		hashed_pw_tlv   = find_tlv(tlvs, 0x0025)

		screen_name = screen_name_tlv.data.decode()

		major_tlv = find_tlv(tlvs, 0x0017)
		minor_tlv = find_tlv(tlvs, 0x0018)
		build_tlv = find_tlv(tlvs, 0x001A)

		major = Buffer(major_tlv.data).read_u16() if major_tlv else 0
		minor = Buffer(minor_tlv.data).read_u16() if minor_tlv else 0
		build = Buffer(build_tlv.data).read_u16() if build_tlv else 0

		version_str = '{}.{}.{}'.format(major, minor, build)
		context.client = Client('aim', version_str, context.client.via)

		self.logger.info('Screen Name (client-given):', screen_name)
		self.logger.info('Client version:', version_str)
		self.logger.info('Password (hashed):', hashed_pw_tlv.data)

		response_msg = SNACMessage(0x0017, 0x0003)

		error_code = None
		uuid = None

		if (uuid := context.backend.util_get_uuid_from_username(screen_name)) is None:
			error_code = LoginError.UnregisteredScreenname
			self.logger.info('Unregistered screenname')
		else:
			client_hash = hashed_pw_tlv.data

			pw_bucp1 = context.backend.user_service.aim_get_md5_password(screen_name)
			pw_bucp2 = context.backend.user_service.aim_get_md5_password_bucp2(screen_name)

			auth_ok = (pw_bucp1 is not None and pw_bucp1 == client_hash) or (pw_bucp2 is not None and pw_bucp2 == client_hash)

			if not auth_ok:
				error_code = LoginError.IncorrectPassword
				self.logger.info('Incorrect password')
			else:
				self.logger.info('Authenticated via', 'AIM5.x' if (pw_bucp2 == client_hash) else 'AIM3.5-4.8')

		response_msg.write_bytes(login(self.logger, context, tlvs, uuid, error_code))

		client.send_snac(response_msg)