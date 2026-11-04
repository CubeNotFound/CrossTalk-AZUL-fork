from core.client import Client
from util.misc import Logger
from util.hash import gen_salt

from ..proto import names
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
		screen_name = screen_name_tlv.data.decode('latin-1') if screen_name_tlv is not None else ''

		# ICQ signs on with its UIN, AIM with a screen name; the salt is the account's, whichever one the name means
		salt = None
		for uuid in (context.backend.util_get_uuids_for_login(screen_name) if names.valid_name(screen_name) else []):
			salt = context.backend.user_service.aim_get_md5_salt_by_uuid(uuid)
			if salt is not None:
				break

		if salt is None:
			# screen name doesn't exist or user did not enable OSCAR
			salt = gen_salt()

		response_msg = SNACMessage(0x0017, 0x0007, 0x0000, message.request_id)
		response_msg.write_u16(len(salt))
		response_msg.write_string(salt)

		self.logger.info('[Server] BUCP__CHALLENGE_RESPONSE (salt:', salt + ')')
		client.send_snac(response_msg)

	@Subgroup(0x0002)
	def login_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] BUCP__LOGIN_REQUEST')

		from ..ctrl import authenticate, client_version, multi_conn_flag

		tlvs = unmarshal_tlvs(message.data)

		screen_name_tlv = find_tlv(tlvs, 0x0001)
		hashed_pw_tlv   = find_tlv(tlvs, 0x0025)

		screen_name = screen_name_tlv.data.decode('latin-1') if screen_name_tlv is not None else ''
		client_hash = hashed_pw_tlv.data if hashed_pw_tlv is not None else b''

		version_str = client_version(tlvs)

		self.logger.info('Screen Name (client-given):', screen_name)
		self.logger.info('Client version:', version_str)
		self.logger.info('Password (hashed):', client_hash)

		response_msg = SNACMessage(0x0017, 0x0003, 0x0000, message.request_id)

		user_service = context.backend.user_service
		matched = {}

		def check(uuid: str) -> bool:
			pw_bucp1 = user_service.aim_get_md5_password_by_uuid(uuid)
			pw_bucp2 = user_service.aim_get_md5_password_bucp2_by_uuid(uuid)
			if pw_bucp2 is not None and pw_bucp2 and pw_bucp2 == client_hash:
				matched[uuid] = 'AIM5.x'
				return True
			if pw_bucp1 is not None and pw_bucp1 and pw_bucp1 == client_hash:
				matched[uuid] = 'AIM3.5-4.8'
				return True
			return False

		uuid, icq, error_code = authenticate(context.backend, screen_name, check)
		if error_code in (LoginError.UnregisteredScreenname, LoginError.ICQUserError):
			self.logger.info('Unregistered screenname')
		elif error_code == LoginError.IncorrectPassword:
			self.logger.info('Incorrect password')
		else:
			self.logger.info('Authenticated via', matched.get(uuid))

		context.client = Client('icq' if icq else 'aim', version_str, context.client.via)
		client.ctrl.client = context.client

		response_msg.write_bytes(login(self.logger, context, tlvs, uuid, error_code, icq = icq, multi_conn = multi_conn_flag(tlvs)))

		client.send_snac(response_msg)
