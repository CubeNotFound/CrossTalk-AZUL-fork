import struct

from util.misc import Logger

from ..proto import names
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs, find_tlv

ADMIN_TLV_SCREEN_NAME = 0x0001
ADMIN_TLV_NEW_PASSWORD = 0x0002
ADMIN_TLV_URL = 0x0004
ADMIN_TLV_ERROR = 0x0008
ADMIN_TLV_EMAIL = 0x0011
ADMIN_TLV_OLD_PASSWORD = 0x0012
ADMIN_TLV_REG_STATUS = 0x0013

ADMIN_PERMISSIONS = 0x0003

ADMIN_ERROR_VALIDATE_NICKNAME = 0x0001
ADMIN_ERROR_INVALID_REG_PREFERENCE = 0x0009
ADMIN_ERROR_READ_ONLY_FIELD = 0x0010

CONFIRM_EMAIL_SENT = 0x0000
CONFIRM_ALREADY_CONFIRMED = 0x001E
CONFIRM_SERVER_ERROR = 0x0023

# registration status (how much of the account's e-mail the directory may give out): none, limited, full
REG_STATUSES = (0x0001, 0x0002, 0x0003)
AIM_REG_KEY = 'AIM_REG'


def _reply(subgroup: int, request_id: int, tlvs: list) -> SNACMessage:
	# ADMIN__INFO_REPLY and ADMIN__INFO_CHANGE_REPLY: u16 permissions, then a counted TLV block
	msg = SNACMessage(0x0007, subgroup, 0x0000, request_id)
	msg.write_u16(ADMIN_PERMISSIONS)
	msg.write_tlv_block(tlvs)
	return msg

def _error(subgroup: int, request_id: int, tag: int, code: int) -> SNACMessage:
	# a failed change carries the error code and a (blank) URL; a password change echoes the empty new password TLV first
	if tag == ADMIN_TLV_NEW_PASSWORD:
		return _reply(subgroup, request_id, [TLV(ADMIN_TLV_NEW_PASSWORD, b''), TLV(ADMIN_TLV_ERROR, struct.pack('>H', code))])
	return _reply(subgroup, request_id, [TLV(ADMIN_TLV_ERROR, struct.pack('>H', code)), TLV(ADMIN_TLV_URL, '')])


@Foodgroup(0x0007)
class AdminFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def info_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ADMIN__INFO_QUERY')

		user = context.user
		tlvs = unmarshal_tlvs(message.data)
		if find_tlv(tlvs, ADMIN_TLV_REG_STATUS) is not None:
			status = int(user.settings.get(AIM_REG_KEY, 0x0003))
			client.send_snac(_reply(0x0003, message.request_id, [TLV(ADMIN_TLV_REG_STATUS, struct.pack('>H', status))]))
		elif find_tlv(tlvs, ADMIN_TLV_EMAIL) is not None:
			client.send_snac(_reply(0x0003, message.request_id, [TLV(ADMIN_TLV_EMAIL, user.email or '')]))
		elif find_tlv(tlvs, ADMIN_TLV_SCREEN_NAME) is not None:
			client.send_snac(_reply(0x0003, message.request_id, [TLV(ADMIN_TLV_SCREEN_NAME, names.self_name(context.bs))]))
		else:
			client.ctrl.send_snac_error(0x0007, message.request_id, 0x0008)

	@Subgroup(0x0004)
	def info_change_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ADMIN__INFO_CHANGE_REQUEST')

		user = context.user
		tlvs = unmarshal_tlvs(message.data)

		if (sn_tlv := find_tlv(tlvs, ADMIN_TLV_SCREEN_NAME)) is not None:
			proposed = sn_tlv.data.decode('latin-1')
			# the screen name is the account's username, which is only changed from the website; asking for it as it is
			# already succeeds
			if names.normalize(proposed) != user.username.lower():
				client.send_snac(_error(0x0005, message.request_id, ADMIN_TLV_SCREEN_NAME, ADMIN_ERROR_VALIDATE_NICKNAME))
			elif proposed != user.username:
				client.send_snac(_error(0x0005, message.request_id, ADMIN_TLV_SCREEN_NAME, ADMIN_ERROR_READ_ONLY_FIELD))
			else:
				client.send_snac(_reply(0x0005, message.request_id, [TLV(ADMIN_TLV_SCREEN_NAME, user.username)]))
		elif find_tlv(tlvs, ADMIN_TLV_EMAIL) is not None:
			# the e-mail address belongs to the account, managed from the website
			client.send_snac(_error(0x0005, message.request_id, ADMIN_TLV_EMAIL, ADMIN_ERROR_READ_ONLY_FIELD))
		elif (reg_tlv := find_tlv(tlvs, ADMIN_TLV_REG_STATUS)) is not None and len(reg_tlv.data) >= 2:
			status = struct.unpack('>H', reg_tlv.data[:2])[0]
			if status not in REG_STATUSES:
				client.send_snac(_error(0x0005, message.request_id, ADMIN_TLV_REG_STATUS, ADMIN_ERROR_INVALID_REG_PREFERENCE))
				return
			user.settings[AIM_REG_KEY] = status
			context.backend._mark_modified(user)
			client.send_snac(_reply(0x0005, message.request_id, [TLV(ADMIN_TLV_REG_STATUS, struct.pack('>H', status))]))
		elif find_tlv(tlvs, ADMIN_TLV_NEW_PASSWORD) is not None:
			# so is the password: every protocol's copy of it is derived from the one set on the website
			client.send_snac(_error(0x0005, message.request_id, ADMIN_TLV_NEW_PASSWORD, ADMIN_ERROR_READ_ONLY_FIELD))
		else:
			client.ctrl.send_snac_error(0x0007, message.request_id, 0x0008)

	@Subgroup(0x0006)
	def account_confirm_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] ADMIN__ACCT_CONFIRM_REQUEST')

		# ADMIN__ACCT_CONFIRM_REPLY: u16 status, then a TLV (empty here); confirmation mails come from the website
		status = CONFIRM_ALREADY_CONFIRMED if getattr(context.user, 'account_verified', False) else CONFIRM_SERVER_ERROR
		reply = SNACMessage(0x0007, 0x0007, 0x0000, message.request_id)
		reply.write_u16(status)
		reply.write_tlv(TLV(0x0000, b''))
		client.send_snac(reply)
