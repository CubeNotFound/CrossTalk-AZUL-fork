import struct

from html import escape
from typing import Any, Dict, List, Optional, Tuple

from core.models import Substatus, User
from util.misc import Logger

from ..proto import names
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs, find_tlv
from ..proto.userinfo import build_userinfo, pick_session, AWAY_SUBSTATUSES

LOCATE_TYPE_PROFILE = 0x0001
LOCATE_TYPE_AWAY = 0x0002
LOCATE_TYPE_CAPABILITIES = 0x0004

OMITTED_CAPS = frozenset(bytes.fromhex(cap.replace('-', '')) for cap in (
	'0946134A-4C7F-11D1-8222-444553540000',
	'0946134D-4C7F-11D1-8222-444553540000',
	'09461341-4C7F-11D1-8222-444553540000',
))

AIM_DIR_KEY = 'AIM_DIR'

DIR_FIELDS = (0x0001, 0x0002, 0x0003, 0x0004, 0x0006, 0x0007, 0x0008, 0x000C, 0x000D, 0x0021)
DIR_INTEREST = 0x000B
MAX_INTERESTS = 5

DEFAULT_MIME = 'text/aolrtf; charset="us-ascii"'


def dir_info(user: User) -> Dict[str, Any]:
	store = user.settings.get(AIM_DIR_KEY)
	if not isinstance(store, dict):
		store = {}
		user.settings[AIM_DIR_KEY] = store
	return store

def dir_tlvs(user: User) -> List[TLV]:
	# what the directory shows for someone: what they set over OSCAR, else their account's own name and location
	store = dir_info(user)
	profile = user.profile
	fallback = {
		0x0001: user.first_name or '',
		0x0002: user.last_name or '',
		0x0006: (profile.country if profile is not None else None) or '',
		0x0007: (profile.state if profile is not None else None) or '',
		0x0008: (profile.city if profile is not None else None) or '',
		0x000D: str(profile.zip) if profile is not None and profile.zip else '',
	}
	tlvs = []
	for tag in DIR_FIELDS:
		value = store.get(str(tag), fallback.get(tag, ''))
		tlvs.append(TLV(tag, str(value).encode('latin-1', errors = 'replace')))
	return tlvs

def profile_of(user: User, bs: Any) -> Tuple[str, str]:
	# the profile an OSCAR client set this session, else the account's bio, else its status message
	stored = bs.front_data.get('oscar0_profile') if bs is not None else None
	if stored is not None:
		return stored
	bio = user.profile.bio if user.profile is not None else None
	return DEFAULT_MIME, escape(bio or user.status.message or '', quote = False).replace('\n', '<BR>')

def away_message_of(user: User, bs: Any) -> Optional[Tuple[str, str]]:
	if user.status.substatus not in AWAY_SUBSTATUSES:
		return None
	if bs is not None and bs.front_data.get('oscar0_away') is not None:
		return bs.front_data.get('oscar0_away_mime') or DEFAULT_MIME, bs.front_data['oscar0_away']
	return DEFAULT_MIME, escape(user.status.message or '', quote = False)

def user_info_reply(client: OSCARClient, context: OSCARContext, message: SNACMessage, query_type: int, name: str) -> None:
	# LOCATE__USER_INFO_REPLY: the USERINFO, then the profile/away message/capabilities TLVs that were asked for
	backend = context.backend
	viewer = context.bs
	target = names.resolve_user(backend, name)
	if target is None:
		client.ctrl.send_snac_error(0x0002, message.request_id, 0x0004)
		return

	if target is not viewer.user:
		from .icbm import _blocks
		if _blocks(backend, target, viewer.user) or _blocks(backend, viewer.user, target):
			client.ctrl.send_snac_error(0x0002, message.request_id, 0x0004)
			return
		if not backend.util_get_sessions_by_user(target) or target.status.is_offlineish():
			client.ctrl.send_snac_error(0x0002, message.request_id, 0x0004)
			return

	bs_target = viewer if target is viewer.user else pick_session(backend, target)
	reply = SNACMessage(0x0002, 0x0006, 0x0000, message.request_id)
	reply.write_bytes(build_userinfo(
		target, bs_target, name = names.name_for(viewer, target), viewer_icq = names.is_icq_session(viewer),
	))

	tlvs = []
	if query_type & LOCATE_TYPE_PROFILE:
		mime, text = profile_of(target, bs_target)
		tlvs.append(TLV(0x0001, mime))
		tlvs.append(TLV(0x0002, text))
	if query_type & LOCATE_TYPE_AWAY:
		away = away_message_of(target, bs_target)
		if away is not None:
			tlvs.append(TLV(0x0003, away[0]))
			tlvs.append(TLV(0x0004, away[1]))
	if query_type & LOCATE_TYPE_CAPABILITIES:
		caps = bs_target.front_data.get('oscar0_caps') if bs_target is not None else None
		if caps:
			tlvs.append(TLV(0x0005, b''.join(caps)))
	reply.write_tlvs(tlvs)
	client.send_snac(reply)


@Foodgroup(0x0002)
class LocateFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def client_versions(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] LOCATE__RIGHTS_QUERY')

		response_msg = SNACMessage(0x0002, 0x0003, 0x0000, message.request_id)

		# Response from NINA's servers:
		# ==
		# 0000   2a 02 00 07 00 28 00 02 00 03 00 00 00 00 00 02   *....(..........
		#		[FLAP Header....] [SNAC Header................]
		# 0010   00 01 00 02 10 00 00 02 00 02 00 80 00 03 00 02   ................
		#		[TLV 0x0001.....] [TLV 0x0002.....] [TLV 0x0003
		# 0020   00 1e 00 04 00 02 10 00 00 05 00 02 00 80		 ..............
		#		....] [TLV 0x0004.....] [TLV 0x0005.....]
		#
		# TLV 0x0001: client max profile len (data is 0x1000 = 256)
		# TLV 0x0002: max capabilities (CLSIDs) (data is 0x0080 = 128)
		# TLV 0x0003: unknown (data is 0x001E = 30)
		# TLV 0x0004: unknown (data is 0x1000 = 256)
		# TLV 0x0005: unknown (data is 0x0080 = 128)
		#
		response_msg.write_tlvs([
			TLV(0x0001, struct.pack('>H', 4096)),	# client max profile len
			TLV(0x0002, struct.pack('>H', 128)),	 # max capabilities (CLSIDs)
			TLV(0x0003, struct.pack('>H', 0x001E)),  # unknown
			TLV(0x0004, struct.pack('>H', 0x1000)),  # unknown
			TLV(0x0005, struct.pack('>H', 0x0080))   # unknown
		])

		self.logger.info('[Server] LOCATE__RIGHTS_REPLY')
		client.send_snac(response_msg)

	@Subgroup(0x0004)
	def set_info(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] LOCATE__SET_INFO')

		bs = context.bs
		tlvs = unmarshal_tlvs(message.data)
		profile_tlv = find_tlv(tlvs, 0x0002)   # user profile (HTML)
		away_tlv = find_tlv(tlvs, 0x0004)	  # away message (HTML), present while away
		caps_tlv = find_tlv(tlvs, 0x0005)	  # capability block, 16 bytes per capability
		profile_mime_tlv = find_tlv(tlvs, 0x0001)
		away_mime_tlv = find_tlv(tlvs, 0x0003)
		ready = bool(bs.front_data.get('oscar0_ready'))

		fields = {}
		if profile_tlv is not None:
			fields['message'] = profile_tlv.data.decode('utf-8', 'replace')
			mime = profile_mime_tlv.data.decode('latin-1') if profile_mime_tlv is not None else DEFAULT_MIME
			bs.front_data['oscar0_profile'] = (mime, fields['message'])

		# a tag with no data clears the thing it sets, a tag that isn't there changes nothing
		if caps_tlv is not None:
			caps = [
				caps_tlv.data[i:i + 16] for i in range(0, len(caps_tlv.data) - 15, 16)
			]
			caps = [cap for cap in caps if cap not in OMITTED_CAPS]
			if caps != bs.front_data.get('oscar0_caps') and ready:
				fields['needs_notify'] = True
				fields['notify_status'] = True
			bs.front_data['oscar0_caps'] = caps

		if away_tlv is not None:
			if away_tlv.data:
				bs.front_data['oscar0_away'] = away_tlv.data.decode('utf-8', 'replace')
				bs.front_data['oscar0_away_mime'] = away_mime_tlv.data.decode('latin-1') if away_mime_tlv is not None else DEFAULT_MIME
				fields['substatus'] = Substatus.Away
			else:
				bs.front_data.pop('oscar0_away', None)
				if context.user.status.substatus is Substatus.Away:
					fields['substatus'] = Substatus.Online

		# before OSERVICE__CLIENT_READY the client is only saying how it wants to come online
		if not ready:
			fields.pop('substatus', None)

		if fields:
			bs.me_update(fields)

	@Subgroup(0x0005)
	def user_info_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# u16 type (LOCATE_TYPE_*), string08 who
		query_type = message.read_u16()
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		self.logger.info('[Client] LOCATE__USER_INFO_QUERY for', name, '(type', hex(query_type) + ')')
		user_info_reply(client, context, message, query_type, name)

	@Subgroup(0x0015)
	def user_info_query2(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# the same query with a u32 type
		query_type = message.read_u32()
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		self.logger.info('[Client] LOCATE__USER_INFO_QUERY2 for', name, '(type', hex(query_type) + ')')
		user_info_reply(client, context, message, query_type & 0xFFFF, name)

	@Subgroup(0x0009)
	def set_dir_info(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] LOCATE__SET_DIR_INFO')

		# a TLV per ODIR field; whatever is sent replaces what was there
		store = dir_info(context.user)
		for tlv in unmarshal_tlvs(message.data):
			if tlv.type in DIR_FIELDS:
				store[str(tlv.type)] = tlv.data.decode('latin-1')
		context.backend._mark_modified(context.user)

		# LOCATE__SET_DIR_REPLY: u16 result, 1 for success
		reply = SNACMessage(0x0002, 0x000A, 0x0000, message.request_id)
		reply.write_u16(0x0001)
		self.logger.info('[Server] LOCATE__SET_DIR_REPLY')
		client.send_snac(reply)

	@Subgroup(0x000B)
	def get_dir_info(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] LOCATE__GET_DIR_INFO')

		screen_name = message.read_bytes(message.read_u8()).decode('latin-1')
		self.logger.info('[Client] Getting info for:', screen_name)

		# Response from NINA's servers:
		# ==
		# 0000   2A 02 00 0F 00 1A 00 02 00 0C 00 00 00 01 00 0B   *...............
		#		[FLAP Header....] [SNAC Header................]
		# 0010   00 01 00 01 00 1C 00 08 75 73 2D 61 73 63 69 69   ........us-ascii
		#		^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
		#
		# I have no idea what any of the values in the SNAC body mean, and the lack of documentation on NINA's wiki
		# don't help either: https://ninawiki.preloading.dev/wiki/Protocols/OSCAR/SNAC/LOCATE_GET_DIR_REPLY
		# (it's u16 status 1 (found), then a counted TLV block of ODIR fields; TLV 0x1C is the region/charset)
		response_msg = SNACMessage(0x0002, 0x000C, 0x0000, message.request_id)
		target = names.resolve_user(context.backend, screen_name)
		response_msg.write_u16(0x0001)
		tlvs = [TLV(0x001C, 'us-ascii')]
		if target is not None:
			tlvs = dir_tlvs(target) + tlvs
		response_msg.write_tlv_block(tlvs)

		self.logger.info('[Server] LOCATE__GET_DIR_REPLY')
		client.send_snac(response_msg)

	@Subgroup(0x000F)
	def set_keyword_info(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		self.logger.info('[Client] LOCATE__SET_KEYWORD_INFO')

		# up to five interests, TLV 0x0B each
		interests = [tlv.data.decode('latin-1') for tlv in unmarshal_tlvs(message.data) if tlv.type == DIR_INTEREST]
		dir_info(context.user)['interests'] = interests[:MAX_INTERESTS]
		context.backend._mark_modified(context.user)

		# LOCATE__SET_KEYWORD_REPLY: u16, 1
		reply = SNACMessage(0x0002, 0x0010, 0x0000, message.request_id)
		reply.write_u16(0x0001)
		self.logger.info('[Server] LOCATE__SET_KEYWORD_REPLY')
		client.send_snac(reply)
