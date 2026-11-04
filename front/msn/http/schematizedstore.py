from typing import Optional, Any
from datetime import datetime
import secrets, base64, settings, util.misc
from aiohttp import web

from core import models
from core.backend import Backend
from util.avatar import get_img_type, find_avatar_file
from ..misc import cid_format
from .util import find_element, get_tag_localname, render, preprocess_soap, unknown_soap, storage_fault

def register(app: web.Application) -> None:
	# MSN >= 8
	app.router.add_post('/storageservice/SchematizedStore.asmx', handle_storageservice)

async def handle_storageservice(req: web.Request) -> web.Response:
	backend = req.app['backend']
	header, action, bs, token = await preprocess_soap(req)
	assert bs is not None
	soapaction = (req.headers.get('SOAPAction') or '')
	if soapaction.startswith('"') and soapaction.endswith('"'):
		soapaction = soapaction[1:-1]
	storage_ns = ('w10' if soapaction.startswith('http://www.msn.com/webservices/storage/w10/') else '2008')
	action_str = get_tag_localname(action)
	now_str = util.misc.date_format(datetime.utcnow())
	user = bs.user
	cachekey = secrets.token_urlsafe(172)
	
	cid = cid_format(user.uuid)
	
	if action_str == 'GetProfile':
		roaming_info = backend.user_service.get_roaming_info(user)
		assert roaming_info is not None

		# Resolve the active avatar using the md5 stored in users.avatar.
		# find_avatar_file returns None if no avatar has been uploaded yet.
		avatar_md5 = user.avatar
		mime		= None
		image_size  = 0
		image_thumb_size = 0

		if avatar_md5:
			full_file  = find_avatar_file(user.uuid, avatar_md5, small=False)
			thumb_file = find_avatar_file(user.uuid, avatar_md5, small=True)

			if full_file and full_file.is_file():
				ext  = full_file.suffix.lstrip('.').lower()
				mime = ext
				image_size = full_file.stat().st_size

			if thumb_file and thumb_file.is_file():
				image_thumb_size = thumb_file.stat().st_size

		return render(req, 'msn:storageservice/GetProfileResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
			'now': now_str,
			'mime': mime,
			'size_static': image_size,
			'size_small': image_thumb_size,
			'roaming_info': roaming_info,
			'host': settings.USERSTORAGE_HOST,
		})
	if action_str == 'FindDocuments':
		# TODO: FindDocuments
		return render(req, 'msn:storageservice/FindDocumentsResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
		})
	if action_str == 'UpdateProfile':
		delete_psm = False
		delete_name = False
		delete_avatar = False
		
		# TODO: More properties?
		
		# Update to roaming name/message
		# ```
		# <UpdateProfile xmlns="http://www.msn.com/webservices/storage/w10">
		#   <profile>
		#	 <ResourceID>862d987eb60b7a63!106</ResourceID>
		#	 <ExpressionProfile>
		#	   <FreeText>Update</FreeText>
		#	   <DisplayName>Society is betrayal</DisplayName>
		#	   <PersonalStatus>Prosperity is the best medicine. :)</PersonalStatus>
		#	 </ExpressionProfile>
		#   </profile>
		# </UpdateProfile>
		# ```
		
		# Remove roaming message
		# ```
		# <UpdateProfile xmlns="http://www.msn.com/webservices/storage/w10">
		#   <profile>
		#	 <ResourceID>bb4542ce2eacdbde!106</ResourceID>
		#	 <ExpressionProfile>
		#	   <FreeText>Update</FreeText>
		#	   <DisplayName>%walkingphas3r%</DisplayName>
		#	   <Flags>0</Flags>
		#	 </ExpressionProfile>
		#   </profile>
		#   <profileAttributesToDelete>
		#	 <ExpressionProfileAttributes>
		#	   <PersonalStatus>true</PersonalStatus>
		#	 </ExpressionProfileAttributes>
		#   </profileAttributesToDelete>
		# </UpdateProfile>
		# ```
		
		expression_profile = find_element(action, 'ExpressionProfile')
		name = find_element(expression_profile, 'DisplayName')
		message = find_element(expression_profile, 'PersonalStatus')
		
		attributes_to_delete = find_element(action, 'profileAttributesToDelete/ExpressionProfileAttributes')
		if attributes_to_delete is not None:
			# `PersonalStatus` and `DisplayName` is the only known attribute that has the ability to be deleted
			delete_psm = find_element(attributes_to_delete, 'PersonalStatus') or False
			delete_name = find_element(attributes_to_delete, 'DisplayName') or False
			if not (isinstance(delete_psm, bool) and isinstance(delete_name, bool)):
				return storage_fault(req, storage_ns, action_str, 'GeneralException')
		
		name = find_element(action, 'DisplayName')
		message = find_element(action, 'PersonalStatus')
		
		if name:
			backend.user_service.save_single_roaming(user, { 'name': name })
		if message and not delete_psm:
			if backend.user_service.save_single_roaming(user, { 'message': message }):
				backend.notify_whats_new(user)
		
		if delete_psm:
			backend.user_service.save_single_roaming(user, { 'message': '' })
		if delete_name:
			backend.user_service.save_single_roaming(user, { 'name': '' })
		
		return render(req, 'msn:storageservice/UpdateProfileResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user
		})
	if action_str == 'DeleteRelationships':
		# TODO: DeleteRelationships
		return render(req, 'msn:storageservice/DeleteRelationshipsResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
		})
	if action_str in ('CreateDocument', 'UpdateDocument'):
		op = 'Update' if action_str == 'UpdateDocument' else 'Create'
		return handle_document(req, action, op, storage_ns, user, cid, token, backend)
	if action_str == 'CreateRelationships':
		# TODO: CreateRelationships
		return render(req, 'msn:storageservice/CreateRelationshipsResponse.xml', {
			'storage_ns': storage_ns,
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
		})
	if action_str in { 'ShareItem' }:
		# TODO: ShareItem
		return unknown_soap(req, header, action, expected = True)
	return unknown_soap(req, header, action)


def handle_document(
	req: web.Request,
	action: Any,
	op_type: str,		  # 'Create' or 'Update'
	storage_ns: str,
	user: models.User,
	cid: str,
	token: str,
	backend: Backend,
) -> web.Response:
	streamtype = find_element(action, 'DocumentStreamType')

	if streamtype == 'UserTileStatic':
		raw_b64 = find_element(action, 'Data')
		if raw_b64:
			try:
				data = base64.b64decode(raw_b64)
			except Exception:
				return storage_fault(req, storage_ns, '{}Document'.format(op_type), 'InvalidDocumentStream')

			err = _store_avatar_from_bytes(backend, user, data)
			# stupid dumb doodoo hack to make avatar interop work
			# we compute a yahoo avatar hash so it can be displayed in yahoo as well
			# i'm sure there's a better approach but overengineering is funnier
			_yahoo_avatar_gaming(backend, user)
			if err is not None:
				return storage_fault(req, storage_ns, '{}Document'.format(op_type), err)

	return render(req, 'msn:storageservice/{}DocumentResponse.xml'.format(op_type), {
		'storage_ns': storage_ns,
		'cid': cid,
		'pptoken1': token,
		'user': user,
	})


def _store_avatar_from_bytes(
	backend: Backend,
	user: models.User,
	data: bytes,
) -> Optional[str]:
	# The storage fault (error code) if the picture can't be kept
	ext = get_img_type(data)
	if ext is None:
		# Not a picture (in a format that can be shown)
		return 'InvalidDocumentStream'

	avatar_old = user.avatar
	try:
		backend.user_service.save_avatar(user, data, ext)
	except Exception:
		import traceback
		traceback.print_exc()
		return 'GeneralException'
	if user.avatar != avatar_old:
		# A different picture is a new activity
		backend.notify_whats_new(user)

	return None

def _yahoo_avatar_gaming(backend: Backend, user: models.User) -> None:
	avatar_md5 = getattr(user, 'avatar', None)
	if not avatar_md5:
		return
	import struct, binascii
	raw = bytes.fromhex(avatar_md5)
	crc = binascii.crc32(raw) & 0xFFFFFFFF
	checksum_bytes = str(struct.unpack('i', struct.pack('I', crc))[0]).encode('utf-8')

	detail = user.detail
	if detail is None:
		return
	for ctc in detail.contacts.values():
		if not (ctc.lists & models.ContactList.FL) or ctc.status.is_offlineish():
			continue
		for bs_other in backend.util_get_sessions_by_user(ctc.head):
			if bs_other.front_data.get('ymsg'):
				bs_other.evt.ymsg_on_friend_icon(user.username, bs_other.user.username, checksum_bytes)
