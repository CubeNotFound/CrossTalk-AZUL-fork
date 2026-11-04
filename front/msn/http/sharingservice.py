from typing import Any, Optional
from datetime import datetime
import asyncio, secrets, sys, util.misc, settings

from aiohttp import web

from core import models, error
from core.backend import Backend, BackendSession

from .util import find_element, render, dispatch_abch, abch_fault, schema_fault

def register(app: web.Application) -> None:
	app.router.add_post('/abservice/SharingService.asmx', handle_sharingservice)

async def handle_sharingservice(req: web.Request) -> web.Response:
	return await dispatch_abch(req, sys.modules[__name__], 'sharing')

def sharing_FindMembership(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	now_str = util.misc.date_format(datetime.utcnow())
	user = bs.user
	detail = user.detail
	cachekey = secrets.token_urlsafe(172)
	return render(req, 'msn:sharing/FindMembershipResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
		'user': user,
		'detail': detail,
		'ContactList': models.ContactList,
		'lists': [models.ContactList.AL, models.ContactList.BL, models.ContactList.RL],
		'circles': backend.user_service.get_circle_batch(user),
		'now': now_str,
	})

def sharing_AddMember(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	memberships = action.findall('.//{*}memberships/{*}Membership')
	for membership in memberships:
		email = None # type: Optional[str]
		circle_id = None
		
		lst = models.ContactList.Parse(str(find_element(membership, 'MemberRole')))
		if lst is None:
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/AddMember')
		members = membership.findall('.//{*}Members/{*}Member')
		for member in members:
			member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
			if member_type == 'PassportMember':
				if find_element(member, 'Type') == 'Passport' and find_element(member, 'State') == 'Accepted':
					email = find_element(member, 'PassportName')
			elif member_type == 'EmailMember':
				if find_element(member, 'Type') == 'Email' and find_element(member, 'State') == 'Accepted':
					email = find_element(member, 'Email')
			elif member_type == 'CircleMember':
				if find_element(member, 'Type') == 'Circle' and find_element(member, 'State') == 'Accepted':
					circle_id = find_element(member, 'CircleId')
			if email is None and circle_id is None:
				return render(req, 'msn:sharing/Fault.userdoesnotexist.xml', status = 500)
			if email is not None:
				name = None
				contact_uuid = backend.util_get_uuid_from_email(email)
				if contact_uuid is None:
					return render(req, 'msn:sharing/Fault.userdoesnotexist.xml', status = 500)
				ctc = detail.contacts.get(contact_uuid)
				if ctc is None:
					name = email
				
				try:
					bs.me_contact_add(contact_uuid, lst, name = name)
				except error.ContactListIsFull:
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/AddMember', 'Contact list is full')
				except:
					pass
			elif circle_id is not None:
				if not (circle_id.startswith('00000000-0000-0000-0009-') and len(circle_id[24:]) == 12):
					return render(req, 'msn:sharing/Fault.userdoesnotexist.xml', status = 500)
				chat_id = circle_id[-12:]
				circle = backend.user_service.get_circle(chat_id)
				if circle is None: return abch_fault(req, 'AddMember', 'UserDoesNotExist')
				
				if lst in (models.ContactList.RL,models.ContactList.PL):
					# Only the service puts anyone on those
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/AddMember')
				if lst == models.ContactList.BL:
					bs.me_block_circle(circle)
	return render(req, 'msn:sharing/AddMemberResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def sharing_DeleteMember(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	contact_uuid = None
	circle_id = None
	
	memberships = action.findall('.//{*}memberships/{*}Membership')
	for membership in memberships:
		lst = models.ContactList.Parse(str(find_element(membership, 'MemberRole')))
		if lst is None:
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/DeleteMember')
		members = membership.findall('.//{*}Members/{*}Member')
		for member in members:
			member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
			if member_type == 'PassportMember':
				if find_element(member, 'Type') == 'Passport' and find_element(member, 'State') == 'Accepted':
					try:
						contact_uuid = find_element(member, 'MembershipId').split('/', 1)[1]
					except:
						email = find_element(member, 'PassportName')
						contact_uuid = backend.util_get_uuid_from_email(email or '')
					if contact_uuid is None:
						return abch_fault(req, 'DeleteMember', 'MemberDoesNotExist')
			# (A circle member is one too, not a kind of Passport member)
			elif member_type == 'CircleMember':
				if find_element(member, 'Type') == 'Circle' and find_element(member, 'State') == 'Accepted':
					circle_id = find_element(member, 'CircleId')
			if contact_uuid is not None:
				if contact_uuid not in detail.contacts:
					return render(req, 'msn:sharing/Fault.memberdoesnotexist.xml', status = 500)
				try:
					bs.me_contact_remove(contact_uuid, lst)
				except:
					pass
			elif circle_id is not None:
				if not (circle_id.startswith('00000000-0000-0000-0009-') and len(circle_id[24:]) == 12):
					return abch_fault(req, 'DeleteMember', 'MemberDoesNotExist')
				chat_id = circle_id[-12:]
				circle = backend.user_service.get_circle(chat_id)
				if circle is None: return abch_fault(req, 'DeleteMember', 'MemberDoesNotExist')
				
				if lst in (models.ContactList.RL,models.ContactList.PL):
					# Only the service takes anyone off those; there's nothing to do
					continue
				if lst == models.ContactList.BL:
					bs.me_unblock_circle(circle)
	return render(req, 'msn:sharing/DeleteMemberResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def sharing_CreateCircle(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	
	if (
		find_element(action, 'Domain') == 1
		and find_element(action, 'HostedDomain') == 'live.com'
		and find_element(action, 'Type') == 2
		and isinstance(find_element(action, 'IsPresenceEnabled'), bool)
	):
		membership_access = int(find_element(action, 'MembershipAccess'))
		name = str(find_element(action, 'DisplayName'))
		owner_friendly = str(find_element(action, 'PublicDisplayName'))
		
		circle = bs.me_create_circle(name, owner_friendly, membership_access)
		
		backend.loop.create_task(_dispatch_circle_created(backend, user, circle))
		
		return render(req, 'msn:sharing/CreateCircleResponse.xml', {
			'cachekey': cachekey,
			'host': settings.ADDRESSBOOK_HOST,
			'session_id': util.misc.gen_uuid(),
			'chat_id': circle.chat_id,
		})
	
	return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/CreateCircle')

async def _dispatch_circle_created(backend: Backend, user: models.User, circle: models.Circle) -> None:
	await asyncio.sleep(0.04)
	for sess in backend.util_get_sessions_by_user(user):
		sess.evt.on_circle_created(circle)
