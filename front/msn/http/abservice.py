from typing import Any
from enum import IntEnum
from datetime import datetime
import asyncio, secrets, sys, util.misc, settings

from aiohttp import web
from dateutil import parser as iso_parser
from markupsafe import Markup

from core import models, error
from core.backend import Backend, BackendSession, MAX_GROUP_NAME_LENGTH

from .util import find_element, render, bool_to_str, dispatch_abch, abch_fault, schema_fault, server_fault
from ..misc import gen_signedticket_xml

def register(app: web.Application) -> None:
	app.router.add_post('/abservice/abservice.asmx', handle_abservice)

async def handle_abservice(req: web.Request) -> web.Response:
	return await dispatch_abch(req, sys.modules[__name__], 'ab')


def ab_ABFindAll(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	now_str = util.misc.date_format(datetime.utcnow())
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABFindAll', 'ABDoesNotExist')
	
	return render(req, 'msn:abservice/ABFindAllResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
		'ContactList': models.ContactList,
		'user': user,
		'detail': user.detail,
		'now': now_str,
		'ab_id': ab_id,
	})

def ab_ABFindContactsPaged(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	now_str = util.misc.date_format(datetime.utcnow())
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	circle = None
	
	ab_id = find_element(action, 'ABId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	try:
		if not (ab_id == '00000000-0000-0000-0000-000000000000' or (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12)):
			return abch_fault(req, 'ABFindContactsPaged', 'ABDoesNotExist')
	except:
		return abch_fault(req, 'ABFindContactsPaged', 'ABDoesNotExist')
	
	if ab_id == '00000000-0000-0000-0000-000000000000':
		ab_type = 'Individual'
	else:
		ab_type = 'Group'
		chat_id = ab_id[-12:]
		circle = backend.user_service.get_circle(chat_id)
		# A circle's address book is only there for its members
		if circle is None or user.uuid not in circle.memberships:
			return abch_fault(req, 'ABFindContactsPaged', 'ABDoesNotExist')
	
	circles = [
		circle
		for circle in backend.user_service.get_circle_batch(user)
		if not (
			circle.memberships[user.uuid].role == models.CircleRole.Empty
			or circle.memberships[user.uuid].state == models.CircleState.Empty
		)
	]
	
	return render(req, 'msn:abservice/ABFindContactsPagedResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
		'ContactList': models.ContactList,
		'user': user,
		'detail': user.detail,
		'now': now_str,
		'circles': circles,
		'circle': circle,
		'CircleRole': models.CircleRole,
		'CircleState': models.CircleState,
		'signedticket': Markup(gen_signedticket_xml(bs, backend).replace('<', '&lt;').replace('>', '&gt;')),
		'ab_id': ab_id,
		'ab_type': ab_type,
	})

def ab_ABContactAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	nickname = None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABContactAdd', 'ABDoesNotExist')
	
	contact = find_element(action, 'contacts/Contact')
	
	if contact is None:
		return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactAdd')
	
	type = find_element(contact, 'contactType') or 'LivePending'
	email = find_element(contact, 'passportName') or ''
	if '@' not in email:
		return render(req, 'msn:abservice/Fault.emailmissingatsign.xml', status = 500)
	elif '.' not in email:
		return render(req, 'msn:abservice/Fault.emailmissingdot.xml', status = 500)
	
	contact_uuid = backend.util_get_uuid_from_email(email)
	if contact_uuid is None:
		return render(req, 'msn:abservice/Fault.invaliduser.xml', {
			'action_str': 'ABContactAdd',
			'email': email,
		}, status = 500)
	
	annotations = contact.findall('.//{*}annotations/{*}Annotation')
	if annotations:
		for annotation in annotations:
			name = find_element(annotation, 'Name')
			if name not in _ANNOTATION_NAMES:
				return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactAdd')
			value = find_element(annotation, 'Value')
			if name == 'AB.NickName':
				nickname = value
	
	add_ctc = False
	
	ctc = detail.contacts.get(contact_uuid)
	if ctc is not None:
		if not ctc.lists & models.ContactList.FL:
			add_ctc = True
	else:
		add_ctc = True
	
	if add_ctc:
		try:
			bs.me_contact_add(contact_uuid, models.ContactList.FL, name = email, nickname = nickname)
		except error.ContactListIsFull:
			# TODO
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactAdd', 'Contact list is full')
		except:
			pass
	
	return render(req, 'msn:abservice/ABContactAddResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
		'contact_uuid': contact_uuid,
	})

def ab_CreateContact(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	email = str(find_element(action, 'contactHandle/Email') or '')
	if '@' not in email:
		return render(req, 'msn:abservice/Fault.emailmissingatsign.xml', status = 500)
	elif '.' not in email:
		return render(req, 'msn:abservice/Fault.emailmissingdot.xml', status = 500)
	
	contact_uuid = backend.util_get_uuid_from_email(email)
	if contact_uuid is None:
		return render(req, 'msn:abservice/Fault.invaliduser.xml', {
			'action_str': 'CreateContact',
			'email': email,
		}, status = 500)
	head = backend._load_user_record(contact_uuid)
	if head is None:
		return abch_fault(req, 'CreateContact', 'InvalidPassportUser')

	ab_id = str(find_element(action, 'abHandle/ABId') or '00000000-0000-0000-0000-000000000000').lower()
	if ab_id != '00000000-0000-0000-0000-000000000000':
		if not (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12):
			return abch_fault(req, 'CreateContact', 'ABDoesNotExist')
		circle = backend.user_service.get_circle(ab_id[-12:])
		if circle is None or user.uuid not in circle.memberships:
			return abch_fault(req, 'CreateContact', 'ABDoesNotExist')
		caller_membership = circle.memberships[user.uuid]
		if contact_uuid not in circle.memberships and caller_membership.role in (models.CircleRole.Admin, models.CircleRole.AssistantAdmin):
			bs.me_add_user_to_circle(circle, head)
		return render(req, 'msn:abservice/CreateContactResponse.xml', {
			'cachekey': cachekey,
			'host': settings.ADDRESSBOOK_HOST,
			'session_id': util.misc.gen_uuid(),
			'head': head,
			'user': user,
			'now': util.misc.date_format(datetime.utcnow()),
			'trust_level': 0,
		})

	nickname = None
	for annotation in action.findall('.//{*}contactInfo/{*}annotations/{*}Annotation'):
		if find_element(annotation, 'Name') == 'AB.NickName':
			nickname = find_element(annotation, 'Value')
	
	ctc = detail.contacts.get(contact_uuid)
	if ctc is None or not ctc.lists & models.ContactList.FL:
		try:
			bs.me_contact_add(contact_uuid, models.ContactList.FL, name = email, nickname = nickname)
		except error.ContactListIsFull:
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/CreateContact', 'Contact list is full')
		except:
			pass
	
	trust_level = find_element(action, 'contactInfo/TrustLevel')
	if trust_level is not None:
		try:
			user.settings['TrustLevels'] = { **(user.settings.get('TrustLevels') or {}), contact_uuid: int(trust_level) }
		except (TypeError, ValueError):
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/CreateContact')
		backend._mark_modified(user)
	
	return render(req, 'msn:abservice/CreateContactResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
		'head': head,
		'user': user,
		'now': util.misc.date_format(datetime.utcnow()),
		'trust_level': (user.settings.get('TrustLevels') or {}).get(contact_uuid, 0),
	})

def ab_ABContactDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABContactDelete', 'ABDoesNotExist')
	
	contacts = action.findall('.//{*}contacts/{*}Contact')
	for contact in contacts:
		contact_uuid = find_element(contact, 'contactId')
		assert contact_uuid is not None
		try:
			bs.me_contact_remove(contact_uuid, models.ContactList.FL)
		except:
			pass
	return render(req, 'msn:abservice/ABContactDeleteResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABContactUpdate(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABContactUpdate', 'ABDoesNotExist')
	
	contacts = action.findall('.//{*}contacts/{*}Contact')
	for contact in contacts:
		ctc = None
		contact_info = find_element(contact, 'contactInfo')
		if find_element(contact_info, 'contactType') == 'Me':
			contact_uuid = user.uuid
		else:
			contact_uuid = find_element(contact, 'contactId')
		if not contact_uuid:
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
		if contact_uuid is not user.uuid:
			ctc = detail.contacts.get(contact_uuid)
			if not ctc:
				return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
					'action_str': 'ABContactUpdate',
				}, status = 500)
		properties_changed = contact.find('./{*}propertiesChanged')
		if not properties_changed:
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
		properties_changed = str(properties_changed).strip().split(' ')
		for contact_property in properties_changed:
			if contact_property not in _CONTACT_PROPERTIES:
				return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
		
		for contact_property in properties_changed:
			if contact_property == 'Anniversary':
				assert ctc is not None
				property = find_element(contact_info, 'Anniversary')
				# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
				try:
					if property not in (None,-1):
						property = str(property)
						property = datetime.strptime(property, '%Y/%m/%d')
				except:
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
			if contact_property == 'ContactBirthDate':
				assert ctc is not None
				property = find_element(contact_info, 'birthdate')
				try:
					if property is not None:
						property = str(property)
						if property != '0001-01-01T00:00:00':
							if not property.endswith('Z'):
								return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
							property = iso_parser.parse(property)
				except:
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
			if contact_property == 'ContactLocation':
				assert ctc is not None
				contact_locations = contact_info.findall('.//{*}locations/{*}ContactLocation')
				for contact_location in contact_locations:
					if str(find_element(contact_location, 'contactLocationType')) not in ('ContactLocationPersonal','ContactLocationBusiness'):
						return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
					location_properties_changed = find_element(contact_location, 'Changes')
					if location_properties_changed is None:
						return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
					location_properties_changed = str(location_properties_changed).strip().split(' ')
					for location_property in location_properties_changed:
						if location_property not in _CONTACT_LOCATION_PROPERTIES:
							return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
					for location_property in location_properties_changed:
						if location_property == 'Name' and str(find_element(contact_location, 'contactLocationType')) != 'ContactLocationBusiness':
							return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
			if contact_property == 'IsMessengerUser':
				assert ctc is not None
				property = find_element(contact_info, 'isMessengerUser')
				if property is None:
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
			if contact_property == 'ContactEmail':
				assert ctc is not None
				contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
				for contact_email in contact_emails:
					email_properties_changed = find_element(contact_email, 'propertiesChanged')
					if email_properties_changed is None:
						return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
					email_properties_changed = str(email_properties_changed).strip().split(' ')
					for email_property in email_properties_changed:
						if email_property not in _CONTACT_EMAIL_PROPERTIES:
							return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
					if (
						str(find_element(contact_email, 'contactEmailType')) not in (
							'ContactEmailPersonal', 'ContactEmailBusiness', 'ContactEmailMessenger', 'ContactEmailOther',
						)
					):
						return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
			if contact_property == 'ContactPrimaryEmailType':
				assert ctc is not None
				email_primary_type = str(find_element(contact_info, 'primaryEmailType'))
				if email_primary_type not in ('Passport','ContactEmailPersonal','ContactEmailBusiness','ContactEmailOther'):
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
			if contact_property == 'ContactPhone':
				assert ctc is not None
				contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
				for contact_phone in contact_phones:
					phone_properties_changed = find_element(contact_phone, 'propertiesChanged')
					if phone_properties_changed is None:
						return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
					phone_properties_changed = str(phone_properties_changed).strip().split(' ')
					for phone_property in phone_properties_changed:
						if phone_property not in _CONTACT_PHONE_PROPERTIES:
							return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
					if (
						str(find_element(contact_phone, 'contactPhoneType')) not in (
							'ContactPhonePersonal', 'ContactPhoneBusiness', 'ContactPhoneMobile', 'ContactPhoneFax', 'ContactPhonePager', 'ContactPhoneOther',
						)
					):
						return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
			if contact_property == 'ContactWebSite':
				assert ctc is not None
				contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
				for contact_website in contact_websites:
					if str(find_element(contact_website, 'contactWebSiteType')) not in ('ContactWebSitePersonal','ContactWebSiteBusiness'):
						return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
			if contact_property == 'Annotation':
				if find_element(contact_info, 'contactType') != 'Me':
					if ctc is None:
						return abch_fault(req, 'ABContactUpdate', 'ContactDoesNotExist')
				annotations = contact_info.findall('.//{*}annotations/{*}Annotation')
				for annotation in annotations:
					name = find_element(annotation, 'Name')
					#if name not in _ANNOTATION_NAMES:
					#	return web.HTTPInternalServerError()
					value = find_element(annotation, 'Value')
					value = bool_to_str(value) if isinstance(value, bool) else str(find_element(annotation, 'Value'))
					
					if name == 'MSN.IM.GTC':
						try:
							if value == '':
								gtc = GTCAnnotation.Empty
							else:
								gtc = GTCAnnotation(int(value))
						except ValueError:
							return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
					if name == 'MSN.IM.BLP':
						try:
							if value == '':
								blp = BLPAnnotation.Empty
							else:
								blp = BLPAnnotation(int(value))
						except ValueError:
							return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABContactUpdate')
		if find_element(contact_info, 'contactType') != 'Me':
			if ctc is None:
				return abch_fault(req, 'ABContactUpdate', 'ContactDoesNotExist')
	for contact in contacts:
		updated = False
		ctc = None
		contact_info = find_element(contact, 'contactInfo')
		if find_element(contact_info, 'contactType') == 'Me':
			contact_uuid = user.uuid
		else:
			contact_uuid = find_element(contact, 'contactId')
		if contact_uuid is not user.uuid and contact_uuid is not None:
			ctc = detail.contacts.get(contact_uuid)
		properties_changed = str(contact.find('./{*}propertiesChanged')).strip().split(' ')
		
		for contact_property in properties_changed:
			if contact_property == 'ContactFirstName':
				assert ctc is not None
				property = find_element(contact_info, 'firstName')
				ctc.detail.first_name = property
				updated = True
			if contact_property == 'ContactLastName':
				assert ctc is not None
				property = find_element(contact_info, 'lastName')
				ctc.detail.last_name = property
				updated = True
			# TODO: `ContactQuickName`
			# <ABContactUpdate xmlns="http://www.msn.com/webservices/AddressBook">
			#   <abId>00000000-0000-0000-0000-000000000000</abId>
			#   <contacts>
			#	 <Contact xmlns="http://www.msn.com/webservices/AddressBook">
			#		<contactId>074606e9-00c5-4ccc-ba6c-b638c4b1547f</contactId>
			#		<contactInfo>
			#		   <quickName>BobRoss 1</quickName>
			#		</contactInfo>
			#		<propertiesChanged>ContactQuickName</propertiesChanged>
			#	 </Contact>
			#   </contacts>
			# </ABContactUpdate>
			if contact_property == 'MiddleName':
				assert ctc is not None
				property = find_element(contact_info, 'MiddleName')
				ctc.detail.middle_name = property
				updated = True
			if contact_property == 'Anniversary':
				assert ctc is not None
				property = find_element(contact_info, 'Anniversary')
				# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
				if property not in (None,-1):
					property = str(property)
					property = datetime.strptime(property, '%Y/%m/%d')
				if property == -1:
					property = None
				ctc.detail.anniversary = property
				updated = True
			if contact_property == 'ContactBirthDate':
				assert ctc is not None
				property = find_element(contact_info, 'birthdate')
				if property is not None:
					property = str(property)
					if property != '0001-01-01T00:00:00':
						property = iso_parser.parse(property)
					else:
						property = None
				ctc.detail.birthdate = property
				updated = True
			if contact_property == 'Comment':
				assert ctc is not None
				property = find_element(contact_info, 'comment')
				if property is not None:
					property = str(property)
				ctc.detail.notes = property
				updated = True
			if contact_property == 'ContactLocation':
				assert ctc is not None
				contact_locations = contact_info.findall('.//{*}locations/{*}ContactLocation')
				for contact_location in contact_locations:
					contact_location_type = str(find_element(contact_location, 'contactLocationType'))
					location_properties_changed = str(find_element(contact_location, 'Changes')).strip().split(' ')
					if contact_location_type not in ctc.detail.locations:
						ctc.detail.locations[contact_location_type] = models.ContactLocation(contact_location_type)
					for location_property in location_properties_changed:
						if location_property == 'Name':
							property = find_element(contact_location, 'name')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].name = property
							updated = True
						if location_property == 'Street':
							property = find_element(contact_location, 'street')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].street = property
							updated = True
						if location_property == 'City':
							property = find_element(contact_location, 'city')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].city = property
							updated = True
						if location_property == 'State':
							property = find_element(contact_location, 'state')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].state = property
							updated = True
						if location_property == 'Country':
							property = find_element(contact_location, 'country')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].country = property
							updated = True
						if location_property == 'PostalCode':
							property = find_element(contact_location, 'postalCode')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].zip_code = property
							updated = True
					if (
						ctc.detail.locations[contact_location_type].street is None
						and ctc.detail.locations[contact_location_type].city is None
						and ctc.detail.locations[contact_location_type].state is None
						and ctc.detail.locations[contact_location_type].country is None
						and ctc.detail.locations[contact_location_type].zip_code is None
					):
						del ctc.detail.locations[contact_location_type]
						updated = True
			if contact_property == 'IsMessengerUser':
				assert ctc is not None
				property = find_element(contact_info, 'isMessengerUser')
				ctc.is_messenger_user = property
				updated = True
			if contact_property == 'ContactEmail':
				assert ctc is not None
				contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
				for contact_email in contact_emails:
					email_properties_changed = str(find_element(contact_email, 'propertiesChanged')).strip().split(' ')
					for email_property in email_properties_changed:
						if email_property == 'Email':
							email = contact_email.find('./{*}email')
							if email is not None:
								email = str(email)
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailPersonal':
								ctc.detail.personal_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailBusiness':
								ctc.detail.work_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailMessenger':
								ctc.detail.im_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailOther':
								ctc.detail.other_email = email
							updated = True
			if contact_property == 'ContactPrimaryEmailType':
				assert ctc is not None
				email_primary_type = str(find_element(contact_info, 'primaryEmailType'))
				ctc.detail.primary_email_type = email_primary_type
				updated = True
			if contact_property == 'ContactPhone':
				assert ctc is not None
				contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
				for contact_phone in contact_phones:
					phone_properties_changed = str(find_element(contact_phone, 'propertiesChanged')).strip().split(' ')
					for phone_property in phone_properties_changed:
						if phone_property == 'Number':
							phone_number = contact_phone.find('./{*}number')
							if phone_number is not None:
								phone_number = str(phone_number)
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePersonal':
								ctc.detail.home_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneBusiness':
								ctc.detail.work_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneFax':
								ctc.detail.fax_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePager':
								ctc.detail.pager_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneMobile':
								ctc.detail.mobile_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneOther':
								ctc.detail.other_phone = phone_number
							updated = True
			if contact_property == 'ContactWebSite':
				assert ctc is not None
				contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
				for contact_website in contact_websites:
					contact_website_type = str(find_element(contact_website, 'contactWebSiteType'))
					website = str(find_element(contact_website, 'webURL'))
					if contact_website_type == 'ContactWebSitePersonal':
						ctc.detail.personal_website = website
					if contact_website_type == 'ContactWebSiteBusiness':
						ctc.detail.business_website = website
					updated = True
			if contact_property == 'Annotation':
				if contact_uuid is not None:
					if find_element(contact_info, 'contactType') != 'Me' and not ctc:
						continue
				else:
					continue
				annotations = contact_info.findall('.//{*}annotations/{*}Annotation')
				for annotation in annotations:
					name = find_element(annotation, 'Name')
					value = find_element(annotation, 'Value')
					value = bool_to_str(value) if isinstance(value, bool) else str(find_element(annotation, 'Value'))
					
					if name == 'MSN.IM.GTC':
						if value == '':
							gtc = GTCAnnotation.Empty
						else:
							gtc = GTCAnnotation(int(value))
						
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'gtc': None if gtc is GTCAnnotation.Empty else gtc.name })
						continue
					if name == 'MSN.IM.BLP':
						if value == '':
							blp = BLPAnnotation.Empty
						else:
							blp = BLPAnnotation(int(value))
						
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'blp': None if blp is BLPAnnotation.Empty else blp.name })
						continue
					if name == 'MSN.IM.MPOP':
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'mpop': None if value in ('', None) else value })
						continue
					if name == 'MSN.IM.RoamLiveProperties':
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'rlp': value })
						continue
					if name == 'MSN.IM.HasSharedFolder':
						# This will have to be stored in `_front_data` somehow. Ignore for now
						continue
					if name == 'AB.NickName':
						if ctc:
							ctc.detail.nickname = value
							updated = True
						continue
					if name == 'Live.Profile.Expression.LastChanged':
						# TODO: What's this used for?
						continue
		if updated:
			backend._mark_modified(user)
	
	return render(req, 'msn:abservice/ABContactUpdateResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})


def ab_UpdateContact(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	from lxml import etree
	from lxml.objectify import fromstring as parse_xml
	
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	contact_uuid = str(find_element(action, 'contactId') or '')
	contact_info = action.find('./{*}contactInfo')
	if contact_info is None:
		return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/UpdateContact')
	if contact_uuid != user.uuid and contact_uuid not in detail.contacts:
		return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
			'action_str': 'UpdateContact',
		}, status = 500)
	
	properties_changed = str(find_element(contact_info, 'PropertiesChanged') or '').strip().split()
	
	if 'TrustLevel' in properties_changed:
		try:
			trust_level = int(find_element(contact_info, 'TrustLevel'))
		except (TypeError, ValueError):
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/UpdateContact')
		user.settings['TrustLevels'] = { **(user.settings.get('TrustLevels') or {}), contact_uuid: trust_level }
		backend._mark_modified(user)
	
	properties_changed = [contact_property for contact_property in properties_changed if contact_property != 'TrustLevel']
	if properties_changed:
		contact_info_elm = etree.fromstring(etree.tostring(contact_info))
		for elm in contact_info_elm.findall('{*}PropertiesChanged') + contact_info_elm.findall('{*}TrustLevel'):
			contact_info_elm.remove(elm)
		if contact_uuid == user.uuid and contact_info_elm.find('{*}contactType') is None:
			# `ABContactUpdate` addresses the user's own contact by its type
			etree.SubElement(contact_info_elm, '{http://www.msn.com/webservices/AddressBook}contactType').text = 'Me'
		response = ab_ABContactUpdate(req, header, parse_xml(
			b'<ABContactUpdate xmlns="http://www.msn.com/webservices/AddressBook"><abId>00000000-0000-0000-0000-000000000000</abId><contacts><Contact>'
			+ '<contactId>{}</contactId>'.format(contact_uuid).encode('utf-8') + etree.tostring(contact_info_elm)
			+ '<propertiesChanged>{}</propertiesChanged>'.format(' '.join(properties_changed)).encode('utf-8')
			+ b'</Contact></contacts></ABContactUpdate>'
		), bs)
		if response.status != 200:
			return response
	
	return render(req, 'msn:abservice/UpdateContactResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABGroupAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABGroupAdd', 'ABDoesNotExist')
	
	name = find_element(action, 'name')
	is_favorite = find_element(action, 'IsFavorite')
	assert isinstance(is_favorite, bool) or is_favorite is None
	
	if name == '(No Group)':
		return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	if len(name) > MAX_GROUP_NAME_LENGTH:
		return render(req, 'msn:abservice/Fault.groupnametoolong.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	if detail.get_groups_by_name(name):
		return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	group = bs.me_group_add(name, is_favorite = is_favorite)
	return render(req, 'msn:abservice/ABGroupAddResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
		'group_id': group.uuid,
	})

def ab_ABGroupUpdate(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABGroupUpdate', 'ABDoesNotExist')
	
	groups = action.findall('.//{*}groups/{*}Group')
	for group_elm in groups:
		group_id = str(find_element(group_elm, 'groupId'))
		if group_id not in detail._groups_by_uuid:
			return abch_fault(req, 'ABGroupUpdate', 'GroupDoesNotExist')
		group_info = group_elm.find('.//{*}groupInfo')
		properties_changed = find_element(group_elm, 'propertiesChanged')
		if not properties_changed:
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABGroupUpdate')
		properties_changed = str(properties_changed).strip().split(' ')
		#for contact_property in properties_changed:
		#	if contact_property not in _CONTACT_PROPERTIES:
		#		return web.HTTPInternalServerError()
		for contact_property in properties_changed:
			if contact_property == 'GroupName':
				name = str(find_element(group_info, 'name'))
				if name is None:
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABGroupUpdate')
				elif name == '(No Group)':
					return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
						'action_str': 'ABGroupUpdate',
					}, status = 500)
				elif len(name) > MAX_GROUP_NAME_LENGTH:
					return render(req, 'msn:abservice/Fault.groupnametoolong.xml', {
						'action_str': 'ABGroupUpdate',
					}, status = 500)
				
				if detail.get_groups_by_name(name):
					return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
						'action_str': 'ABGroupUpdate',
					}, status = 500)
			is_favorite = find_element(group_info, 'IsFavorite')
			if is_favorite is not None:
				if not isinstance(is_favorite, bool):
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABGroupUpdate')
	for group_elm in groups:
		group_id = str(find_element(group_elm, 'groupId'))
		group_info = group_elm.find('.//{*}groupInfo')
		properties_changed = find_element(group_elm, 'propertiesChanged')
		properties_changed = str(properties_changed).strip().split(' ')
		for contact_property in properties_changed:
			if contact_property == 'GroupName':
				name = str(find_element(group_info, 'name'))
				bs.me_group_edit(group_id, new_name = name)
			# What's the `propertiesChanged` value for the favourite setting? Check for the node for now
			is_favorite = find_element(group_info, 'IsFavorite')
			if is_favorite is not None:
				bs.me_group_edit(group_id, is_favorite = is_favorite)
	return render(req, 'msn:abservice/ABGroupUpdateResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABGroupDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABGroupDelete', 'ABDoesNotExist')
	
	group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
	for group_id in group_ids:
		if group_id not in detail._groups_by_uuid:
			return abch_fault(req, 'ABGroupDelete', 'GroupDoesNotExist')
	for group_id in group_ids:
		bs.me_group_remove(group_id)
	return render(req, 'msn:abservice/ABGroupDeleteResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABGroupContactAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABGroupContactAdd', 'ABDoesNotExist')
	
	group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
	
	for group_id in group_ids:
		if group_id not in detail._groups_by_uuid:
			return abch_fault(req, 'ABGroupContactAdd', 'GroupDoesNotExist')
	
	if find_element(action, 'contactInfo') is not None:
		email = find_element(action, 'passportName')
		if email is None:
			email = find_element(action, 'email')
			if email is None:
				return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ABGroupContactAdd')
		contact_uuid = backend.util_get_uuid_from_email(email)
		if contact_uuid is None:
			return render(req, 'msn:abservice/Fault.invaliduser.xml', {
				'action_str': 'ABGroupContactAdd',
				'email': email,
			}, status = 500)
		
		ctc = detail.contacts.get(contact_uuid)
		if ctc is not None and ctc.lists & models.ContactList.FL:
			for group_id in group_ids:
				for group_contact_entry in ctc._groups:
					if group_contact_entry.uuid == group_id:
						return abch_fault(req, 'ABGroupContactAdd', 'ContactAlreadyExists')
		
		for group_id in group_ids:
			try:
				ctc, _ = bs.me_contact_add(contact_uuid, models.ContactList.FL, group_id = group_id, name = email)
			except:
				return server_fault(req, 'http://www.msn.com/webservices/AddressBook/ABGroupContactAdd')
	else:
		contact_uuid = find_element(action, 'contactId')
		assert contact_uuid is not None
		
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None or not ctc.lists & models.ContactList.FL:
			return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
				'action_str': 'ABGroupContactAdd',
			}, status = 500)
		else:
			for group_id in group_ids:
				for group_contact_entry in ctc._groups:
					if group_contact_entry.uuid == group_id:
						return abch_fault(req, 'ABGroupContactAdd', 'ContactAlreadyExists')
		
		for group_id in group_ids:
			bs.me_group_contact_add(group_id, ctc.head.uuid)
	return render(req, 'msn:abservice/ABGroupContactAddResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
		'contact_uuid': contact_uuid,
	})

def ab_ABGroupContactDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return abch_fault(req, 'ABGroupContactDelete', 'ABDoesNotExist')
	
	group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
	
	for group_id in group_ids:
		if group_id not in detail._groups_by_uuid:
			return abch_fault(req, 'ABGroupContactDelete', 'GroupDoesNotExist')
	
	contact_uuid = find_element(action, 'contactId')
	ctc = detail.contacts.get(contact_uuid or '')
	if ctc is not None:
		if ctc.lists & models.ContactList.FL:
			for group_id in group_ids:
				ctc_in_group = False
				for group_contact_entry in ctc._groups:
					if group_contact_entry.uuid == group_id:
						ctc_in_group = True
						break
				if not ctc_in_group:
					return abch_fault(req, 'ABGroupContactDelete', 'ContactDoesNotExist')
			for group_id in group_ids:
				bs.me_group_contact_remove(group_id, ctc.head.uuid)
	else:
		return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
			'action_str': 'ABGroupContactDelete',
		}, status = 500)
	return render(req, 'msn:abservice/ABGroupContactDeleteResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ManageWLConnection(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	now_str = util.misc.date_format(datetime.utcnow())
	cachekey = secrets.token_urlsafe(172)

	user = bs.user
	detail = user.detail
	assert detail is not None

	ab_id = find_element(action, 'ABId')
	ab_id = str(ab_id) if ab_id is not None else '00000000-0000-0000-0000-000000000000'

	if not (ab_id == '00000000-0000-0000-0000-000000000000' or (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12)):
		return abch_fault(req, 'ManageWLConnection', 'ABDoesNotExist')

	circle = None
	invite_message = None
	circle_mode = False

	contact_uuid = find_element(action, 'contactId')
	assert contact_uuid is not None
	contact_uuid = str(contact_uuid)

	if ab_id != '00000000-0000-0000-0000-000000000000':
		head = backend._load_user_record(contact_uuid)
	elif contact_uuid.startswith('00000000-0000-0000-0009-'):
		head = user
	else:
		head = backend._load_user_record(contact_uuid)

	if head is None:
		return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
			'action_str': 'ManageWLConnection',
		}, status=500)

	if ab_id == '00000000-0000-0000-0000-000000000000' and contact_uuid.startswith('00000000-0000-0000-0009-'):
		chat_id = contact_uuid[-12:]
		uuid = user.uuid
		circle_mode = True
	elif ab_id.startswith('00000000-0000-0000-0009-'):
		chat_id = ab_id[-12:]
		uuid = contact_uuid
		circle_mode = True

	if circle_mode:
		circle = backend.user_service.get_circle(chat_id)
		if circle is None:
			return abch_fault(req, 'ManageWLConnection', 'ABDoesNotExist')
		if uuid not in circle.memberships:
			return abch_fault(req, 'ManageWLConnection', 'MemberDoesNotExist')

	if find_element(action, 'connection') == True:
		# Parse relationship variables; relationshipRole is optional (absent in older clients)
		try:
			relationship_type_raw = find_element(action, 'relationshipType')
			relationship_role_raw = find_element(action, 'relationshipRole')
			wl_action = int(find_element(action, 'action'))
		except (ValueError, TypeError):
			return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
				'cachekey': cachekey,
				'host': settings.ADDRESSBOOK_HOST,
				'session_id': util.misc.gen_uuid(),
				'error': 'Relationship variables invalid',
			}, status=500)

		try:
			relationship_type = models.RelationshipType(relationship_type_raw)
		except (ValueError, TypeError):
			relationship_type = None 
		relationship_role = int(relationship_role_raw) if relationship_role_raw is not None else None

		if circle_mode:
			# All circle operations require a valid Circle relationship type
			if relationship_type != models.RelationshipType.Circle:
				return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
					'cachekey': cachekey,
					'host': settings.ADDRESSBOOK_HOST,
					'session_id': util.misc.gen_uuid(),
					'error': 'Expected Circle relationship type for circle operation',
				}, status=500)

			if wl_action == 1:
				if relationship_role == 0:
					if ab_id == '00000000-0000-0000-0000-000000000000':
						try:
							bs.me_accept_circle_invite(circle, send_events=False)
							backend.loop.create_task(_dispatch_circle_invite_status(backend, user, circle, False))
						except error.MemberNotInCircle:
							error_msg = 'User `{email}` does not have membership in `Circle`'.format(email=head.email)
							return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
								'cachekey': cachekey,
								'host': settings.ADDRESSBOOK_HOST,
								'session_id': util.misc.gen_uuid(),
								'error': error_msg,
							}, status=500)
						except error.MemberAlreadyInCircle:
							error_msg = 'User `{email}` already accepted in `Circle`'.format(email=head.email)
							return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
								'cachekey': cachekey,
								'host': settings.ADDRESSBOOK_HOST,
								'session_id': util.misc.gen_uuid(),
								'error': error_msg,
							})
						except error.CircleDoesNotExist:
							return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
								'cachekey': cachekey,
								'host': settings.ADDRESSBOOK_HOST,
								'session_id': util.misc.gen_uuid(),
								'error': '`Circle` does not currently exist',
							}, status=500)
				elif relationship_role == 3:
					caller_membership = circle.memberships.get(user.uuid)
					if caller_membership is None or caller_membership.role not in (models.CircleRole.Admin, models.CircleRole.AssistantAdmin):
						error_msg = 'Caller is not in `Circle` or does not have sufficient privileges to perform this action'
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.ADDRESSBOOK_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': error_msg,
						}, status=500)

					annotations = action.findall('.//{*}annotations/{*}Annotation')
					for annotation in annotations:
						name = find_element(annotation, 'Name')
						value = find_element(annotation, 'Value')
						if name == 'MSN.IM.InviteMessage':
							invite_message = value
							break
					try:
						bs.me_invite_user_to_circle(circle, head, invite_message=invite_message)
					except error.MemberNotInCircle:
						error_msg = 'User `{email}` does not have membership in `Circle`'.format(email=head.email)
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.ADDRESSBOOK_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': error_msg,
						}, status=500)
					except error.MemberAlreadyInvitedToCircle:
						error_msg = 'User `{email}` already invited to `Circle`'.format(email=head.email)
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.ADDRESSBOOK_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': error_msg,
						}, status=500)
					except error.CircleDoesNotExist:
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.ADDRESSBOOK_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': '`Circle` does not currently exist',
						}, status=500)
				else:
					error_msg = 'RelationshipRole `{role}` not currently supported for relationship type `{type}`'.format(
						role=relationship_role, type=relationship_type.name,
					)
					return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
						'cachekey': cachekey,
						'host': settings.ADDRESSBOOK_HOST,
						'session_id': util.misc.gen_uuid(),
						'error': error_msg,
					}, status=500)
			elif wl_action == 2:
				if ab_id == '00000000-0000-0000-0000-000000000000':
					try:
						bs.me_decline_circle_invite(circle, send_events=False)
						backend.loop.create_task(_dispatch_circle_invite_status(backend, user, circle, False))
					except error.MemberNotInCircle:
						error_msg = 'User `{email}` does not have membership in `Circle`'.format(email=head.email)
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.ADDRESSBOOK_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': error_msg,
						}, status=500)
					except error.MemberAlreadyInCircle:
						error_msg = 'User `{email}` already accepted in `Circle`'.format(email=head.email)
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.ADDRESSBOOK_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': error_msg,
						})
					except error.CircleDoesNotExist:
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.ADDRESSBOOK_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': '`Circle` does not currently exist',
						}, status=500)
				else:
					return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ManageWLConnection')
		else:
			# regular contact add/remove
			if wl_action == 1:
				add_ctc = False
				ctc = detail.contacts.get(contact_uuid)
				if ctc is not None:
					if not ctc.lists & models.ContactList.FL:
						add_ctc = True
				else:
					add_ctc = True
				if add_ctc:
					try:
						bs.me_contact_add(contact_uuid, models.ContactList.FL, name=head.email)
					except error.ContactListIsFull:
						return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ManageWLConnection', 'Contact list is full')
					except:
						pass
			elif wl_action == 2:
				try:
					bs.me_contact_remove(contact_uuid, models.ContactList.FL)
				except:
					pass
			else:
				return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ManageWLConnection')
	else:
		return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/ManageWLConnection')

	return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
		'ab_id': ab_id,
		'head': head,
		'circle': circle,
		'CircleRole': models.CircleRole,
		'CircleState': models.CircleState,
		'now': now_str,
		'user': user,
	})

def ab_BreakConnection(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)

	user = bs.user
	detail = user.detail
	assert detail is not None

	ab_id = find_element(action, 'ABId')
	ab_id = str(ab_id) if ab_id is not None else '00000000-0000-0000-0000-000000000000'

	if not (ab_id == '00000000-0000-0000-0000-000000000000' or (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12)):
		return abch_fault(req, 'BreakConnection', 'ABDoesNotExist')

	contact_uuid = find_element(action, 'contactId')
	assert contact_uuid is not None
	contact_uuid = str(contact_uuid)

	circle_mode = False
	chat_id = None

	if ab_id.startswith('00000000-0000-0000-0009-'):
		# Circle-AB leave: the caller must be the contact being removed
		if contact_uuid != user.uuid:
			return schema_fault(req, 'http://www.msn.com/webservices/AddressBook/BreakConnection', 'Access Denied')
		chat_id = ab_id[-12:]
		circle_mode = True
	elif contact_uuid.startswith('00000000-0000-0000-0009-'):
		# Default-AB with circle contactId: alternate leave form
		chat_id = contact_uuid[-12:]
		circle_mode = True

	if circle_mode:
		circle = backend.user_service.get_circle(chat_id)
		if circle is None:
			return abch_fault(req, 'BreakConnection', 'ABDoesNotExist')
		if user.uuid not in circle.memberships:
			return abch_fault(req, 'BreakConnection', 'MemberDoesNotExist')
		try:
			bs.me_leave_circle(circle)
		except Exception:
			return server_fault(req, 'http://www.msn.com/webservices/AddressBook/BreakConnection')
		backend.loop.create_task(_dispatch_circle_left(backend, user, circle))
	else:
		try:
			bs.me_contact_remove(contact_uuid, models.ContactList.FL)
		except:
			pass

	return render(req, 'msn:abservice/BreakConnectionResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

async def _dispatch_circle_invite_status(backend: Backend, user: models.User, circle: models.Circle, accepted: bool) -> None:
	await asyncio.sleep(0.04)
	if accepted:
		for sess in backend.util_get_sessions_by_user(user):
			sess.evt.on_accepted_circle_invite(circle)
	else:
		chat = backend.chat_get('persistent', circle.chat_id)
		if chat is None: return
		for sess in backend.util_get_sessions_by_user(user):
			sess.evt.on_declined_chat_invite(chat, circle = True)

async def _dispatch_circle_left(backend: Backend, user: models.User, circle: models.Circle) -> None:
	await asyncio.sleep(0.04)
	for sess in backend.util_get_sessions_by_user(user):
		sess.evt.on_left_circle(circle)

def ab_UpdateDynamicItem(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	# TODO: UpdateDynamicItem
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None

	return render(req, 'msn:abservice/UpdateDynamicItemResponse.xml', {
		'cachekey': cachekey,
		'host': settings.ADDRESSBOOK_HOST,
		'session_id': util.misc.gen_uuid(),
	})

_CONTACT_PROPERTIES = (
	'Comment', 'DisplayName', 'ContactType', 'ContactFirstName', 'ContactLastName', 'MiddleName', 'Anniversary',
	'ContactBirthDate', 'ContactEmail', 'ContactLocation', 'ContactWebSite', 'ContactPrimaryEmailType', 'ContactPhone', 'GroupName',
	'IsMessengerEnabled', 'IsMessengerUser', 'IsFavorite', 'HasSpace',
	'Annotation', 'Capability', 'MessengerMemberInfo',
)

_CONTACT_PHONE_PROPERTIES = (
	'Number',
)

_CONTACT_EMAIL_PROPERTIES = (
	'Email',
)

_CONTACT_LOCATION_PROPERTIES = (
	'Name', 'Street', 'City', 'State', 'Country', 'PostalCode',
)

_ANNOTATION_NAMES = (
	'MSN.IM.InviteMessage', 'MSN.IM.MPOP', 'MSN.IM.BLP', 'MSN.IM.GTC', 'MSN.IM.RoamLiveProperties',
	'MSN.IM.MBEA', 'MSN.IM.BuddyType', 'MSN.IM.HasSharedFolder', 'AB.NickName', 'AB.Profession', 'AB.Spouse',
	'AB.JobTitle', 'Live.Locale', 'Live.Profile.Expression.LastChanged',
	'Live.Passport.Birthdate', 'Live.Favorite.Order',
)

class GTCAnnotation(IntEnum):
	Empty = 0
	A = 1
	N = 2

class BLPAnnotation(IntEnum):
	Empty = 0
	AL = 1
	BL = 2
