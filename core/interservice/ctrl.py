from typing import Tuple, Optional, Iterable, List, Any, Callable, Dict
from disposable_email_domains import blocklist as disposable_emails
import asyncio, io, hashlib, base64, json, traceback
import sqlalchemy as sa
from sqlalchemy.orm.attributes import flag_modified

from core.backend import Backend
from core.models import CircleRole
from core import error
from util import misc, hash
import core.db as db

import settings

class INSCtrl:
	__slots__ = (
		'logger', 'reader', 'writer', 'peername', 'close_callback', 'closed', 'transport',
		'authenticated', 'current_challenge', 'backend', #'alive', 'alive_task',
	)
	
	logger: misc.Logger
	reader: 'INSReader'
	writer: 'INSWriter'
	peername: Tuple[str, int]
	close_callback: Optional[Callable[[], None]]
	closed: bool
	transport: Optional[asyncio.WriteTransport]
	authenticated: bool
	current_challenge: Optional[str]
	#alive: bool
	#alive_task: Optional[misc.VoidTaskType]
	backend: Backend
	
	def __init__(self, logger: misc.Logger, via: str, backend: Backend) -> None:
		self.logger = logger
		self.reader = INSReader(logger)
		self.writer = INSWriter(logger)
		self.peername = ('0.0.0.0', 4309)
		self.close_callback = None
		self.closed = False
		self.transport = None
		
		self.authenticated = False
		self.current_challenge = None
		#self.alive = True
		#self.alive_task = None
		self.backend = backend
	
	def _m_linksrv(self, password: str, identifier: Optional[str]) -> None:
		backend = self.backend

		bytes_enc = identifier.encode("ascii")
		base64_dec = base64.b64decode(bytes_enc)
		identifier_dec = base64_dec.decode("ascii")
	
		valid_identifiers = ['WEB', 'AzuL-SERV', 'WTV', 'uMaIL', 'sBOOK', 'NOTBAY', 'CrossBot', 'SEARCH', 'WebTalk']
		if identifier_dec not in valid_identifiers:
			self.logger.info(f'InterService identification failed, invalid identifier "{identifier_dec}".')
			self.send_numeric(Err.AuthenticationFailed)
			self.close()
		else:
			hashed_pw = hashlib.sha256(settings.INS_LINK_PASSWORD.encode()).hexdigest()
			if password == hashed_pw:
				self.authenticated = True
				backend._linked = True
				# TODO: Re-implement in V2
				#self.alive_task = backend.loop.create_task(self._ping_conn())
				self.logger.info(f'New InterService session established (identifier: {identifier_dec})')
				self.send_reply('LINKSRV', 'OK')
			else:
				self.send_numeric(Err.AuthenticationFailed)
				self.close()
				
	#def _m_pong(self, challenge: str) -> None:
	#	if self.alive: return
	#	if not self.current_challenge or challenge != self.current_challenge:
	#		self.close()
	#		return
	#	self.alive = True
	#	self.current_challenge = None
	
	def _m_circle(self, ts: str, chat_id: str, action: str, *args: str) -> None:
		backend = self.backend
		
		if not self.authenticated:
			self.send_numeric(Err.NotAuthenticated)
			self.close()
			return
		
		circle = backend.user_service.get_circle(chat_id)
		
		if circle is None:
			self.send_numeric(Err.CircleDoesNotExist, ':CIRCLE {}'.format(ts))
			return
		
		if action == 'INCHAT':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':CIRCLE {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':CIRCLE {}'.format(ts))
				return
			
			try:
				in_chat = backend.util_user_online_in_circle(circle, user)
				self.send_reply('CIRCLE', ts, 'INCHAT', uuid, str(in_chat))
			except error.MemberNotInCircle:
				self.send_numeric(Err.CircleMemberInvalid, ':CIRCLE {}'.format(ts))
			return
		elif action == 'ACCEPT':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':CIRCLE {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':CIRCLE {}'.format(ts))
				return
			
			try:
				backend.util_accept_circle_invite(circle, user)
			except error.MemberNotInCircle:
				self.send_numeric(Err.CircleMemberInvalid, ':CIRCLE {}'.format(ts))
				return
			except error.MemberAlreadyInCircle:
				self.send_numeric(Err.MemberAlreadyInCircle, ':CIRCLE {}'.format(ts))
				return
		elif action == 'DECLINE':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':CIRCLE {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':CIRCLE {}'.format(ts))
				return
			
			try:
				backend.util_decline_circle_invite(circle, user)
			except error.MemberNotInCircle:
				self.send_numeric(Err.CircleMemberInvalid, ':CIRCLE {}'.format(ts))
				return
			except error.MemberAlreadyInCircle:
				self.send_numeric(Err.MemberAlreadyInCircle, ':CIRCLE {}'.format(ts))
				return
		elif action == 'REVOKE':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':CIRCLE {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':CIRCLE {}'.format(ts))
				return
			
			try:
				backend.util_revoke_circle_invite(circle, user)
			except error.MemberNotInCircle:
				self.send_numeric(Err.CircleMemberInvalid, ':CIRCLE {}'.format(ts))
				return
			except error.MemberAlreadyInCircle:
				self.send_numeric(Err.MemberAlreadyInCircle, ':CIRCLE {}'.format(ts))
				return
		elif action == 'ROLE':
			if len(args) < 2:
				self.send_numeric(Err.TooFewArguments, ':CIRCLE {}'.format(ts))
				return
			
			user_self = None
			uuid = args[0]
			role_num = args[1]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':CIRCLE {}'.format(ts))
				return
			
			if len(args) >= 3:
				uuid_self = args[2]
				user_self = backend._load_user_record(uuid_self)
				if user_self is None:
					self.send_numeric(Err.UserNotInDB, ':{}'.format(ts))
					return
			
			try:
				role = CircleRole(int(role_num))
				if user_self is not None and role is not CircleRole.Admin: raise ValueError()
				
				backend.util_change_circle_membership_role(circle, user, role, user_self)
			except ValueError:
				self.send_numeric(Err.CircleRoleInvalid, ':CIRCLE {}'.format(ts))
				return
			except error.MemberNotInCircle:
				self.send_numeric(Err.CircleMemberInvalid, ':CIRCLE {}'.format(ts))
				return
			except error.CircleMemberIsPending:
				self.send_numeric(Err.CircleMemberIsPending, ':CIRCLE {}'.format(ts))
				return
			except error.MemberDoesntHaveSufficientCircleRole:
				self.send_numeric(Err.DoesntHaveSufficientPermissions, ':CIRCLE {}'.format(ts))
				return
		elif action == 'REMOVE':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':CIRCLE {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':CIRCLE {}'.format(ts))
				return
			
			try:
				backend.util_remove_user_from_circle(circle, user)
			except error.MemberNotInCircle:
				self.send_numeric(Err.CircleMemberInvalid, ':CIRCLE {}'.format(ts))
				return
			except error.CantLeaveCircle:
				self.send_numeric(Err.CantLeaveCircle, ':CIRCLE {}'.format(ts))
				return
		else:
			self.send_numeric(Err.InvalidArgument, ':CIRCLE {}'.format(ts))
			return
		
		self.send_numeric(StatusCode.CircleActionSuccessful, ':CIRCLE {}'.format(ts))

	def _m_alert(self, ts: str, type: str, content: str = '', url: str = '', targets: str = 'all', icon: str = '') -> None:
		def _quote_circumcision(s: str) -> str:
			if not s or len(s) < 2:
				return s
			if (s[0] == s[-1]) and s[0] in ('"', "'"):
				quote = s[0]
				inner = s[1:-1]
				inner = inner.replace('\\\\', '\\').replace('\\' + quote, quote)
				return inner
			return s

		if not content:
			return self.send_numeric(Err.InvalidArgument, ts)

		if type == 'MAINTENANCE':
			try:
				mt_mins = int(content)
			except ValueError:
				return self.send_numeric(Err.TooFewArguments, ts)
			if self.backend.maintenance_mode or self.backend.notify_maintenance:
				return self.send_numeric(Err.ServerInModeAlready, ts)
			self.backend.push_maintenance_message(1, mt_mins)
			return self.send_reply('ALERT', ts, 'OK')

		else:
			content = content.strip()
			content_circumcised = _quote_circumcision(content)

			if not content_circumcised:
				return self.send_numeric(Err.InvalidArgument, ts)

			sessions = set()
			if targets.strip() == 'all':
				sessions = set(self.backend._sc.iter_sessions())
			else:
				for t in [t.strip() for t in targets.split(',') if t.strip()]:
					uuid = self.backend.util_get_uuid_from_email(t)
					if uuid:
						user = self.backend._load_user_record(uuid)
						if user:
							for s in self.backend.util_get_sessions_by_user(user):
								sessions.add(s)
							continue
					for bs in self.backend._sc.iter_sessions():
						if str(id(bs)) == t:
							sessions.add(bs)

			for bs in sessions:
				bs.evt.on_client_alert(icon, url, content_circumcised)

			self.send_reply('ALERT', ts, 'OK')


	def _m_user(self, ts: str, action: str, uuid: str, field: str = '', *args: str) -> None:
		def _parse_value_for_column(col, value_str):
			py_type = getattr(col.type, 'python_type', None)
			if py_type is not None:
				try:
					if py_type is bool:
						v = value_str.strip().lower()
						return v in ('1', 'true', 'yes', 'on')
					if py_type is int:
						return int(value_str)
					if py_type is float:
						return float(value_str)
					return py_type(value_str)
				except Exception:
					return value_str
			tname = col.type.__class__.__name__.lower()
			if 'json' in tname or 'json' in str(col.type).lower():
				try:
					return json.loads(value_str)
				except Exception:
					return value_str
			if 'boolean' in tname:
				v = value_str.strip().lower()
				return v in ('1', 'true', 'yes', 'on')
			if 'integer' in tname or 'int' in tname:
				try:
					return int(value_str)
				except Exception:
					return value_str
			return value_str

		def set_passwords_and_prune(user_obj, pw: str, flags_list: List[str]):
			if 'oldmsn' in flags_list:
				user_obj.set_front_data('msn', 'pw_md5', hash.hasher_md5.encode(pw))
			else:
				if user_obj._front_data and 'msn' in user_obj._front_data:
					user_obj._front_data.pop('msn', None)
					flag_modified(user_obj, '_front_data')
			
			if 'yahoo' in flags_list:
				user_obj.set_front_data('ymsg', 'pw_md5_unsalted', hash.hasher_md5.encode(pw, salt=''))
				user_obj.set_front_data('ymsg', 'pw_md5crypt', hash.hasher_md5crypt.encode(pw, salt='$1$_2S43d5f'))
			else:
				if user_obj._front_data and 'ymsg' in user_obj._front_data:
					user_obj._front_data.pop('ymsg', None)
					flag_modified(user_obj, '_front_data')
			
			if 'oldaim' in flags_list:
				user_obj.set_front_data('aim', 'pw_md5', hash.hasher_md5.encode(pw, identifier='AOL Instant Messenger (SM)'))
			else:
				if user_obj._front_data and 'aim' in user_obj._front_data:
					user_obj._front_data.pop('aim', None)
					flag_modified(user_obj, '_front_data')
			
			if 'msim' in flags_list:
				user_obj.set_front_data('msim', 'pw_sha1', hash.hasher_sha1.encode(pw))
			else:
				if user_obj._front_data and 'msim' in user_obj._front_data:
					user_obj._front_data.pop('msim', None)
					flag_modified(user_obj, '_front_data')
			
			user_obj.password = hash.hasher.encode(pw)

		if action == 'CREATE':
			if len(args) < 4:
				return self.send_numeric(Err.TooFewArguments, ts)
			email = uuid
			username = field
			first_name = args[0]
			last_name = args[1]
			try:
				uin = int(args[2])
			except Exception:
				return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
			password_b64 = args[3]
			flags = [f.lower() for f in args[4:]]
			try:
				pw_bytes = base64.b64decode(password_b64, validate=True)
				password = pw_bytes.decode('utf-8')
			except Exception:
				return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
			if len(username) > 32:
				return self.send_numeric(Err.TooManyCharactersUsername, f':USER {ts}')
			if len(email) > 254:
				return self.send_numeric(Err.TooManyCharactersEmail, f':USER {ts}')
			if username and not username.isalnum():
				return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
			try:
				with db.Session() as sess:
					user_row = sess.query(db.User).filter_by(email=email).one_or_none()
					if user_row is not None:
						set_passwords_and_prune(user_row, password, flags)
						sess.add(user_row)
						created_uuid = user_row.uuid
					else:
						with open('config/restricted-usernames.json', 'r') as file:
							restricted_usernames = json.load(file)
							if username.lower() in restricted_usernames:
								return self.send_numeric(Err.RestrictedUseranme, f':USER {ts}')
						with open('config/restricted-emails.json', 'r') as file:
							restricted_emails = json.load(file)
							email_domain = email.lower().split('@')[-1] if '@' in email else ''
							if email_domain in restricted_emails:
								return self.send_numeric(Err.RestrictedEmail, f':USER {ts}')
						if email_domain in disposable_emails:
							return self.send_numeric(Err.RestrictedEmail, f':USER {ts}')
						username_conflict = sess.query(db.User).filter_by(username=username).one_or_none()
						email_conflict = sess.query(db.User).filter_by(email=email).one_or_none()
						if username_conflict:
							return self.send_numeric(Err.UsernameTaken, f':USER {ts}')
						elif email_conflict:
							return self.send_numeric(Err.EmailTaken, f':USER {ts}')
						new_user = db.User(
							uuid=misc.gen_uuid(),
							email=email,
							first_name=first_name,
							last_name=last_name,
							username=username,
							uin=uin,
							verified_to_login=True,
							account_verified=False,
							friendly_name=email,
							groups={},
							settings={},
							suspended=False,
							is_tester=False,
							is_mvp=False,
							show_in_dir=False
						)
						set_passwords_and_prune(new_user, password, flags)
						sess.add(new_user)
						self.logger.info(f"New user created")
						self.logger.info(f"UUID: {new_user.uuid}")
						self.logger.info(f"Username: {new_user.username}")
						self.logger.info(f"E-mail: {new_user.email}")
						self.logger.info(f"UIN: {new_user.uin}")
						self.logger.info(f"Flags: {flags}")
						sess.commit()
						created_uuid = new_user.uuid
			except Exception as e:
				self.logger.error(e)
				return self.send_numeric(Err.UserCreationFailed, f':USER {ts}')
			try:
				domain_user = self.backend._load_user_record(created_uuid)
				if domain_user is not None:
					try:
						detail = self.backend._load_detail(domain_user)
					except Exception:
						detail = None
					self.backend._mark_modified(domain_user, detail=detail)
			except Exception as e:
				self.logger.error(e)
				self.logger.info("post-create backend processing failed")

			self.send_reply('USER', 'CREATE', ts, created_uuid, 'OK')
			return

		elif action == 'UPDATE':
			new_raw_value = ' '.join(args)
			try:
				with db.Session() as sess:
					user_row = sess.query(db.User).filter_by(uuid=uuid).one_or_none()
					if user_row is None:
						return self.send_numeric(Err.UserNotInDB, ts)
					if field == 'password':
						if len(args) < 1:
							return self.send_numeric(Err.TooFewArguments, ts)
						password_b64 = args[0]
						flags = [f.lower() for f in args[1:]]
						try:
							pw_bytes = base64.b64decode(password_b64, validate=True)
							password = pw_bytes.decode('utf-8')
						except Exception:
							return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
						set_passwords_and_prune(user_row, password, flags)
						sess.add(user_row)
						try:
							self.backend._user_by_uuid.pop(uuid, None)
						except Exception as e:
							self.logger.error(e)
							self.logger.info("Failed to nuke stale user cache")
					elif field in ('show_in_dir', 'verified_to_login', 'suspended', 'is_tester', 'is_mvp'):
						col = user_row.__table__.columns[field]
						parsed_val = _parse_value_for_column(col, new_raw_value)
						setattr(user_row, field, parsed_val)
						sess.add(user_row)
						try:
							domain_user = self.backend._load_user_record(uuid)
							if domain_user:
								setattr(domain_user, field, parsed_val)
						except Exception as e:
							self.logger.error(e)
							self.logger.info(f"Failed to update cached user object for {field}")
					elif field.startswith('profile.'):
						prof_field = field.split('.', 1)[1]
						profile = sess.query(db.UserProfile).filter_by(user_id=user_row.id).one_or_none()
						if not profile:
							profile = db.UserProfile(user_id=user_row.id)
							sess.add(profile)
							sess.flush()
						if prof_field == 'interests':
							try:
								interests_json = json.loads(new_raw_value)
								if not isinstance(interests_json, list):
									return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
								total_len = 0
								for item in interests_json:
									if not isinstance(item, str):
										return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
									if len(item) > 50:
										return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
									total_len += len(item)
								if total_len > 200:
									return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
								profile.interests = interests_json
							except json.JSONDecodeError:
								return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
						elif prof_field == 'pronouns':
							if len(new_raw_value) > 16:
								return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
							col = profile.__table__.columns[prof_field]
							val = _parse_value_for_column(col, new_raw_value)
							setattr(profile, prof_field, val)
						elif prof_field == 'website':
							if len(new_raw_value) > 75:
								return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
							col = profile.__table__.columns[prof_field]
							val = _parse_value_for_column(col, new_raw_value)
							setattr(profile, prof_field, val)
						elif prof_field == 'bio':
							if len(new_raw_value) > 200:
								return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
							col = profile.__table__.columns[prof_field]
							val = _parse_value_for_column(col, new_raw_value)
							setattr(profile, prof_field, val)
						elif prof_field not in profile.__table__.columns:
							return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
						else:
							col = profile.__table__.columns[prof_field]
							val = _parse_value_for_column(col, new_raw_value)
							setattr(profile, prof_field, val)
						sess.add(profile)
					else:
						if field.endswith('_uuid'):
							return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
						if '.' in field:
							top, sub = field.split('.', 1)
							if top not in user_row.__table__.columns:
								return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
							col = user_row.__table__.columns[top]
							tname = col.type.__class__.__name__.lower()
							if 'json' in tname or 'json' in str(col.type).lower():
								orig = getattr(user_row, top) or {}
								try:
									subval = json.loads(new_raw_value)
								except Exception:
									subval = new_raw_value
								orig[sub] = subval
								setattr(user_row, top, orig)
								sess.add(user_row)
							else:
								return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
						else:
							username_conflict = sess.query(db.User).filter_by(username=new_raw_value).one_or_none()
							email_conflict = sess.query(db.User).filter_by(email=new_raw_value).one_or_none()
							if field not in user_row.__table__.columns:
								return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
							if field == 'username' and len(new_raw_value) > 32:
								return self.send_numeric(Err.TooManyCharactersUsername, f':USER {ts}')
							if field == 'email' and len(new_raw_value) > 254:
								return self.send_numeric(Err.TooManyCharactersEmail, f':USER {ts}')
							if field == 'username' and new_raw_value and not new_raw_value.isalnum():
								return self.send_numeric(Err.InvalidArgument, f':USER {ts}')
							if field == 'username' and username_conflict:			
								return self.send_numeric(Err.UsernameTaken, f':USER {ts}')
							if field == 'email' and email_conflict:			
								return self.send_numeric(Err.EmailTaken, f':USER {ts}')
							with open('config/restricted-usernames.json', 'r') as file:
								restricted_usernames = json.load(file)
								if field == 'username' and new_raw_value.lower() in restricted_usernames:
									return self.send_numeric(Err.RestrictedUseranme, f':USER {ts}')
							if field == 'email':
								with open('config/restricted-emails.json', 'r') as file:
									restricted_emails = json.load(file)
									email_domain = new_raw_value.lower().split('@')[-1] if '@' in new_raw_value else ''
									if email_domain in restricted_emails:
										return self.send_numeric(Err.RestrictedEmail, f':USER {ts}')
								if email_domain in disposable_emails:
									return self.send_numeric(Err.RestrictedEmail, f':USER {ts}')
							col = user_row.__table__.columns[field]
							val = _parse_value_for_column(col, new_raw_value)
							setattr(user_row, field, val)
							sess.add(user_row)
			except Exception:
				traceback.print_exc()
				return self.send_numeric(Err.ServerUnknownError, ts)
			if field == 'email':
				try:
					domain_user = self.backend._load_user_record(uuid)
					if domain_user:
						domain_user.email = new_raw_value
				except Exception as e:
					self.logger.error(e)
					self.logger.info("Failed to update cached email")
			try:
				domain_user = self.backend._load_user_record(uuid)
				if domain_user:
					for bs in self.backend.util_get_sessions_by_user(domain_user):
						try:
							bs.close()
						except Exception:
							pass
			except Exception:
				traceback.print_exc()
			try:
				domain_user = self.backend._load_user_record(uuid)
				if domain_user:
					try:
						detail = self.backend._load_detail(domain_user)
					except Exception:
						detail = None
					self.backend._mark_modified(domain_user, detail=detail)
			except Exception as e:
				self.logger.error(e)
				self.logger.info("Failed while post-processing USER UPDATE")
			if domain_user is not None:
				output_value = "[REDACTED]" if field == "password" else new_raw_value
				self.logger.info(f"{domain_user.username} ({domain_user.email}) has changed user attribute {field} to {output_value}")
			else:
				output_value = "[REDACTED]" if field == "password" else new_raw_value
				self.logger.info(f"User with UUID {uuid} (unresolved) has changed user attribute {field} to {output_value}")
			self.send_reply('USER', 'UPDATE', ts, uuid, 'OK')
			return

		elif action == 'DELETE':
			try:
				with db.Session() as sess:
					user_row = sess.query(db.User).filter_by(uuid=uuid).one_or_none()
					if user_row is None:
						return self.send_numeric(Err.UserNotInDB, ts)
					sess.delete(user_row)
					sess.flush()
				try:
					domain_user = self.backend._load_user_record(uuid)
					if domain_user:
						for bs in self.backend.util_get_sessions_by_user(domain_user):
							try:
								bs.close()
							except Exception:
								pass
						self.backend._mark_modified(domain_user, deleted=True)
				except Exception as e:
					self.logger.error(e)
					self.logger.info("Failed while post-processing USER DELETE")
				if domain_user is not None:
					self.logger.info(f"{domain_user.username} ({domain_user.email}) has deleted their account")
				else:
					self.logger.info(f"User with UUID {uuid} (unresolved) has deleted their account")
				self.send_reply('USER', 'DELETE', ts, uuid, 'OK')
				return
			except Exception as e:
				self.logger.error(e)
				self.logger.info("USER DELETE failed")
				return self.send_numeric(Err.ServerUnknownError, ts)

		else:
			return self.send_numeric(Err.InvalidArgument, ts)

	def _m_allthesessions(self, ts: str, email_filter: str = '') -> None:
		# TODO: make this a payload command
		sessions_info = []
		for bs in self.backend._sc.iter_sessions():
			if email_filter and bs.user.email != email_filter:
				continue
			info = f"{id(bs)}|{bs.user.uuid}|{bs.user.email}|{bs.client.ToJSON(bs.client)}"
			sessions_info.append(info)
		self.send_reply('ALLTHESESSIONS', ts, *sessions_info)

	def _m_session(self, ts: str, sess_id: str, method: str) -> None:
		target = None
		for bs in self.backend._sc.iter_sessions():
			if str(id(bs)) == sess_id:
				target = bs
				break
		if not target:
			return self.send_numeric(e, ts)
		if not method:
			return self.send_numeric(105, ts)
		if method.upper() == 'GET':
			data = (
				sess_id,
				target.user.username,
				target.user.uuid,
				target.user.email,
				str(target.user.uin),
				target.client.ToJSON(target.client),
				str(target.chat_enabled),
			)
			self.send_reply('SESSION', ts, *data)
		elif method.upper() == 'KILL':
			target.close(sess_id=sess_id)
			self.send_reply('SESSION', ts, 'KILLED')
		else:
			self.send_numeric(104, ts)
	
	def _m_quit(self) -> None:
		self.send_reply('QUIT')
		self.close()
	
	#async def _ping_conn(self) -> None:
	#	while True:
	#		await asyncio.sleep(60)
	#		if self.closed or not self.alive:
	#			if not self.alive:
	#				self.close()
	#			break
	#		self.alive = False
	#		self.current_challenge = hash.gen_salt()
	#		self.send_reply('PING', ':{}'.format(self.current_challenge))
	
	def data_received(self, transport: asyncio.BaseTransport, data: bytes) -> None:
		self.peername = transport.get_extra_info('peername')
		for m in self.reader.data_received(data):
			try:
				f = getattr(self, '_m_{}'.format(m[0].lower()))
				f(*m[1:])
			except Exception as ex:
				self.logger.error(ex)
	
	def send_numeric(self, n: int, *m: str) -> None:
		self.send_reply('{:03}'.format(n), *m)
	
	def send_reply(self, *m: str) -> None:
		self.writer.write(m)
		transport = self.transport
		if transport is not None:
			transport.write(self.flush())
	
	def flush(self) -> bytes:
		return self.writer.flush()
	
	def close(self) -> None:
		if self.closed: return
		self.closed = True
		#if self.alive_task is not None and not self.alive_task.cancelled:
		#	self.alive_task.cancel()
		if self.authenticated:
			self.backend._linked = False
		if self.close_callback:
			self.close_callback()

class INSReader:
	__slots__ = ('_logger', '_data')
	
	_logger: misc.Logger
	_data: bytes
	
	def __init__(self, logger: misc.Logger) -> None:
		self._logger = logger
		self._data = b''
	
	def data_received(self, data: bytes) -> Iterable[List[str]]:
		if self._data:
			self._data += data
		else:
			self._data = data
		while self._data:
			m = self._read()
			if m is None:
				break
			self._logger.debug('[Client]', *m)
			yield m
	
	def _read(self) -> Optional[List[str]]:
		try:
			i = self._data.index(b'\r\n')
		except ValueError:
			return None

		chunk = self._data[:i].decode('utf-8', errors='replace')
		self._data = self._data[i+2:]

		if '\r' in chunk or '\n' in chunk:
			self._logger.info('Embedded CR/LF in incoming line; whack his peepee')
			chunk = chunk.replace('\r', ' ').replace('\n', ' ')

		toks = []
		while True:
			chunk = chunk.lstrip(' ')
			if not chunk:
				break

			if chunk[:1] == ':':
				toks.append(chunk[1:])
				break

			if chunk[0] in ('"', "'"):
				quote_char = chunk[0]
				j = 1
				escaped = False
				found = False
				while j < len(chunk):
					ch = chunk[j]
					if ch == '\\' and not escaped:
						escaped = True
						j += 1
						continue
					if ch == quote_char and not escaped:
						found = True
						break
					escaped = False
					j += 1
				if found:
					raw_tok = chunk[:j+1]
					chunk = chunk[j+1:]
					inner = raw_tok[1:-1]
					inner = inner.replace('\\' + quote_char, quote_char).replace('\\\\', '\\')
					if '\r' in inner or '\n' in inner:
						self._logger.info('Satanizing') # intentional
						inner = inner.replace('\r', ' ').replace('\n', ' ')
					toks.append(inner)
				else:
					inner = chunk[1:].replace('\\' + quote_char, quote_char).replace('\\\\', '\\')
					if '\r' in inner or '\n' in inner:
						self._logger.info('Satanizing but quotes')
						inner = inner.replace('\r', ' ').replace('\n', ' ')
					toks.append(inner)
					break
				continue

			k = chunk.find(' ')
			if k < 0:
				tok = chunk
				chunk = ''
			else:
				tok = chunk[:k]
				chunk = chunk[k+1:]
			if tok:
				if '\r' in tok or '\n' in tok:
					self._logger.info('Satanizing CR/LF from token')
					tok = tok.replace('\r', ' ').replace('\n', ' ')
				toks.append(tok)
			if not chunk:
				break
		return toks

class INSWriter:
	__slots__ = ('_logger', '_buf')
	
	_logger: misc.Logger
	_buf: io.BytesIO
	
	def __init__(self, logger: misc.Logger) -> None:
		self._logger = logger
		self._buf = io.BytesIO()
	
	def write(self, m: Iterable[Any]) -> None:
		safe_parts = []
		for part in m:
			s = str(part)
			if '\r' in s or '\n' in s:
				self._logger.info('Satanizing before sending')
				s = s.replace('\r', ' ').replace('\n', ' ')
			if ' ' in s or s.startswith(':') or any(ord(c) < 32 for c in s):
				escaped = s.replace('\\', '\\\\').replace('"', '\\"')
				s = f'"{escaped}"'
			safe_parts.append(s)
		self._logger.debug('[Server]', *safe_parts)
		self._buf.write(' '.join(safe_parts).encode('utf-8'))
		self._buf.write(b'\r\n')

	def flush(self) -> bytes:
		data = self._buf.getvalue()
		if data:
			self._buf = io.BytesIO()
		return data

# `1xx`: Generic codes; `2xx`: Circle codes; `3xx`: Server operations codes; `4xx`: User service status codes

class Err:
	AuthenticationFailed = 101
	NotAuthenticated = 102
	InvalidArgument = 104
	TooFewArguments = 105
	CircleDoesNotExist = 200
	CircleRoleInvalid = 202
	CircleMemberInvalid = 203
	MemberAlreadyInCircle = 204
	CircleMemberIsPending = 205
	DoesntHaveSufficientPermissions = 206
	CantLeaveCircle = 207
	ServerUnknownError = 300
	ServerInModeAlready = 310
	UsernameTaken = 410
	EmailTaken = 411
	RestrictedUseranme = 415
	RestrictedEmail = 416
	TooManyCharactersUsername = 425
	TooManyCharactersEmail = 426
	UserCreationFailed = 427
	UserNotInDB = 428


class StatusCode:
	CircleActionSuccessful = 201