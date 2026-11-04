from typing import Any, Iterator
from datetime import datetime
from contextlib import contextmanager
import sqlalchemy as sa
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

from util.json_type import JSONType
import settings

def Col(*args: Any, **kwargs: Any) -> sa.Column:
	if 'nullable' not in kwargs:
		kwargs['nullable'] = False
	return sa.Column(*args, **kwargs)

class Base(declarative_base()): # type: ignore
	__abstract__ = True

class WithFrontData(Base):
	__abstract__ = True
	
	# Data specific to front-ends; e.g. different types of password hashes
	# E.g. front_data = { 'msn': { ... }, 'ymsg': { ... }, ... }
	_front_data = Col(JSONType, name = 'front_data', default = {})
	
	def set_front_data(self, frontend: str, key: str, value: Any) -> None:
		fd = self._front_data or {}
		if frontend not in fd:
			fd[frontend] = {}
		fd[frontend][key] = value
		# As a side-effect, this also makes `._front_data` into a new object,
		# so SQLAlchemy picks up the fact that it's been changed.
		# (SQLAlchemy only does shallow comparisons on fields by default.)
		self._front_data = _simplify_json_data(fd)
	
	def get_front_data(self, frontend: str, key: str) -> Any:
		fd = self._front_data
		if not fd: return None
		fd = fd.get(frontend)
		if not fd: return None
		return fd.get(key)

class User(WithFrontData):
	__tablename__ = 'user'
	
	id = Col(sa.Integer, primary_key = True)
	date_created = Col(sa.DateTime, default = datetime.utcnow)
	date_login = Col(sa.DateTime, nullable = True)
	uuid = Col(sa.String(50), unique = True)
	email = Col(sa.String(80, collation='utf8mb4_unicode_ci'), nullable=False, unique=True)
	username = Col(sa.String(40, collation='utf8mb4_unicode_ci'), nullable=False, unique=True)
	first_name = Col(sa.String(50), nullable = True)
	middle_name = Col(sa.String(50), nullable = True)
	last_name = Col(sa.String(50), nullable = True)
	# specifically used for social features/member directory
	nickname = Col(sa.String(60), nullable = True)
	uin = Col(sa.BigInteger, nullable = True)
	# verified for logging in. all existing users pre-email verification have this set to true, until a certain date, unless they verified their email (account_verified), then it's always true. this is set to false on all new users post-verification unless they've also verified their e-mail address
	verified_to_login = Col(sa.Boolean)
	# Roaming name - can be null and (in theory) stays constant to what the user sets it to
	name = Col(sa.String(60), nullable = True)
	name_last_modified = Col(sa.DateTime, default = datetime.utcnow)
	# Friendly name set during IM sessions. It cannot be null and is more prone to being overwritten than the roaming name
	friendly_name = Col(sa.String(60))
	# Roaming message
	message = Col(sa.String(255), nullable = True)
	message_last_modified = Col(sa.DateTime, default = datetime.utcnow)
	password = Col(sa.String(250))
	groups = Col(JSONType)
	settings = Col(JSONType)
	suspended = Col(sa.Boolean)
	suspended_at = Col(sa.DateTime, nullable = True)
	is_tester = Col(sa.Boolean)
	is_mvp = Col(sa.Boolean)
	show_in_dir = Col(sa.Boolean)
	evil_permanent = Col(sa.Integer, default = 0)
	evil_temporary = Col(sa.Integer, default = 0)
	alias_active = Col(sa.Boolean, default=False)
	did_firsttime_email_change = Col(sa.Boolean, default=False)
	account_verified = Col(sa.Boolean, default=False) # for e-mail address verification
	is_admin = Col(sa.Boolean, default = False, server_default = sa.false())
	lang = Col(sa.String(10), nullable = True)
	avatar = Col(sa.String(16), nullable = True)
	profile = relationship("UserProfile", backref="user", uselist=False, cascade="all, delete-orphan")
	__table_args__ = (sa.Index('email_ci_index', sa.text('(LOWER(email))'), unique = True), sa.Index('username_ci_index', sa.text('(LOWER(username))'), unique = True))

class UserContact(WithFrontData):
	__tablename__ = 'user_contact'
	
	user_id = Col(sa.Integer, sa.ForeignKey('user.id'), primary_key = True)
	contact_id = Col(sa.Integer, sa.ForeignKey('user.id'), primary_key = True)
	user_uuid = Col(sa.String(50), sa.ForeignKey('user.uuid')) # = User(self.user_id).uuid
	
	uuid = Col(sa.String(50), sa.ForeignKey('user.uuid')) # = User(self.contact_id).uuid
	name = Col(sa.String(100))
	lists = Col(sa.Integer)
	pending = Col(sa.Boolean, default = False)
	groups = Col(JSONType)
	is_messenger_user = Col(sa.Boolean)
	
	index_id = Col(sa.String(50))
	birthdate = Col(sa.DateTime, nullable = True)
	anniversary = Col(sa.DateTime, nullable = True)
	notes = Col(sa.String(255), nullable = True)
	first_name = Col(sa.String(50), nullable = True)
	middle_name = Col(sa.String(50), nullable = True)
	last_name = Col(sa.String(50), nullable = True)
	nickname = Col(sa.String(80), nullable = True)
	primary_email_type = Col(sa.String(10), nullable = True)
	personal_email = Col(sa.String(80), nullable = True)
	work_email = Col(sa.String(80), nullable = True)
	im_email = Col(sa.String(80), nullable = True)
	other_email = Col(sa.String(80), nullable = True)
	home_phone = Col(sa.String(50), nullable = True)
	work_phone = Col(sa.String(50), nullable = True)
	fax_phone = Col(sa.String(50), nullable = True)
	pager_phone = Col(sa.String(50), nullable = True)
	mobile_phone = Col(sa.String(50), nullable = True)
	other_phone = Col(sa.String(50), nullable = True)
	personal_website = Col(sa.String(80), nullable = True)
	business_website = Col(sa.String(80), nullable = True)
	locations = Col(JSONType, default = {})

class UserProfile(WithFrontData):
	__tablename__ = 'user_profile'

	user_id = Col(sa.Integer, sa.ForeignKey('user.id'), primary_key = True)
	bio = Col(sa.Text, nullable = True)
	pronouns = Col(sa.String(40), nullable = True)
	website = Col(sa.String(100), nullable = True)
	socials = Col(JSONType, nullable = True)
	streetaddr = Col(sa.String(100), nullable = True)
	city = Col(sa.String(80), nullable = True)
	state = Col(sa.String(80), nullable = True)
	zip = Col(sa.Integer, nullable = True)
	country = Col(sa.String(60), nullable = True)
	language = Col(JSONType, nullable = True)
	interests = Col(JSONType, nullable = True, default = {})
	visibility = Col(sa.String(25), default='public')

class Circle(Base):
	__tablename__ = 'circle'

	id = Col(sa.Integer, primary_key = True)
	chat_id = Col(sa.String(50), unique = True)
	name = Col(sa.String(100))
	owner_id = Col(sa.Integer, sa.ForeignKey('user.id'))
	owner_uuid = Col(sa.String(50), sa.ForeignKey('user.uuid'))
	owner_friendly = Col(sa.String(100))
	membership_access = Col(sa.Integer)
	request_membership_option = Col(sa.Integer)

class CircleMembership(Base):
	__tablename__ = 'circle_membership'
	
	id = Col(sa.Integer, primary_key = True)
	chat_id = Col(sa.String(50), sa.ForeignKey('circle.chat_id'))
	member_id = Col(sa.Integer, sa.ForeignKey('user.id'))
	member_uuid = Col(sa.String(50), sa.ForeignKey('user.uuid'))
	role = Col(sa.Integer)
	state = Col(sa.Integer)
	blocking = Col(sa.Boolean)
	inviter_uuid = Col(sa.String(50), nullable = True)
	inviter_email = Col(sa.String(100), nullable = True)
	inviter_name = Col(sa.String(100), nullable = True)
	invite_message = Col(sa.String(250), nullable = True)

class Sound(Base):
	__tablename__ = 'sound'
	
	hash = Col(sa.String(50), primary_key = True)
	title = Col(sa.String(100))
	category = Col(sa.Integer)
	language = Col(sa.Integer)
	is_public = Col(sa.Boolean)
	hits = Col(sa.Integer, default = 0)

class Activity(Base):
	__tablename__ = 'user_activity'
	
	id = Col(sa.Integer, primary_key = True)
	# `None` for service announcements
	user_uuid = Col(sa.String(50), sa.ForeignKey('user.uuid'), nullable = True, index = True)
	type = Col(sa.Integer)
	title = Col(sa.String(100), nullable = True)
	text = Col(sa.String(255), nullable = True)
	url = Col(sa.String(255), nullable = True)
	date_created = Col(sa.DateTime, default = datetime.utcnow, index = True)
	
class ActivityReaction(Base):
	__tablename__ = 'user_activity_reaction'
	__table_args__ = (sa.UniqueConstraint('activity_id', 'user_uuid', 'reaction'),)
	
	id = Col(sa.Integer, primary_key = True)
	activity_id = Col(sa.Integer, index = True)
	user_uuid = Col(sa.String(50), index = True)
	reaction = Col(sa.String(64))
	date_created = Col(sa.DateTime, default = datetime.utcnow)

class ActivityComment(Base):
	__tablename__ = 'user_activity_comment'
	
	id = Col(sa.Integer, primary_key = True)
	activity_id = Col(sa.Integer, index = True)
	user_uuid = Col(sa.String(50), index = True)
	text = Col(sa.String(255, collation='utf8mb4_unicode_ci'))
	date_created = Col(sa.DateTime, default = datetime.utcnow)

class InsClient(Base):
	__tablename__ = 'ins_client'
	
	id = Col(sa.Integer, primary_key = True)
	identifier = Col(sa.String(64))
	label = Col(sa.String(100), default = '')
	transport_public = Col(sa.String(64), unique = True)
	auth_public = Col(sa.String(64))
	machine = Col(sa.String(64))
	addresses = Col(JSONType)
	date_created = Col(sa.DateTime, default = datetime.utcnow)
	date_last_seen = Col(sa.DateTime, nullable = True)
	last_address = Col(sa.String(64), nullable = True)
	revoked = Col(sa.Boolean, default = False)
	date_revoked = Col(sa.DateTime, nullable = True)

class InsEnrollment(Base):
	__tablename__ = 'ins_enrollment'
	
	id = Col(sa.Integer, primary_key = True)
	code_id = Col(sa.String(32), unique = True)
	secret_hash = Col(sa.String(64))
	identifier = Col(sa.String(64))
	label = Col(sa.String(100), default = '')
	address = Col(sa.String(64), nullable = True)
	created_by = Col(sa.String(50), nullable = True)
	date_created = Col(sa.DateTime, default = datetime.utcnow)
	date_expires = Col(sa.DateTime)
	date_used = Col(sa.DateTime, nullable = True)
	client_id = Col(sa.Integer, nullable = True)

class LoginToken(Base):
	__tablename__ = 'login_token'
	
	id = Col(sa.Integer, primary_key = True)
	token = Col(sa.String(100))
	purpose = Col(sa.String(25))
	data = Col(JSONType)
	expiry = Col(sa.DateTime)

def _simplify_json_data(data: Any) -> Any:
	if isinstance(data, dict):
		d = {}
		for k, v in data.items():
			v = _simplify_json_data(v)
			if v is not None:
				d[k] = v
		if not d:
			return None
		return d
	if isinstance(data, (list, tuple)):
		return [_simplify_json_data(x) for x in data]
	return data

def ensure_schema(engine: Any) -> list[str]:
	changed: list[str] = []
	inspector = sa.inspect(engine)
	tables = set(inspector.get_table_names())
	for table in (InsClient.__table__, InsEnrollment.__table__):
		if table.name not in tables:
			table.create(engine)
			changed.append(table.name)
	if 'user' in tables:
		columns = { column['name'] for column in inspector.get_columns('user') }
		quote = engine.dialect.identifier_preparer.quote
		if 'is_admin' not in columns:
			false = str(sa.false().compile(dialect = engine.dialect))
			with engine.begin() as conn:
				conn.execute(sa.text('ALTER TABLE {} ADD COLUMN {} BOOLEAN NOT NULL DEFAULT {}'.format(quote('user'), quote('is_admin'), false)))
			changed.append('user.is_admin')
		if 'suspended_at' not in columns:
			kind = sa.DateTime().compile(dialect = engine.dialect)
			with engine.begin() as conn:
				conn.execute(sa.text('ALTER TABLE {} ADD COLUMN {} {} NULL'.format(quote('user'), quote('suspended_at'), kind)))
			changed.append('user.suspended_at')
	return changed

engine = sa.create_engine(settings.DB, echo='debug' if settings.DEBUG and settings.DEBUG_FULL and settings.DEBUG_LOG_SQL_QUERIES else None)
session_factory = sessionmaker(bind = engine)

@contextmanager
def Session() -> Iterator[Any]:
	if Session._depth > 0: # type: ignore
		yield Session._global # type: ignore
		return
	session = session_factory()
	Session._global = session # type: ignore
	Session._depth += 1 # type: ignore
	try:
		yield session
		session.commit()
	except:
		session.rollback()
		raise
	finally:
		session.close()
		Session._global = None # type: ignore
		Session._depth -= 1 # type: ignore
Session._global = None # type: ignore
Session._depth = 0 # type: ignore