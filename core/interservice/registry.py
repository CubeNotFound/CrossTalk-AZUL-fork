from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
import hashlib, hmac, ipaddress, secrets, time

import core.db as db
import settings

from .crypto import (
	ClientHello, INSRejected, Reject, b64, unb64, ed25519_public, make_enrollment_code, fingerprint, CODE_ID_SIZE, CODE_SECRET_SIZE,
)

MAX_FAILURES = 10
FAIL_WINDOW = 600
DEFAULT_CODE_HOURS = 24

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

def normalize_address(host: str) -> str:
	try:
		addr = ipaddress.ip_address(host.split('%', 1)[0])
	except ValueError:
		return host
	if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
		addr = addr.ipv4_mapped
	return str(addr)

def parse_address_list(entries: List[str]) -> List[str]:
	result = [] # type: List[str]
	for entry in entries:
		entry = entry.strip()
		if not entry:
			continue
		if '/' in entry:
			value = str(ipaddress.ip_network(entry, strict = False))
		else:
			value = normalize_address(str(ipaddress.ip_address(entry)))
		if value not in result:
			result.append(value)
	return result

def address_allowed(host: str, allowed: List[str]) -> bool:
	try:
		addr = ipaddress.ip_address(normalize_address(host))
	except ValueError:
		return False
	for entry in allowed:
		try:
			if '/' in entry:
				if addr in ipaddress.ip_network(entry, strict = False):
					return True
			elif addr == ipaddress.ip_address(entry):
				return True
		except ValueError:
			continue
	return False

@dataclass
class ClientRecord:
	id: int
	identifier: str
	label: str
	transport_public: bytes
	auth_public: bytes
	machine: bytes
	addresses: List[str]
	created: datetime
	last_seen: Optional[datetime]
	last_address: Optional[str]
	revoked: bool
	revoked_at: Optional[datetime]

	@property
	def fingerprint(self) -> str:
		return fingerprint(self.transport_public)

@dataclass
class EnrollmentRecord:
	id: int
	code_id: str
	identifier: str
	label: str
	address: Optional[str]
	created_by: Optional[str]
	created: datetime
	expires: datetime
	used: Optional[datetime]
	client_id: Optional[int]

	@property
	def state(self) -> str:
		if self.used is not None:
			return 'used'
		if self.expires <= datetime.utcnow():
			return 'expired'
		return 'waiting'

def _client_from_row(row: Any) -> ClientRecord:
	return ClientRecord(
		row.id, row.identifier, row.label or '', unb64(row.transport_public), unb64(row.auth_public), bytes.fromhex(row.machine),
		list(row.addresses or []), row.date_created, row.date_last_seen, row.last_address, bool(row.revoked), row.date_revoked,
	)

def _enrollment_from_row(row: Any) -> EnrollmentRecord:
	return EnrollmentRecord(
		row.id, row.code_id, row.identifier, row.label or '', row.address, row.created_by, row.date_created, row.date_expires,
		row.date_used, row.client_id,
	)

class ClientRegistry:
	__slots__ = ('host_public', '_by_key', '_failures', 'on_revoke')

	host_public: bytes
	_by_key: Dict[bytes, ClientRecord]
	_failures: Dict[str, Deque[float]]
	on_revoke: Optional[Callable[[ClientRecord], None]]

	def __init__(self, host_public: bytes) -> None:
		self.host_public = host_public
		self._by_key = {}
		self._failures = {}
		self.on_revoke = None
		self.reload()

	def reload(self) -> None:
		with db.Session() as sess:
			self._by_key = { record.transport_public: record for record in (_client_from_row(row) for row in sess.query(db.InsClient)) }

	def clients(self) -> List[ClientRecord]:
		return sorted(self._by_key.values(), key = lambda record: (record.revoked, record.identifier.lower(), record.label.lower(), record.id))

	def get(self, client_id: int) -> Optional[ClientRecord]:
		for record in self._by_key.values():
			if record.id == client_id:
				return record
		return None

	def _fail(self, address: str, reason: int, logger: Any, detail: str) -> INSRejected:
		now = time.monotonic()
		failures = self._failures.setdefault(address, deque())
		failures.append(now)
		while failures and now - failures[0] > FAIL_WINDOW:
			failures.popleft()
		if logger is not None:
			logger.info(f'InterService client from {address} turned away: {detail}')
		return INSRejected(reason)

	def _throttled(self, address: str) -> bool:
		failures = self._failures.get(address)
		if not failures:
			return False
		now = time.monotonic()
		while failures and now - failures[0] > FAIL_WINDOW:
			failures.popleft()
		return len(failures) >= MAX_FAILURES

	def resolve(self, hello: ClientHello, peer: str, logger: Any = None) -> ClientRecord:
		address = normalize_address(peer)
		if self._throttled(address):
			raise INSRejected(Reject.TooManyAttempts)
		if hello.enrollment is not None:
			return self._enroll(hello, address, logger)
		record = self._by_key.get(hello.transport_public)
		if record is None:
			raise self._fail(address, Reject.UnknownKey, logger, 'unknown client key')
		if record.revoked:
			raise self._fail(address, Reject.Revoked, logger, f'revoked key of {record.identifier} "{record.label}"')
		if not address_allowed(address, record.addresses):
			raise self._fail(address, Reject.WrongAddress, logger, f'key of {record.identifier} "{record.label}" used from an address it is not bound to')
		if not hmac.compare_digest(record.machine, hello.machine):
			raise self._fail(address, Reject.WrongMachine, logger, f'key of {record.identifier} "{record.label}" used from a different machine or OS install')
		return record

	def _enroll(self, hello: ClientHello, address: str, logger: Any) -> ClientRecord:
		enrollment = hello.enrollment
		assert enrollment is not None
		now = datetime.utcnow()
		if enrollment.identifier not in settings.INS_IDENTIFIERS:
			raise self._fail(address, Reject.WrongIdentifier, logger, f'enrollment for unknown identifier "{enrollment.identifier}"')
		if hello.transport_public in self._by_key:
			raise self._fail(address, Reject.BadEnrollment, logger, 'enrollment with a key that is already enrolled')
		try:
			ed25519_public(enrollment.auth_public)
		except Exception:
			raise self._fail(address, Reject.BadEnrollment, logger, 'enrollment with an invalid auth key')
		with db.Session() as sess:
			row = sess.query(db.InsEnrollment).filter(db.InsEnrollment.code_id == enrollment.code_id.hex()).one_or_none()
			secret_hash = hashlib.sha256(enrollment.secret).hexdigest()
			if row is None or not hmac.compare_digest(row.secret_hash, secret_hash):
				raise self._fail(address, Reject.BadEnrollment, logger, 'unknown enrollment code')
			if row.date_used is not None:
				raise self._fail(address, Reject.BadEnrollment, logger, f'enrollment code for {row.identifier} used again')
			if row.date_expires <= now:
				raise self._fail(address, Reject.BadEnrollment, logger, f'expired enrollment code for {row.identifier}')
			if row.identifier != enrollment.identifier:
				raise self._fail(address, Reject.WrongIdentifier, logger, f'enrollment code for {row.identifier} used for {enrollment.identifier}')
			if row.address and not address_allowed(address, [row.address]):
				raise self._fail(address, Reject.WrongAddress, logger, f'enrollment code for {row.identifier} used from an address it was not made for')
			label = (enrollment.label or row.label or enrollment.identifier)[:100]
			client_row = db.InsClient(
				identifier = enrollment.identifier, label = label, transport_public = b64(hello.transport_public),
				auth_public = b64(enrollment.auth_public), machine = hello.machine.hex(), addresses = [address],
				date_created = now, revoked = False,
			)
			sess.add(client_row)
			sess.flush()
			row.date_used = now
			row.client_id = client_row.id
			record = _client_from_row(client_row)
			replaced = [
				other for other in self._by_key.values()
				if not other.revoked and other.identifier == record.identifier and hmac.compare_digest(other.machine, record.machine)
			]
			for other in replaced:
				other_row = sess.query(db.InsClient).filter(db.InsClient.id == other.id).one_or_none()
				if other_row is not None:
					other_row.revoked = True
					other_row.date_revoked = now
		self._by_key[record.transport_public] = record
		for other in replaced:
			other.revoked = True
			other.revoked_at = now
			if self.on_revoke is not None:
				self.on_revoke(other)
		if logger is not None:
			logger.info(f'InterService client {record.identifier} "{record.label}" enrolled from {address} (key {record.fingerprint})')
		return record

	def seen(self, record: ClientRecord, peer: str) -> None:
		now = datetime.utcnow()
		address = normalize_address(peer)
		record.last_seen = now
		record.last_address = address
		with db.Session() as sess:
			row = sess.query(db.InsClient).filter(db.InsClient.id == record.id).one_or_none()
			if row is not None:
				row.date_last_seen = now
				row.last_address = address

	def create_code(
		self, identifier: str, *, label: str = '', address: Optional[str] = None, hours: int = DEFAULT_CODE_HOURS,
		created_by: Optional[str] = None,
	) -> Tuple[str, EnrollmentRecord]:
		if identifier not in settings.INS_IDENTIFIERS:
			raise ValueError('unknown identifier')
		if address:
			address = parse_address_list([address])[0]
		code_id = secrets.token_bytes(CODE_ID_SIZE)
		secret = secrets.token_bytes(CODE_SECRET_SIZE)
		now = datetime.utcnow()
		with db.Session() as sess:
			row = db.InsEnrollment(
				code_id = code_id.hex(), secret_hash = hashlib.sha256(secret).hexdigest(), identifier = identifier, label = label[:100],
				address = address or None, created_by = created_by, date_created = now,
				date_expires = now + timedelta(hours = max(1, min(hours, 24 * 30))),
			)
			sess.add(row)
			sess.flush()
			record = _enrollment_from_row(row)
		return make_enrollment_code(self.host_public, code_id, secret), record

	def codes(self) -> List[EnrollmentRecord]:
		with db.Session() as sess:
			rows = sess.query(db.InsEnrollment).order_by(db.InsEnrollment.date_created.desc()).limit(200).all()
			return [_enrollment_from_row(row) for row in rows]

	def cancel_code(self, enrollment_id: int) -> bool:
		with db.Session() as sess:
			row = sess.query(db.InsEnrollment).filter(db.InsEnrollment.id == enrollment_id).one_or_none()
			if row is None or row.date_used is not None:
				return False
			sess.delete(row)
		return True

	def revoke(self, client_id: int) -> Optional[ClientRecord]:
		record = self.get(client_id)
		if record is None or record.revoked:
			return record
		now = datetime.utcnow()
		with db.Session() as sess:
			row = sess.query(db.InsClient).filter(db.InsClient.id == client_id).one_or_none()
			if row is not None:
				row.revoked = True
				row.date_revoked = now
		record.revoked = True
		record.revoked_at = now
		if self.on_revoke is not None:
			self.on_revoke(record)
		return record

	def delete(self, client_id: int) -> bool:
		record = self.get(client_id)
		if record is None or not record.revoked:
			return False
		with db.Session() as sess:
			sess.query(db.InsClient).filter(db.InsClient.id == client_id).delete(synchronize_session = False)
		self._by_key.pop(record.transport_public, None)
		return True

	def set_addresses(self, client_id: int, addresses: List[str]) -> ClientRecord:
		record = self.get(client_id)
		if record is None:
			raise KeyError(client_id)
		parsed = parse_address_list(addresses)
		if not parsed:
			raise ValueError('at least one address is needed')
		with db.Session() as sess:
			row = sess.query(db.InsClient).filter(db.InsClient.id == client_id).one_or_none()
			if row is not None:
				row.addresses = parsed
		record.addresses = parsed
		return record
