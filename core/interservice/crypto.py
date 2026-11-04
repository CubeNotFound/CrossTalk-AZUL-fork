import base64, hashlib, hmac, os, secrets, struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
	from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
	HAS_MLKEM = True
except ImportError:
	HAS_MLKEM = False

MAGIC = b'KNIT'
TRANSPORT_VERSION = 2
IV_SIZE = 16
KEY_SIZE = 32
HELLO_SIZE = len(MAGIC) + 2 + KEY_SIZE
WELCOME_SIZE = len(MAGIC) + 2 + KEY_SIZE + 16
RECORD_HEADER = struct.Struct('>I')
TAG_SIZE = 16
MAX_DATA = 32 * 1024
MAX_PADDING = 64
MAX_RECORD = 1 + MAX_DATA + 2 + MAX_PADDING + 2 * TAG_SIZE + 2048
MLKEM_PUBLIC_SIZE = 1184
MLKEM_CIPHERTEXT_SIZE = 1088
CODE_ID_SIZE = 16
CODE_SECRET_SIZE = 32
MAX_LABEL = 100

FLAG_PQ = 0x01
FLAG_ENROLL = 0x02

REC_CLIENT_KEX = 0x01
REC_SERVER_KEX = 0x02
REC_DATA = 0x03
REC_REJECT = 0x04

CHALLENGE_IDN = b'INS2-IDN'
CHALLENGE_CHK = b'INS2-CHK'

HOST_KEY_FILE = 'host.key'
HOST_PUB_FILE = 'host.pub'
ENROLLMENT_CODE_PREFIX = 'ins2-'

class Reject:
	UnknownKey = 1
	WrongAddress = 2
	WrongMachine = 3
	BadEnrollment = 4
	Revoked = 5
	WrongIdentifier = 6
	TooManyAttempts = 7

	MESSAGES = {
		UnknownKey: 'this client key is not enrolled on the server',
		WrongAddress: 'this client key is not allowed from this address',
		WrongMachine: 'this client key belongs to a different machine or OS install',
		BadEnrollment: 'the enrollment code is not valid, was already used or has expired',
		Revoked: 'this client key was revoked',
		WrongIdentifier: 'this client key is not allowed to use that identifier',
		TooManyAttempts: 'too many failed attempts from this address, try again later',
	}

class INSCryptoError(Exception):
	pass

class INSRejected(INSCryptoError):
	reason: int

	def __init__(self, reason: int, detail: str | None = None) -> None:
		super().__init__(detail or Reject.MESSAGES.get(reason, 'rejected by the server ({})'.format(reason)))
		self.reason = reason

@dataclass(frozen = True)
class EnrollmentRequest:
	code_id: bytes
	secret: bytes
	auth_public: bytes
	identifier: str
	label: str

@dataclass(frozen = True)
class ClientHello:
	transport_public: bytes
	machine: bytes
	enrollment: EnrollmentRequest | None

def _nonce(counter: int) -> bytes:
	return struct.pack('>4xQ', counter)

def raw_public(key: X25519PublicKey | Ed25519PublicKey) -> bytes:
	return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
	return HKDF(algorithm = hashes.SHA256(), length = length, salt = salt, info = info).derive(ikm)

def _exchange(private: X25519PrivateKey, public: X25519PublicKey) -> bytes:
	try:
		return private.exchange(public)
	except ValueError as ex:
		raise INSCryptoError('invalid key exchange') from ex

def _x25519(raw: bytes) -> X25519PublicKey:
	try:
		return X25519PublicKey.from_public_bytes(raw)
	except ValueError as ex:
		raise INSCryptoError('invalid X25519 key') from ex

def _short_string(data: bytes, offset: int, limit: int) -> tuple[str, int]:
	if offset >= len(data):
		raise INSCryptoError('truncated enrollment')
	length = data[offset]
	end = offset + 1 + length
	if length > limit or end > len(data):
		raise INSCryptoError('invalid enrollment')
	try:
		return data[offset + 1:end].decode('utf-8'), end
	except UnicodeDecodeError as ex:
		raise INSCryptoError('invalid enrollment') from ex

def _pack_string(value: str, limit: int) -> bytes:
	data = value.encode('utf-8')[:limit]
	while data:
		try:
			data.decode('utf-8')
			break
		except UnicodeDecodeError:
			data = data[:-1]
	return bytes((len(data),)) + data

class _Veil:
	__slots__ = ('_ctx',)

	def __init__(self, server_public: bytes, iv: bytes, direction: bytes) -> None:
		key = _hkdf(server_public, iv, b'INS2 veil ' + direction)
		self._ctx = Cipher(algorithms.AES(key), modes.CTR(bytes(16))).encryptor()

	def apply(self, data: bytes) -> bytes:
		return self._ctx.update(data)

class SecureChannel:
	__slots__ = (
		'_initiator', '_server_public', '_host_key', '_resolver', '_client_key', '_machine', '_enrollment', '_ephemeral',
		'_peer_ephemeral', '_buffer', '_outbox', '_out_veil', '_in_veil', '_link_send', '_link_recv', '_link_send_ctr',
		'_link_recv_ctr', '_link_binding', '_kex_x25519', '_kex_mlkem', '_kex_random', '_client_body', '_client_send',
		'_client_recv', '_client_send_ctr', '_client_recv_ctr', 'binding', 'established', 'post_quantum', 'pq_offer',
		'identity', 'enrolled', 'rejected',
	)

	def __init__(self) -> None:
		raise TypeError('use SecureChannel.client or SecureChannel.server')

	@classmethod
	def _new(cls, initiator: bool, server_public: bytes, pq_offer: bool) -> 'SecureChannel':
		self = object.__new__(cls)
		self._initiator = initiator
		self._server_public = server_public
		self._host_key: X25519PrivateKey | None = None
		self._resolver: Callable[[ClientHello], Any] | None = None
		self._client_key: X25519PrivateKey | None = None
		self._machine = b''
		self._enrollment: EnrollmentRequest | None = None
		self._ephemeral = X25519PrivateKey.generate()
		self._peer_ephemeral: X25519PublicKey | None = None
		self._buffer = bytearray()
		self._outbox = bytearray()
		self._out_veil: _Veil | None = None
		self._in_veil: _Veil | None = None
		self._link_send: ChaCha20Poly1305 | None = None
		self._link_recv: ChaCha20Poly1305 | None = None
		self._link_send_ctr = 0
		self._link_recv_ctr = 0
		self._link_binding = b''
		self._kex_x25519 = X25519PrivateKey.generate()
		self._kex_mlkem: MLKEM768PrivateKey | None = None
		self._kex_random = secrets.token_bytes(32)
		self._client_body = b''
		self._client_send: AESGCM | None = None
		self._client_recv: AESGCM | None = None
		self._client_send_ctr = 0
		self._client_recv_ctr = 0
		self.binding = b''
		self.established = False
		self.post_quantum = False
		self.pq_offer = pq_offer and HAS_MLKEM
		self.identity = None # type: Any
		self.enrolled = False
		self.rejected: int | None = None
		return self

	@classmethod
	def client(
		cls, server_public: X25519PublicKey | bytes, client_key: X25519PrivateKey, machine: bytes, *,
		enrollment: EnrollmentRequest | None = None, pq_offer: bool = True,
	) -> 'SecureChannel':
		server_raw = server_public if isinstance(server_public, bytes) else raw_public(server_public)
		if len(server_raw) != KEY_SIZE or len(machine) != 32:
			raise INSCryptoError('invalid server key or machine fingerprint')
		self = cls._new(True, server_raw, pq_offer)
		self._client_key = client_key
		self._machine = machine
		self._enrollment = enrollment
		self._start_veil()
		self._write_veiled(MAGIC + bytes((TRANSPORT_VERSION, FLAG_PQ if self.pq_offer else 0)) + raw_public(self._ephemeral.public_key()))
		return self

	@classmethod
	def server(cls, host_key: X25519PrivateKey, resolver: Callable[[ClientHello], Any], *, pq_offer: bool = True) -> 'SecureChannel':
		self = cls._new(False, raw_public(host_key.public_key()), pq_offer)
		self._host_key = host_key
		self._resolver = resolver
		return self

	def _start_veil(self) -> None:
		iv = secrets.token_bytes(IV_SIZE)
		self._out_veil = _Veil(self._server_public, iv, b'c2s' if self._initiator else b's2c')
		self._outbox += iv

	def _write_veiled(self, data: bytes) -> None:
		assert self._out_veil is not None
		self._outbox += self._out_veil.apply(data)

	def receive(self, data: bytes) -> list[bytes]:
		if self.rejected is not None:
			raise INSRejected(self.rejected)
		if self._in_veil is None:
			self._buffer += data
			if len(self._buffer) < IV_SIZE:
				return []
			iv = bytes(self._buffer[:IV_SIZE])
			rest = bytes(self._buffer[IV_SIZE:])
			self._buffer.clear()
			self._in_veil = _Veil(self._server_public, iv, b's2c' if self._initiator else b'c2s')
			data = rest
		self._buffer += self._in_veil.apply(data)
		chunks: list[bytes] = []
		if self._link_recv is None and not self._link_handshake():
			return chunks
		while len(self._buffer) >= RECORD_HEADER.size:
			(size,) = RECORD_HEADER.unpack_from(self._buffer)
			if size < TAG_SIZE + 1 or size > MAX_RECORD:
				raise INSCryptoError('invalid record size {}'.format(size))
			if len(self._buffer) < RECORD_HEADER.size + size:
				break
			header = bytes(self._buffer[:RECORD_HEADER.size])
			body = bytes(self._buffer[RECORD_HEADER.size:RECORD_HEADER.size + size])
			del self._buffer[:RECORD_HEADER.size + size]
			assert self._link_recv is not None
			try:
				record = self._link_recv.decrypt(_nonce(self._link_recv_ctr), body, header)
			except InvalidTag as ex:
				raise INSCryptoError('link record failed authentication') from ex
			self._link_recv_ctr += 1
			chunk = self._on_record(record)
			if chunk:
				chunks.append(chunk)
		return chunks

	def _link_handshake(self) -> bool:
		expected = (WELCOME_SIZE if self._initiator else HELLO_SIZE)
		if len(self._buffer) < len(MAGIC):
			return False
		if bytes(self._buffer[:len(MAGIC)]) != MAGIC:
			raise INSCryptoError('unrecognised traffic')
		if len(self._buffer) < expected:
			return False
		message = bytes(self._buffer[:expected])
		del self._buffer[:expected]
		if message[4] != TRANSPORT_VERSION:
			raise INSCryptoError('unsupported transport version {}'.format(message[4]))
		peer_raw = message[6:38]
		peer = _x25519(peer_raw)
		self._peer_ephemeral = peer
		own_raw = raw_public(self._ephemeral.public_key())
		client_raw, server_raw = ((own_raw, peer_raw) if self._initiator else (peer_raw, own_raw))
		self._link_binding = hashlib.sha256(b'INS2 link' + self._server_public + client_raw + server_raw).digest()
		ee = _exchange(self._ephemeral, peer)
		if self._initiator:
			es = _exchange(self._ephemeral, _x25519(self._server_public))
		else:
			assert self._host_key is not None
			es = _exchange(self._host_key, peer)
		okm = _hkdf(ee + es, self._link_binding, b'INS2 link keys', 64)
		c2s, s2c = ChaCha20Poly1305(okm[:32]), ChaCha20Poly1305(okm[32:])
		if self._initiator:
			self._link_send, self._link_recv = c2s, s2c
			try:
				s2c.decrypt(_nonce(0), message[38:], self._link_binding)
			except InvalidTag as ex:
				raise INSCryptoError('the server did not prove the host key this client trusts') from ex
			self._link_recv_ctr = 1
			self.pq_offer = self.pq_offer and bool(message[5] & FLAG_PQ)
			self._send_client_kex()
		else:
			self._link_send, self._link_recv = s2c, c2s
			self.pq_offer = self.pq_offer and bool(message[5] & FLAG_PQ)
			self._start_veil()
			self._write_veiled(MAGIC + bytes((TRANSPORT_VERSION, FLAG_PQ if self.pq_offer else 0)) + own_raw + s2c.encrypt(_nonce(0), b'', self._link_binding))
			self._link_send_ctr = 1
		return True

	def _send_record(self, record: bytes) -> None:
		assert self._link_send is not None
		header = RECORD_HEADER.pack(len(record) + TAG_SIZE)
		self._write_veiled(header + self._link_send.encrypt(_nonce(self._link_send_ctr), record, header))
		self._link_send_ctr += 1

	def _send_client_kex(self) -> None:
		assert self._client_key is not None
		flags = 0
		body = raw_public(self._client_key.public_key()) + raw_public(self._kex_x25519.public_key()) + self._kex_random + self._machine
		if self.pq_offer:
			self._kex_mlkem = MLKEM768PrivateKey.generate()
			body += self._kex_mlkem.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
			flags |= FLAG_PQ
		enrollment = self._enrollment
		if enrollment is not None:
			flags |= FLAG_ENROLL
			body += (
				enrollment.code_id + enrollment.secret + enrollment.auth_public
				+ _pack_string(enrollment.identifier, 64) + _pack_string(enrollment.label, MAX_LABEL)
			)
		self._client_body = bytes((flags,)) + body
		self._send_record(bytes((REC_CLIENT_KEX,)) + self._client_body)

	def _derive_client_key(self, client_body: bytes, server_body: bytes, shared: bytes) -> tuple[bytes, bytes]:
		self.binding = hashlib.sha256(b'INS2 client' + self._link_binding + client_body + server_body).digest()
		okm = _hkdf(shared, self.binding, b'INS2 client keys', 64)
		return okm[:32], okm[32:]

	def _parse_client_kex(self, body: bytes) -> tuple[ClientHello, bytes, bytes, bytes | None]:
		if len(body) < 1 + 4 * KEY_SIZE:
			raise INSCryptoError('truncated client KEX')
		flags = body[0]
		static_raw = body[1:33]
		kex_raw = body[33:65]
		machine = body[97:129]
		offset = 129
		mlkem_raw: bytes | None = None
		if flags & FLAG_PQ:
			mlkem_raw = body[offset:offset + MLKEM_PUBLIC_SIZE]
			if len(mlkem_raw) != MLKEM_PUBLIC_SIZE:
				raise INSCryptoError('truncated ML-KEM key')
			offset += MLKEM_PUBLIC_SIZE
		enrollment: EnrollmentRequest | None = None
		if flags & FLAG_ENROLL:
			end = offset + CODE_ID_SIZE + CODE_SECRET_SIZE + KEY_SIZE
			if len(body) < end:
				raise INSCryptoError('truncated enrollment')
			code_id = body[offset:offset + CODE_ID_SIZE]
			secret = body[offset + CODE_ID_SIZE:offset + CODE_ID_SIZE + CODE_SECRET_SIZE]
			auth_raw = body[end - KEY_SIZE:end]
			identifier, offset = _short_string(body, end, 64)
			label, offset = _short_string(body, offset, MAX_LABEL)
			enrollment = EnrollmentRequest(code_id, secret, auth_raw, identifier, label)
		if offset != len(body):
			raise INSCryptoError('unexpected bytes after client KEX')
		return ClientHello(static_raw, machine, enrollment), static_raw, kex_raw, mlkem_raw

	def reject(self, reason: int) -> None:
		if self.rejected is None and self._link_send is not None:
			self._send_record(bytes((REC_REJECT, reason & 0xff)))
		self.rejected = reason

	def _on_record(self, record: bytes) -> bytes | None:
		kind = record[0]
		if kind == REC_DATA and self.established:
			assert self._client_recv is not None
			try:
				inner = self._client_recv.decrypt(_nonce(self._client_recv_ctr), record[1:], b'\x03')
			except InvalidTag as ex:
				raise INSCryptoError('client record failed authentication') from ex
			self._client_recv_ctr += 1
			(length,) = struct.unpack_from('>H', inner)
			if length > len(inner) - 2:
				raise INSCryptoError('invalid data length')
			return inner[2:2 + length]
		if kind == REC_CLIENT_KEX and not self._initiator and self._client_send is None:
			hello, static_raw, kex_raw, mlkem_raw = self._parse_client_kex(record[1:])
			assert self._resolver is not None
			try:
				self.identity = self._resolver(hello)
			except INSRejected as ex:
				self.reject(ex.reason)
				raise
			self.enrolled = hello.enrollment is not None
			shared = _exchange(self._kex_x25519, _x25519(kex_raw))
			shared += _exchange(self._ephemeral, _x25519(static_raw))
			pq_part = b''
			used_pq = mlkem_raw is not None and self.pq_offer
			if used_pq:
				assert mlkem_raw is not None
				try:
					mlkem_pub = MLKEM768PublicKey.from_public_bytes(mlkem_raw)
				except ValueError as ex:
					raise INSCryptoError('invalid ML-KEM key') from ex
				pq_shared, pq_part = mlkem_pub.encapsulate()
				shared += pq_shared
			flags = (FLAG_PQ if used_pq else 0) | (FLAG_ENROLL if self.enrolled else 0)
			server_body = bytes((flags,)) + raw_public(self._kex_x25519.public_key()) + self._kex_random + pq_part
			client_random = record[66:98]
			c2s, s2c = self._derive_client_key(record[1:], server_body, shared + client_random + self._kex_random)
			self._client_send, self._client_recv = AESGCM(s2c), AESGCM(c2s)
			self._send_record(bytes((REC_SERVER_KEX,)) + server_body + self._client_send.encrypt(_nonce(0), b'', self.binding))
			self._client_send_ctr = 1
			self.post_quantum = used_pq
			self.established = True
			return None
		if kind == REC_SERVER_KEX and self._initiator and self._client_recv is None:
			assert self._client_key is not None and self._peer_ephemeral is not None
			flags = record[1]
			used_pq = bool(flags & FLAG_PQ)
			end = 66 + (MLKEM_CIPHERTEXT_SIZE if used_pq else 0)
			if len(record) != end + TAG_SIZE:
				raise INSCryptoError('invalid server KEX')
			server_body = record[1:end]
			shared = _exchange(self._kex_x25519, _x25519(record[2:34]))
			shared += _exchange(self._client_key, self._peer_ephemeral)
			if used_pq:
				if self._kex_mlkem is None:
					raise INSCryptoError('server used ML-KEM that was not offered')
				try:
					shared += self._kex_mlkem.decapsulate(record[66:end])
				except ValueError as ex:
					raise INSCryptoError('invalid ML-KEM ciphertext') from ex
			c2s, s2c = self._derive_client_key(self._client_body, server_body, shared + self._kex_random + record[34:66])
			self._client_send, self._client_recv = AESGCM(c2s), AESGCM(s2c)
			try:
				self._client_recv.decrypt(_nonce(0), record[end:], self.binding)
			except InvalidTag as ex:
				raise INSCryptoError('server failed client key confirmation') from ex
			self._client_recv_ctr = 1
			self.post_quantum = used_pq
			self.enrolled = bool(flags & FLAG_ENROLL)
			self.established = True
			return None
		if kind == REC_REJECT and self._initiator and len(record) == 2:
			self.rejected = record[1]
			raise INSRejected(record[1])
		raise INSCryptoError('unexpected record type {}'.format(kind))

	def send(self, plaintext: bytes) -> None:
		if not plaintext:
			return
		if not self.established or self._client_send is None:
			raise INSCryptoError('channel not established')
		for i in range(0, len(plaintext), MAX_DATA):
			chunk = plaintext[i:i + MAX_DATA]
			inner = struct.pack('>H', len(chunk)) + chunk + secrets.token_bytes(secrets.randbelow(MAX_PADDING + 1))
			self._send_record(bytes((REC_DATA,)) + self._client_send.encrypt(_nonce(self._client_send_ctr), inner, b'\x03'))
			self._client_send_ctr += 1

	def drain(self) -> bytes:
		if not self._outbox:
			return b''
		data = bytes(self._outbox)
		self._outbox.clear()
		return data

def _challenge_message(purpose: bytes, nonce: bytes, binding: bytes, identifier: str) -> bytes:
	return purpose + b'\x00' + identifier.encode('utf-8') + b'\x00' + nonce + binding

def sign_challenge(key: Ed25519PrivateKey, purpose: bytes, nonce: bytes, binding: bytes, identifier: str = '') -> str:
	return base64.b64encode(key.sign(_challenge_message(purpose, nonce, binding, identifier))).decode('ascii')

def verify_challenge(key: Ed25519PublicKey, signature: str, purpose: bytes, nonce: bytes, binding: bytes, identifier: str = '') -> bool:
	try:
		key.verify(base64.b64decode(signature, validate = True), _challenge_message(purpose, nonce, binding, identifier))
	except (InvalidSignature, ValueError):
		return False
	return True

def ed25519_public(raw: bytes) -> Ed25519PublicKey:
	try:
		return Ed25519PublicKey.from_public_bytes(raw)
	except ValueError as ex:
		raise INSCryptoError('invalid Ed25519 key') from ex

def fingerprint(key: X25519PublicKey | Ed25519PublicKey | bytes) -> str:
	digest = hashlib.sha256(key if isinstance(key, bytes) else raw_public(key)).hexdigest()
	return ':'.join(digest[i:i + 4] for i in range(0, 32, 4))

def b64(data: bytes) -> str:
	return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def unb64(text: str) -> bytes:
	try:
		return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
	except (ValueError, TypeError) as ex:
		raise INSCryptoError('invalid base64') from ex

def make_enrollment_code(server_public: bytes, code_id: bytes, secret: bytes) -> str:
	body = bytes((1,)) + server_public + code_id + secret
	return ENROLLMENT_CODE_PREFIX + b64(body + hashlib.sha256(body).digest()[:4])

def parse_enrollment_code(code: str) -> tuple[bytes, bytes, bytes]:
	code = ''.join(code.split())
	if not code.lower().startswith(ENROLLMENT_CODE_PREFIX):
		raise INSCryptoError('not an INS2 enrollment code')
	data = unb64(code[len(ENROLLMENT_CODE_PREFIX):])
	body, check = data[:-4], data[-4:]
	if len(body) != 1 + KEY_SIZE + CODE_ID_SIZE + CODE_SECRET_SIZE or body[0] != 1 or not hmac.compare_digest(hashlib.sha256(body).digest()[:4], check):
		raise INSCryptoError('the enrollment code is damaged or incomplete')
	return body[1:33], body[33:49], body[49:81]

def _write_new(path: Path, data: bytes, mode: int) -> None:
	fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
	with os.fdopen(fd, 'wb') as f:
		f.write(data)

def _private_pem(key: X25519PrivateKey) -> bytes:
	return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

def _public_pem(key: X25519PublicKey) -> bytes:
	return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

@dataclass(frozen = True)
class ServerKeys:
	host: X25519PrivateKey
	generated: bool

	@property
	def public_raw(self) -> bytes:
		return raw_public(self.host.public_key())

def load_or_generate_server_keys(directory: str | os.PathLike[str]) -> ServerKeys:
	base = Path(directory)
	base.mkdir(parents = True, exist_ok = True)
	key_path = base / HOST_KEY_FILE
	if key_path.exists():
		key = serialization.load_pem_private_key(key_path.read_bytes(), password = None)
		if not isinstance(key, X25519PrivateKey):
			raise INSCryptoError('{} must be an X25519 private key'.format(key_path))
		return ServerKeys(key, False)
	if (base / HOST_PUB_FILE).exists():
		raise INSCryptoError('{} is missing but {} exists'.format(key_path, base / HOST_PUB_FILE))
	key = X25519PrivateKey.generate()
	_write_new(key_path, _private_pem(key), 0o600)
	_write_new(base / HOST_PUB_FILE, _public_pem(key.public_key()), 0o644)
	return ServerKeys(key, True)
