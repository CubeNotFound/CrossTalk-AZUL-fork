import hashlib, secrets, base64, binascii
from typing import Dict, Optional, Tuple, Any, List, Type

from argon2 import PasswordHasher as Argon2Impl
from argon2.exceptions import VerifyMismatchError

HASHERS: Dict[str, Type['Hasher']] = {}

class Hasher:
	algorithm = 'unknown'
	separator = '$'

	@classmethod
	def encode(cls, password: str, *stuff: Any, salt: Optional[str] = None, identifier: Optional[str] = None) -> str:
		assert password is not None
		if salt is None:
			salt = gen_salt()
		assert cls.separator not in salt

		if identifier is None:
			(hash_bytes, other_stuff) = cls._encode_impl(password, *stuff, salt=salt)
		else:
			(hash_bytes, other_stuff) = cls._encode_impl(password, *stuff, salt=salt, identifier=identifier)

		hash = base64.b64encode(hash_bytes).decode('ascii').strip()
		return cls.separator.join([cls.algorithm] + other_stuff + [salt, hash])

	@classmethod
	def _encode_impl(cls, password: str, *stuff: Any, salt: str, identifier: Optional[str] = None) -> Tuple[bytes, List[str]]:
		raise NotImplementedError('Hasher._encode_impl')

	@classmethod
	def extract_salt(cls, encoded: str) -> Optional[str]:
		return encoded.split(cls.separator)[-2]

	@classmethod
	def extract_hash(cls, encoded: str) -> bytes:
		hash = encoded.split(cls.separator)[-1]
		return base64.b64decode(hash)

	@classmethod
	def verify(cls, password: str, encoded: str) -> bool:
		try:
			(algorithm, *stuff, salt, _) = encoded.split(cls.separator)
		except ValueError:
			return False

		try:
			hasher = HASHERS[algorithm]
		except KeyError:
			return False

		assert algorithm == hasher.algorithm
		encoded_2 = hasher.encode(password, *stuff, salt=salt)
		return secrets.compare_digest(encoded, encoded_2)

class Argon2PasswordHasher(Hasher):
	algorithm = 'argon2id'
	impl = Argon2Impl()

	@classmethod
	def _encode_impl(cls, password: str, *stuff: Any, salt: str) -> Tuple[bytes, List[str]]:
		assert not stuff
		hash_str = cls.impl.hash(password + salt)
		hash_bytes = hash_str.encode('utf-8')
		return hash_bytes, []

	@classmethod
	def verify(cls, password: str, encoded: str) -> bool | str:
		try:
			parts = encoded.split(cls.separator)
			if len(parts) != 3 or parts[0] != cls.algorithm:
				raise ValueError("Not an argon2 hash")
			_, salt, b64hash = parts
			hash_str = base64.b64decode(b64hash).decode('utf-8')
			cls.impl.verify(hash_str, password + salt)
			return True
		except (ValueError, VerifyMismatchError, binascii.Error):
			# PBKDF2 fallback, migrate hash to Argon2
			try:
				parts = encoded.split(cls.separator)
				alg = parts[0]
				if alg != PBKDF2PasswordHasher.algorithm:
					return False
				_, *stuff, salt, _ = parts
				if PBKDF2PasswordHasher.verify(password, encoded):
					return 'MIGRATEMEPLSTHX'
			except Exception:
				return False
			return False

class PBKDF2PasswordHasher(Hasher):
	algorithm = 'pbkdf2_sha256'
	iterations = 24000

	@classmethod
	def _encode_impl(cls, password: str, *stuff: Any, salt: str) -> Tuple[bytes, List[str]]:
		assert len(stuff) <= 1
		iterations: Optional[int] = (stuff[0] if stuff else None)
		if iterations is None:
			iterations = cls.iterations
		iterations = int(iterations)
		hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations, None)
		return hash, [str(iterations)]

class MD5PasswordHasher(Hasher):
	algorithm = 'md5'
	digest = hashlib.md5

	@classmethod
	def _encode_impl(cls, password: str, *stuff: Any, salt: str, identifier: Optional[str] = None) -> Tuple[bytes, List[str]]:
		assert not stuff
		assert salt is not None
		md5 = hashlib.md5()

		if identifier is None:
			md5.update((salt + password).encode('utf-8'))
		else:
			md5.update((salt + password + identifier).encode('utf-8'))

		return md5.digest(), []

	# maybe we could find a better way to do this? it works for now though
	@classmethod
	def encode_aim5(cls, password: str, *, salt: str) -> str:
		md5_pw_raw = hashlib.md5(password.encode('utf-8')).digest()
		md5 = hashlib.md5()
		md5.update(salt.encode('utf-8'))
		md5.update(md5_pw_raw)
		md5.update(b'AOL Instant Messenger (SM)')
		hash_b64 = base64.b64encode(md5.digest()).decode('ascii').strip()
		return cls.separator.join([cls.algorithm, salt, hash_b64])

	@classmethod
	def verify_hash(cls, hash_1: str, encoded: str) -> bool:
		try:
			(_, _, hash) = encoded.split(cls.separator)
		except ValueError:
			return False
		hash = binascii.hexlify(base64.b64decode(hash)).decode('ascii')
		return secrets.compare_digest(hash_1, hash)

class MD5CryptPasswordHasher(Hasher):
	algorithm = 'md5crypt'

	@classmethod
	def _encode_impl(cls, password: str, *stuff: Any, salt: str) -> Tuple[bytes, List[str]]:
		from util.unixmd5crypt import unix_md5_crypt
		assert not stuff
		return unix_md5_crypt(password, salt), []

	@classmethod
	def encode(cls, password: str, *stuff: Any, salt: Optional[str] = None) -> str:
		assert not stuff
		assert salt is not None
		if salt[:3] == '$1$':
			salt = salt[3:]
		salt = salt[:8]
		return super().encode(password, salt=salt)

class SHA1PasswordHasher(Hasher):
	algorithm = 'sha1'
	encoding = 'utf-16le'

	@classmethod
	def encode(cls, password: str, *stuff: Any) -> str:
		assert password is not None

		(hash_bytes, other_stuff) = cls._encode_impl(password, *stuff)

		hash = (base64.b64encode(hash_bytes)
				.decode('ascii')
				.strip())

		return cls.separator.join([cls.algorithm] + other_stuff + [hash])

	@classmethod
	def _encode_impl(cls, password: str, *stuff: Any) -> Tuple[bytes, List[str]]:
		assert not stuff

		sha1 = hashlib.sha1()
		sha1.update(password.encode(cls.encoding))

		return sha1.digest(), []

	@classmethod
	def extract_salt(cls, encoded: str) -> Optional[str]:
		raise NotImplementedError('SHA1PasswordHasher.extract_salt')

	@classmethod
	def verify(cls, password: str, encoded: str) -> bool:
		try:
			(algorithm, *stuff, _) = encoded.split(cls.separator)
		except ValueError:
			return False

		try:
			hasher = HASHERS[algorithm]
		except KeyError:
			return False

		assert algorithm == hasher.algorithm
		encoded_2 = hasher.encode(password, *stuff)
		return secrets.compare_digest(encoded, encoded_2)

HASHERS[Argon2PasswordHasher.algorithm] = Argon2PasswordHasher
HASHERS[PBKDF2PasswordHasher.algorithm] = PBKDF2PasswordHasher
HASHERS[MD5PasswordHasher.algorithm] = MD5PasswordHasher
HASHERS[MD5CryptPasswordHasher.algorithm] = MD5CryptPasswordHasher
HASHERS[SHA1PasswordHasher.algorithm] = SHA1PasswordHasher

def gen_salt(length: int = 15) -> str:
	return secrets.token_hex(length)[:length]

hasher = Argon2PasswordHasher
hasher_pbkdf2 = PBKDF2PasswordHasher
hasher_md5 = MD5PasswordHasher
hasher_md5crypt = MD5CryptPasswordHasher
hasher_sha1 = SHA1PasswordHasher