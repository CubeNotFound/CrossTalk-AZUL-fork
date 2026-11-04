import asyncio
import hashlib
import struct

from enum import IntEnum, IntFlag
from io import BytesIO
from pathlib import Path
from typing import Callable, TYPE_CHECKING

from core.models import User
from util.avatar import get_avatar_data

if TYPE_CHECKING:
	from core.backend import BackendSession


class BARTType(IntEnum):
	BuddyIconSmall = 0x0000
	BuddyIcon = 0x0001
	StatusStr = 0x0002
	ArriveSound = 0x0003
	RichName = 0x0004
	SuperIcon = 0x0005
	BuddyIconBig = 0x000C

class BARTFlags(IntFlag):
	Known = 0x00
	Custom = 0x01
	Url = 0x02
	Data = 0x04
	Unknown = 0x40
	Redirect = 0x80

class BARTReplyCode(IntEnum):
	Success = 0x00
	Invalid = 0x01
	NoCustom = 0x02
	TooSmall = 0x03
	TooBig = 0x04
	InvalidType = 0x05
	Banned = 0x06
	NotFound = 0x07

CLEAR_ICON_HASH = bytes.fromhex('0201d20472')

BLANK_GIF = bytes([
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x32, 0x00, 0x32, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x32, 0x00, 0x32, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
])

ICON_SIZE = (48, 48)
MAX_ICON_BYTES = 7168

BART_STORAGE = Path('storage/bart')

_stored: set[bytes] = set()
_items: dict[bytes, bytes] = {}
_MAX_CACHED_ITEMS = 512
_avatar_icons: dict[tuple[str, str], tuple[bytes, bytes]] = {}
_avatar_by_hash: dict[bytes, tuple[str, str]] = {}
_preparing: set[tuple[str, str]] = set()
_refresh_hook: Callable[[User], None] | None = None

def _load_index() -> None:
	try:
		if BART_STORAGE.is_dir():
			for path in BART_STORAGE.iterdir():
				try:
					_stored.add(bytes.fromhex(path.name))
				except ValueError:
					continue
	except OSError:
		pass

_load_index()


def set_refresh_hook(hook: Callable[[User], None]) -> None:
	global _refresh_hook
	_refresh_hook = hook

def build_bart_id(type: int, flags: int, hash: bytes) -> bytes:
	# BART_ID: u16 type, u8 flags, u8 length, then the hash (a BART_INFO behind the type)
	return struct.pack('>HBB', type, flags, len(hash)) + hash

def parse_bart_info(data: bytes) -> tuple[int, bytes] | None:
	# BART_INFO: u8 flags, u8 length, hash
	if len(data) < 2 or len(data) < 2 + data[1]:
		return None
	return data[0], data[2:2 + data[1]]

def parse_bart_id(data: bytes) -> tuple[int, int, bytes, bytes] | None:
	# returns type, flags, hash and whatever follows the BART_ID
	if len(data) < 4:
		return None
	type, flags, length = struct.unpack('>HBB', data[:4])
	if len(data) < 4 + length:
		return None
	return type, flags, data[4:4 + length], data[4 + length:]

def is_known(hash: bytes) -> bool:
	return hash == CLEAR_ICON_HASH or hash in _stored or hash in _items or hash in _avatar_by_hash

def _remember(hash: bytes, data: bytes) -> None:
	if len(_items) >= _MAX_CACHED_ITEMS:
		_items.pop(next(iter(_items)))
	_items[hash] = data

def bart_info(user: User, bs: 'BackendSession | None' = None) -> bytes | None:
	# OSERVICE__USERINFO TLV 0x1D: the icon an OSCAR client set this session, else the account's avatar
	icon = bs.front_data.get('oscar0_bart_icon') if bs is not None else None
	if icon is not None:
		flags, hash = icon
		# a cleared icon shows nothing, and one still waiting to be uploaded can't be fetched yet
		if hash == CLEAR_ICON_HASH or flags & BARTFlags.Unknown:
			return None
		return build_bart_id(BARTType.BuddyIcon, flags, hash)
	entry = _avatar_icon(user)
	if entry is None:
		return None
	return build_bart_id(BARTType.BuddyIcon, BARTFlags.Custom, entry[0])

def _avatar_icon(user: User) -> tuple[bytes, bytes] | None:
	if not user.avatar:
		return None
	key = (user.uuid, user.avatar)
	entry = _avatar_icons.get(key)
	if entry is not None or key in _preparing:
		return entry
	# reading and scaling the image is file work, so it happens off the event loop and shows up on the next update
	try:
		loop = asyncio.get_running_loop()
	except RuntimeError:
		return None
	_preparing.add(key)
	loop.create_task(_prepare_avatar(user, key))
	return None

async def _prepare_avatar(user: User, key: tuple[str, str]) -> None:
	try:
		icon = await asyncio.get_running_loop().run_in_executor(None, _load_avatar_icon, key[0], key[1])
	finally:
		_preparing.discard(key)
	if icon is None:
		return
	hash = hashlib.md5(icon).digest()
	_avatar_icons[key] = (hash, icon)
	_avatar_by_hash[hash] = key
	if _refresh_hook is not None and user.avatar == key[1]:
		_refresh_hook(user)

def _load_avatar_icon(uuid: str, avatar: str) -> bytes | None:
	found = get_avatar_data(uuid, avatar)
	if found is None:
		return None
	return to_icon(found[0])

def to_icon(data: bytes) -> bytes | None:
	# AIM 4.x/5.x take GIF, JPEG and BMP icons of up to 48x48; anything else gets scaled down into a GIF
	try:
		from PIL import Image
	except ImportError:
		return data if data[:6] in (b'GIF87a', b'GIF89a') and len(data) <= MAX_ICON_BYTES else None
	try:
		img = Image.open(BytesIO(data))
		img = img.convert('RGBA')
		img.thumbnail(ICON_SIZE)
		out = BytesIO()
		img.convert('RGB').convert('P', palette = Image.ADAPTIVE).save(out, format = 'GIF')
		icon = out.getvalue()
	except Exception:
		return None
	return icon if len(icon) <= MAX_ICON_BYTES else None

async def get_item(hash: bytes) -> bytes | None:
	# BART__DOWNLOAD: whatever image has this hash, from memory, the converted avatars or the BART store on disk
	if hash == CLEAR_ICON_HASH:
		return BLANK_GIF
	data = _items.get(hash)
	if data is not None:
		return data
	key = _avatar_by_hash.get(hash)
	if key is not None and key in _avatar_icons:
		return _avatar_icons[key][1]
	if hash not in _stored:
		return None
	data = await asyncio.get_running_loop().run_in_executor(None, _read_item, hash)
	if data is not None:
		_remember(hash, data)
	return data

def _read_item(hash: bytes) -> bytes | None:
	try:
		return (BART_STORAGE / hash.hex()).read_bytes()
	except OSError:
		return None

async def store_item(data: bytes) -> bytes:
	# BART__UPLOAD: filed by MD5, which is the hash every client computes for an icon
	hash = hashlib.md5(data).digest()
	_remember(hash, data)
	if hash not in _stored:
		await asyncio.get_running_loop().run_in_executor(None, _write_item, hash, data)
		_stored.add(hash)
	return hash

def _write_item(hash: bytes, data: bytes) -> None:
	BART_STORAGE.mkdir(parents = True, exist_ok = True)
	(BART_STORAGE / hash.hex()).write_bytes(data)
