from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path
from typing import Optional, Tuple

STORAGE_BASE = Path('storage/dp')
PHOTO_STORAGE_BASE = Path('storage/photos')
THUMB_SIZE = (21, 21)
IM_SIZE   = (96, 96)

def compute_md5(data: bytes) -> str:
	return hashlib.md5(data).hexdigest()[:16]

def get_img_type(data: bytes) -> Optional[str]:
	if data[:6] in (b'GIF87a', b'GIF89a'):
		return 'gif'
	if data[:2] == b'\xff\xd8':
		return 'jpeg'
	if data[:8] == b'\x89PNG\r\n\x1a\n':
		return 'png'
	return None

def get_avatar_dir(uuid: str) -> Path:
	return STORAGE_BASE / uuid

def store_avatar_file(uuid: str, data: bytes, ext: str) -> str:
	from PIL import Image

	md5 = compute_md5(data)
	avatar_dir = get_avatar_dir(uuid)
	avatar_dir.mkdir(parents=True, exist_ok=True)

	full_path  = avatar_dir / f'{md5}.{ext}'
	thumb_path = avatar_dir / f'{md5}_thumb.png'
	im_path   = avatar_dir / f'{md5}_im.png'

	if not full_path.exists():
		full_path.write_bytes(data)

	if not thumb_path.exists() or not im_path.exists():
		try:
			img = Image.open(BytesIO(data))
			if not thumb_path.exists():
				img.resize(THUMB_SIZE).save(str(thumb_path))
			if not im_path.exists():
				img.resize(IM_SIZE).save(str(im_path))
		except Exception:
			pass 

	return md5


def store_photo_file(uuid: str, data: bytes, ext: str) -> str:
	photo_dir = PHOTO_STORAGE_BASE / uuid
	photo_dir.mkdir(parents=True, exist_ok=True)
	name = f'{compute_md5(data)}.{ext}'
	path = photo_dir / name
	if not path.exists():
		path.write_bytes(data)
	return name

def get_photo_data(uuid: str, name: str) -> Optional[Tuple[bytes, str]]:
	path = PHOTO_STORAGE_BASE / uuid / name
	if not path.is_file():
		return None
	try:
		data = path.read_bytes()
	except OSError:
		return None
	return data, 'image/' + path.suffix.lstrip('.').lower()


def find_avatar_file(
	uuid: str,
	md5: str,
	*,
	small: bool = False,
	im: bool = False,
) -> Optional[Path]:
	avatar_dir = get_avatar_dir(uuid)
	if not avatar_dir.is_dir():
		return None

	if small:
		thumb = avatar_dir / f'{md5}_thumb.png'
		if thumb.is_file():
			return thumb

	elif im:
		im_file = avatar_dir / f'{md5}_im.png'
		if im_file.is_file():
			return im_file

	for p in avatar_dir.iterdir():
		if p.is_file() and p.stem == md5:
			return p

	return None


def get_avatar_data(
	uuid: str,
	md5: Optional[str],
	*,
	small: bool = False,
	im: bool = False,
) -> Optional[Tuple[bytes, str]]:
	if not md5:
		return None

	path = find_avatar_file(uuid, md5, small=small, im=im)
	if path is None:
		return None

	try:
		data = path.read_bytes()
	except OSError:
		return None

	if not data:
		return None

	ext = path.suffix.lstrip('.').lower() or 'png'
	mime_map = {'jpg': 'jpeg', 'jpeg': 'jpeg', 'png': 'png', 'gif': 'gif'}
	content_type = 'image/' + mime_map.get(ext, ext)
	return data, content_type