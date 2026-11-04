import struct

from enum import IntEnum

from util import icq


class Version(IntEnum):
	V1 = 0x0001
	V2 = 0x0002
	V3 = 0x0003
	V4 = 0x0004
	V5 = 0x0005

class Command(IntEnum):
	# what clients send (CMD_*)
	Ack = 0x000A
	ThruServer = 0x010E
	Reconnect = 0x015E
	Login = 0x03E8
	GetDeps = 0x03F2
	RegNewUser = 0x03FC
	ContactList = 0x0406
	SearchUin = 0x041A
	SearchUser = 0x0424
	KeepAlive = 0x042E
	Logoff = 0x0438
	SysMsgDoneAck = 0x0442
	SysMsgReq = 0x044C
	Authorize = 0x0456
	InfoReq = 0x0460
	ExtInfoReq = 0x046A
	SetPassword = 0x049C
	UpdateBasic = 0x04A6
	UpdateDetail = 0x04B0
	GetExternals = 0x04C4
	SetStatus = 0x04D8
	FirstLogin = 0x04EC
	SetBasicInfo = 0x050A
	SetAuth = 0x0514
	KeepAlive2 = 0x051E
	UserAdd = 0x053C
	SetWorkInfo = 0x0578
	SetHomeInfo = 0x0582
	SetHomeWeb = 0x058C
	SetNotes = 0x0596
	GetNotes = 0x05AA
	SetWorkWeb = 0x05BE
	SearchStart = 0x05C8
	RegRequestInfo = 0x05DC
	RegNewUserInfo = 0x05E6
	GetDeps1 = 0x05F0
	UserGetInfo = 0x05FA
	MetaUser = 0x064A
	InvisibleList = 0x06A4
	VisibleList = 0x06AE
	ChangeVILists = 0x06B8

class Server(IntEnum):
	# what the server sends (SRV_*)
	Ack = 0x000A
	SetOffline = 0x0028
	DepsList = 0x0032
	Hello = 0x005A
	WrongPassword = 0x0064
	UserOnline = 0x006E
	UserOffline = 0x0078
	SearchFound = 0x008C
	SearchDone = 0x00A0
	UpdatedBasic = 0x00B4
	UpdateBasicFail = 0x00BE
	UpdatedDetail = 0x00C8
	UpdateDetailFail = 0x00D2
	SysMsgOffline = 0x00DC
	SysMsgDone = 0x00E6
	NotConnected = 0x00F0
	Busy = 0x00FA
	SysMsgOnline = 0x0104
	InfoReply = 0x0118
	ExtInfoReply = 0x0122
	InvalidUin = 0x012C
	UserStatus = 0x01A4
	UpdatedBasicV4 = 0x01E0
	UpdateBasicFailV4 = 0x01EA
	UserListDone = 0x021C
	MetaUser = 0x03DE

class Meta(IntEnum):
	# META_USER (0x064A) requests: the u16 that leads the data
	SetBasic = 0x03E8
	SetBasic2 = 0x03E9
	SetWork = 0x03F2
	SetWork2 = 0x03F3
	SetMore = 0x03FC
	SetMore2 = 0x03FD
	SetAbout = 0x0406
	SetInterests = 0x0410
	SetAffiliations = 0x041A
	SetSecurity = 0x0424
	SetPassword = 0x042E
	SetHomepageCategory = 0x0442
	FullInfo = 0x04B0
	FullInfo2 = 0x04B1
	ShortInfo = 0x04BA
	Unregister = 0x04C4
	LoginInfo = 0x04CE
	LoginInfo2 = 0x04CF
	SearchName = 0x0514
	SearchName2 = 0x0515
	SearchUin = 0x051E
	SearchUin2 = 0x051F
	SearchEmail = 0x0528
	SearchEmail2 = 0x0529
	SearchWhite = 0x0532
	SearchWhite2 = 0x0533
	UsageStats = 0x06B8
	Login = 0x07D0

class MetaReply(IntEnum):
	# SRV_META_USER (0x03DE) replies: the u16 that leads the data, then a u8 result
	SetBasicAck = 0x0064
	SetWorkAck = 0x006E
	SetMoreAck = 0x0078
	SetAboutAck = 0x0082
	SetInterestsAck = 0x008C
	SetAffiliationsAck = 0x0096
	SetSecurityAck = 0x00A0
	SetPasswordAck = 0x00AA
	UnregisterAck = 0x00B4
	SetHomepageCategoryAck = 0x00BE
	BasicInfo = 0x00C8
	WorkInfo = 0x00D2
	MoreInfo = 0x00DC
	About = 0x00E6
	Interests = 0x00F0
	Affiliations = 0x00FA
	ShortInfo = 0x0104
	HomepageCategory = 0x010E
	UserFound = 0x0190
	LastUserFound = 0x019A
	WhiteFound = 0x01A4
	WhiteLastFound = 0x01AE

class MetaResult(IntEnum):
	Ok = 0x0A
	Fail = 0x32

class MessageType(IntEnum):
	# the low byte of a message's type
	Text = 0x01
	Chat = 0x02
	File = 0x03
	Url = 0x04
	AuthRequest = 0x06
	AuthDeny = 0x07
	AuthGrant = 0x08
	Server = 0x09
	Added = 0x0C
	WebPager = 0x0D
	EmailPager = 0x0E
	Contacts = 0x13
	Plugin = 0x1A
	AutoAway = 0xE8
	AutoOccupied = 0xE9
	AutoNotAvailable = 0xEA
	AutoDnd = 0xEB
	AutoFreeForChat = 0xEC

# what the client's fixed-size buffers take
MAX_NICK = 20
MAX_NAME = 64
MAX_PHONE = 30
MAX_HOMEPAGE = 127
MAX_ABOUT = 450
# the longest password a client sends; the rest of the packet isn't trusted past it
MAX_PASSWORD = 20


class LE:
	# a little-endian writer, the only byte order the pre-OSCAR protocol has
	__slots__ = ('data',)

	data: bytearray

	def __init__(self) -> None:
		self.data = bytearray()

	def u8(self, value: int) -> 'LE':
		self.data += struct.pack('<B', value & 0xFF)
		return self

	def u16(self, value: int) -> 'LE':
		self.data += struct.pack('<H', value & 0xFFFF)
		return self

	def u32(self, value: int) -> 'LE':
		self.data += struct.pack('<L', value & 0xFFFFFFFF)
		return self

	def raw(self, value: bytes) -> 'LE':
		self.data += value
		return self

	def string(self, value: str, limit: int = 0) -> 'LE':
		# u16 length counting the NUL, the text, the NUL; an empty string is still a length of 1 and its NUL
		encoded = icq.latin1(value)
		if limit:
			encoded = encoded[:limit]
		return self.u16(len(encoded) + 1).raw(encoded).u8(0)

	def bytes(self) -> bytes:
		return bytes(self.data)

class Reader:
	__slots__ = ('data', 'pos')

	data: bytes
	pos: int

	def __init__(self, data: bytes) -> None:
		self.data = data
		self.pos = 0

	def remaining(self) -> int:
		return len(self.data) - self.pos

	def take(self, length: int) -> bytes:
		if length < 0 or self.pos + length > len(self.data):
			raise ValueError('truncated ICQ packet')
		chunk = self.data[self.pos:self.pos + length]
		self.pos += length
		return chunk

	def skip(self, length: int) -> None:
		self.take(length)

	def u8(self) -> int:
		return self.take(1)[0]

	def u16(self) -> int:
		return struct.unpack('<H', self.take(2))[0]

	def u32(self) -> int:
		return struct.unpack('<L', self.take(4))[0]

	def raw_string(self, limit: int = 0) -> bytes:
		# u16 length, then that many bytes ending in a NUL; a client's own length is trusted only up to `limit`
		length = self.u16()
		if limit and length > limit + 1:
			raw = self.take(length)[:limit]
		else:
			raw = self.take(length)
		if b'\x00' in raw:
			raw = raw[:raw.index(b'\x00')]
		return raw

	def string(self) -> str:
		return icq.from_latin1(self.raw_string())

	def rest(self) -> bytes:
		chunk = self.data[self.pos:]
		self.pos = len(self.data)
		return chunk

def uin_list(data: bytes) -> list[int]:
	# u8 count, then that many u32 UINs (contact, visible and invisible lists); a short packet ends the list early
	reader = Reader(data)
	uins = []
	try:
		count = reader.u8()
		for _ in range(count):
			uins.append(reader.u32())
	except ValueError:
		pass
	return uins
