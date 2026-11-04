import calendar
import struct
import time

from enum import IntEnum, IntFlag
from typing import Optional, TYPE_CHECKING

from core.models import Substatus, User

from .bart import bart_info
from .buffer import Buffer
from .names import is_uin
from .tlv import TLV

if TYPE_CHECKING:
	from core.backend import Backend, BackendSession


class UserFlags(IntFlag):
	DamnedTransient = 0x0001
	Administrator = 0x0002
	Aol = 0x0004
	OscarPay = 0x0008
	OscarFree = 0x0010
	Unavailable = 0x0020
	Icq = 0x0040
	Wireless = 0x0080
	Internal = 0x0100
	Fish = 0x0200
	Bot = 0x0400
	Beast = 0x0800
	OneWayWireless = 0x1000
	Official = 0x2000
	BuddyMatchDirect = 0x10000
	BuddyMatchIndirect = 0x20000
	NoKnockKnock = 0x40000
	ForwardMobile = 0x80000

class UserInfoTag(IntEnum):
	UserFlags = 0x01
	SignonTod = 0x03
	IdleTime = 0x04
	MemberSince = 0x05
	Status = 0x06
	IcqDcInfo = 0x0C
	OscarCaps = 0x0D
	OscarOt = 0x0F
	BartInfo = 0x1D
	UserFlags2 = 0x1F

class ICQStatus(IntFlag):
	# OSERVICE__USER_STATUS: the low word is the ICQ status, ICQ clients send the "away" bit along with the stronger ones
	Online = 0x0000
	Away = 0x0001
	Dnd = 0x0002
	NotAvailable = 0x0004
	Occupied = 0x0010
	FreeForChat = 0x0020
	Invisible = 0x0100
	WebAware = 0x00010000
	HideIp = 0x00020000
	Birthday = 0x00080000
	DirectRequireAuth = 0x10000000

# the part of the status dword that says how available someone is (the rest are flags)
ICQ_STATUS_MASK = 0x0000FFFF

# ICQ direct connection info (SNAC(01,1E) TLV 0x0C), zeroed: no direct connections, but ICQ needs the TLV to take an arrival
# u32 ip, u32 port, u8 dc type, u16 dc protocol version, u32 dc cookie, u32 web port, u32 client features, u32 x3 timestamps, u16
ICQ_DC_INFO_EMPTY = bytes(37)

MAX_WARNING = 999

# anything that isn't online, idle, or offline-ish is an "away" state as far as AIM is concerned
AWAY_SUBSTATUSES = frozenset({
	Substatus.Busy, Substatus.Away, Substatus.BRB, Substatus.OnPhone, Substatus.OutToLunch, Substatus.NotAtHome,
	Substatus.NotAtDesk, Substatus.NotInOffice, Substatus.OnVacation, Substatus.SteppedOut,
})

# used for sessions that never sent a capability block (i.e. users on other frontends)
DEFAULT_CAPS = [bytes.fromhex(cap.replace('-', '')) for cap in (
	"09461345-4C7F-11D1-8222-444553540000",
	"094601FF-4C7F-11D1-8222-444553540000",
	"748F2420-6287-11D1-8222-444553540000",
	"09461343-4C7F-11D1-8222-444553540000",
	"09461341-4C7F-11D1-8222-444553540000",
	"09460104-4C7F-11D1-8222-444553540000",
	"09460105-4C7F-11D1-8222-444553540000",
	"09460102-4C7F-11D1-8222-444553540000",
	"09460103-4C7F-11D1-8222-444553540000",
	"09460101-4C7F-11D1-8222-444553540000",
	"0946134A-4C7F-11D1-8222-444553540000",
	"09461346-4C7F-11D1-8222-444553540000",
)]


def pick_session(backend: 'Backend', user: User) -> Optional['BackendSession']:
	sessions = backend.util_get_sessions_by_user(user)
	for bs in sessions:
		if bs.front_data.get('oscar0'):
			return bs
	return sessions[0] if sessions else None

def user_flags(substatus: Substatus) -> UserFlags:
	flags = UserFlags.OscarFree
	if substatus in AWAY_SUBSTATUSES:
		flags |= UserFlags.Unavailable
	return flags

def _unix(dt: object) -> Optional[int]:
	if dt is None:
		return None
	return int(calendar.timegm(dt.timetuple())) # type: ignore

# what an ICQ client reads out of a substatus, for people who aren't on ICQ themselves
_ICQ_STATUS_BY_SUBSTATUS = {
	Substatus.Online: ICQStatus.Online,
	Substatus.Idle: ICQStatus.Online,
	Substatus.Away: ICQStatus.Away,
	Substatus.BRB: ICQStatus.Away,
	Substatus.OutToLunch: ICQStatus.Away,
	Substatus.SteppedOut: ICQStatus.Away,
	Substatus.NotAtDesk: ICQStatus.Away,
	Substatus.NotAtHome: ICQStatus.NotAvailable | ICQStatus.Away,
	Substatus.NotInOffice: ICQStatus.NotAvailable | ICQStatus.Away,
	Substatus.OnVacation: ICQStatus.NotAvailable | ICQStatus.Away,
	Substatus.Busy: ICQStatus.Occupied | ICQStatus.Away,
	Substatus.OnPhone: ICQStatus.Occupied | ICQStatus.Away,
	Substatus.Invisible: ICQStatus.Invisible,
}

def icq_status_from_substatus(substatus: Substatus) -> int:
	return int(_ICQ_STATUS_BY_SUBSTATUS.get(substatus, ICQStatus.Online))

def substatus_from_icq_status(status: int) -> Substatus:
	# the strongest bit wins: DND (0x13) and occupied (0x11) carry the away bit, N/A (0x05) does too
	status &= ICQ_STATUS_MASK
	if status & ICQStatus.Invisible:
		return Substatus.Invisible
	if status & (ICQStatus.Dnd | ICQStatus.Occupied):
		return Substatus.Busy
	if status & ICQStatus.NotAvailable:
		return Substatus.NotAtHome
	if status & ICQStatus.Away:
		return Substatus.Away
	return Substatus.Online

def icq_status_for(user: User, bs: Optional['BackendSession'], substatus: Optional[Substatus] = None) -> int:
	# an ICQ client's own status word (DND rather than occupied, free for chat, web aware...) is passed on while it still holds
	if substatus is None:
		substatus = user.status.substatus
	raw = None
	if bs is not None:
		raw = bs.front_data.get('oscar0_icq_status')
		if raw is None:
			# a pre-OSCAR ICQ client's status dword, kept the same way by that frontend
			raw = bs.front_data.get('icq0_status')
	if raw is not None and substatus_from_icq_status(raw) is substatus:
		return int(raw)
	return icq_status_from_substatus(substatus)

def build_departure(name: str, *, with_flags: bool = True) -> bytes:
	# BUDDY__DEPARTED holds a bare OSERVICE__USERINFO: the TLV count is always there, and ICQ only takes a departure that
	# carries a (zero) user class in it
	buf = Buffer()
	buf.write_string_u8(name)
	buf.write_u16(0)
	buf.write_tlv_block([TLV(UserInfoTag.UserFlags, struct.pack('>H', 0))] if with_flags else [])
	return buf.data

def build_userinfo(
	user: User, bs: Optional['BackendSession'] = None, *,
	substatus: Optional[Substatus] = None, departed: bool = False, name: Optional[str] = None, viewer_icq: bool = False,
) -> bytes:
	# OSERVICE__USERINFO: string08 displayId, u16 warning level, tlvBlock of OSERVICE__USER_INFO_TAGS
	if substatus is None:
		substatus = user.status.substatus
	if name is None:
		name = user.username
	# whoever is shown by UIN is an ICQ user to the client: it wants the ICQ user class, a status word and DC info for them
	icq = is_uin(name)
	
	now = time.time()
	flags = int(user_flags(substatus))
	if icq:
		flags |= UserFlags.Icq
	tlvs = [TLV(UserInfoTag.UserFlags, struct.pack('>H', flags & 0xFFFF))]
	
	# the upper bytes of the flags only get sent when something in them is set
	if flags >> 16:
		tlvs.append(TLV(UserInfoTag.UserFlags2, (flags >> 16).to_bytes(2, 'big')))
	
	if not departed:
		member_since = _unix(user.date_created)
		if member_since is not None:
			tlvs.append(TLV(UserInfoTag.MemberSince, struct.pack('>L', member_since)))
		
		signon = None # type: Optional[int]
		if bs is not None and bs.front_data.get('oscar0_signon') is not None:
			signon = int(bs.front_data['oscar0_signon'])
		else:
			signon = _unix(user.date_login)
		if signon is not None:
			tlvs.append(TLV(UserInfoTag.SignonTod, struct.pack('>L', signon)))
			tlvs.append(TLV(UserInfoTag.OscarOt, struct.pack('>L', max(0, int(now) - signon))))
		
		# idle time is in minutes
		idle_since = bs.front_data.get('oscar0_idle_since') if bs is not None else None
		if idle_since is not None:
			tlvs.append(TLV(UserInfoTag.IdleTime, struct.pack('>H', min(0xFFFF, max(1, int((now - idle_since) // 60))))))
		elif substatus is Substatus.Idle:
			tlvs.append(TLV(UserInfoTag.IdleTime, struct.pack('>H', 1)))
		
		caps = bs.front_data.get('oscar0_caps') if bs is not None else None
		if caps is None and not viewer_icq:
			caps = DEFAULT_CAPS
		# ICQ reads capabilities as what the other side's client can do peer to peer; non-OSCAR users can't do any of it
		if caps is not None:
			tlvs.append(TLV(UserInfoTag.OscarCaps, b''.join(caps)))
		
		if icq or viewer_icq:
			tlvs.append(TLV(UserInfoTag.Status, struct.pack('>L', icq_status_for(user, bs, substatus))))
		if icq:
			dc_info = bs.front_data.get('oscar0_icq_dc') if bs is not None else None
			tlvs.append(TLV(UserInfoTag.IcqDcInfo, dc_info if dc_info is not None else ICQ_DC_INFO_EMPTY))
		
		bart = bart_info(user, bs)
		if bart is not None:
			tlvs.append(TLV(UserInfoTag.BartInfo, bart))
	
	buf = Buffer()
	buf.write_string_u8(name)
	buf.write_u16(max(0, min(MAX_WARNING, int(user.evil_permanent or 0) + int(user.evil_temporary or 0))))
	buf.write_tlv_block(tlvs)
	return buf.data