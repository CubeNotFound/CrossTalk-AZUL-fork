import struct 

from typing import Optional
from util.misc import Logger

from ..proto.tlv import TLV, marshal_tlvs

def system_message(alert_url: Optional[str], alert_txt: str) -> bytes:
	return marshal_tlvs([
		TLV(0x0003, struct.pack('>H', 0x00D9)),	# message window width
		TLV(0x0004, struct.pack('>H', 0x0096)),	# message window length
		TLV(0x0005, struct.pack('>H', 0x001E)),	 # autohide delay
		TLV(0x0002, alert_url),				 # alert URL
		TLV(0x0001, alert_txt),				 # alert text
	])

	