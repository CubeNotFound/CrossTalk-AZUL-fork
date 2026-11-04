import struct
from typing import Optional

from util.misc import Logger

from ..proto.common import system_message
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..proto.tlv import TLV, unmarshal_tlvs

def popup_display(self, alert_url: Optional[str], alert_txt: str):
	response_msg = SNACMessage(0x0008, 0x0002, 0x0000, 0x00000000)

	response_msg.write_bytes(system_message(alert_url, alert_txt))
	# TODO: pipe to ctrl.send_snac()
	print('TLVs:', unmarshal_tlvs(response_msg.data))
	#client.send_snac(response_msg)
	return response_msg
