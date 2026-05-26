from . import buffer   # because of circular imports, would've prefered to do `from .buffer import ...` but oh well

from dataclasses import dataclass
from typing import Optional


@dataclass
class TLV:
	__slots__ = ('type', 'data')

	type: int
	data: bytes

	def __init__(self, type: int, data: bytes | str = b''):
		self.type = type

		if isinstance(data, str):
			self.data = data.encode()
		else:
			self.data = data

	def marshal(self) -> bytes:
		buf = buffer.Buffer()
		buf.write_u16(self.type)
		buf.write_u16(len(self.data))
		buf.write_bytes(self.data)

		return buf.data


def marshal_tlvs(tlvs: list[TLV]) -> bytes:
	return b''.join([tlv.marshal() for tlv in tlvs])


def unmarshal_tlvs(data: bytes) -> list[TLV]:
	buf = buffer.Buffer(data)
	tlvs = []

	while len(buf) > 4:
		type = buf.read_u16()
		length = buf.read_u16()
		value = buf.read_bytes(length)

		tlvs.append(TLV(type, value))

	return tlvs


def find_tlv(tlvs: list[TLV], type: int) -> Optional[TLV]:
	for tlv in tlvs:
		if tlv.type == type:
			return tlv

	return None
