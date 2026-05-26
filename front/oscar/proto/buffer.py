import struct

from array import array
from dataclasses import dataclass

from .tlv import TLV, marshal_tlvs, unmarshal_tlvs


@dataclass
class Buffer:
	data: bytes

	def __init__(self, data: bytes = b''):
		self.data = data

	def __len__(self) -> int:
		return len(self.data)

	########################
	# read_xxx() functions #
	########################
	def read_bytes(self, length: int) -> bytes:
		"""Reads the specified amount of bytes from the buffer.

		Args:
			length: bytes to read

		Returns:
			bytes: the bytes read
		"""
		value = self.data[:length]

		self.data = self.data[length:]

		return value

	def read_u8(self) -> int:
		"""Reads a byte (8 bits) from the buffer.

		Returns:
			int: The read byte from the buffer.
		"""
		value, = struct.unpack('>B', self.data[:1])

		self.data = self.data[1:]

		return value

	def read_u16(self) -> int:
		"""Reads an unsigned short (16 bits) from the buffer.

		Returns:
			int: The read unsigned short from the buffer.
		"""
		value, = struct.unpack('>H', self.data[:2])

		self.data = self.data[2:]

		return value

	def read_u32(self) -> int:
		"""Reads an unsigned int (32 bits) from the buffer.

		Returns:
			int: The read unsigned int from the buffer.
		"""
		value, = struct.unpack('>L', self.data[:4])

		self.data = self.data[4:]

		return value

	def read_string(self, length: int) -> str:
		"""Reads a string with the specified length from the buffer.

		Args:
			length: The length of the string to read.

		Returns:
			str: The read string from the buffer."""
		str_bytes = self.data[:length]

		self.data = self.data[length:]

		return str_bytes.decode('utf-8')

	def read_string_u8(self) -> str:
		"""Reads a string prepended with a u8 showing the length of the string.

		Returns:
			str: The read string from the buffer.
		"""
		return self.read_string(self.read_u8())

	def read_string_u16(self) -> str:
		"""Reads a string prepended with a u16 showing the length of the string.

		Returns:
			str: The read string from the buffer.
		"""
		return self.read_string(self.read_u16())

	def read_string_u32(self) -> str:
		"""Reads a string prepended with a u32 showing the length of the string.

		Returns:
			str: The read string from the buffer.
		"""
		return self.read_string(self.read_u32())

	def read_tlv_block(self) -> array[TLV]:
		"""Reads a TLV list prepended with a u16 showing the number of TLVs in the list, from the buffer.

		Returns:
			array[TLV]: The TLVs found in the block.
		"""
		length = self.read_u16()
		tlvs = []

		for _ in range(length):
			type, length = struct.unpack('>HH', self.data[0:4])
			value = self.data[4:length + 4]

			# make sure length is not too long
			assert len(self) > length - 4

			tlvs.append(TLV(type, value))
			self.data = self.data[length + 4:]

		return tlvs

	def read_tlv_l_block(self) -> array[TLV]:
		"""Reads a list of TLVs prepended with a u16 showing the length of the total TLV bytes, from the buffer.

		Returns:
			array[TLV]: The TLVs found in the block.
		"""
		length = self.read_u16()
		tlvs = unmarshal_tlvs(self.data[:length])

		self.data = self.data[length:]

		return tlvs

	#########################
	# write_xxx() functions #
	#########################
	def write_bytes(self, value: bytes) -> None:
		"""Writes the specified bytes into the buffer.

		Args:
			value: The bytes to write into the buffer.
		"""
		self.data += value

	def write_u8(self, value: int) -> None:
		"""Writes a byte (8 bits) into the buffer.

		Args:
			value: The byte to write into the buffer.
		"""
		self.data += struct.pack('>B', value)

	def write_u16(self, value: int) -> None:
		"""Writes a unsigned short (16 bits) into the buffer.

		Args:
			value: The unsigned short to write into the buffer.
		"""
		self.data += struct.pack('>H', value)

	def write_u32(self, value: int) -> None:
		"""Writes a unsigned int (32 bits) into the buffer.

		Args:
			value: The unsigned int to write into the buffer.
		"""
		self.data += struct.pack('>L', value)

	def write_string(self, value: str) -> None:
		"""Writes a string imto the buffer.

		Args:
			value: The string to write into the buffer.
		"""
		self.data += value.encode('utf-8')

	def write_string_u8(self, value: str) -> None:
		"""Writes a string prepended with a u8 showing the length of the string into the buffer.

		Args:
			value: The string to write into the buffer.
		"""
		self.write_u8(len(value))
		self.write_string(value)

	def write_string_u16(self, value: str) -> None:
		"""Writes a string prepended with a u16 showing the length of the string into the buffer.

		Args:
			value: The string to write into the buffer.
		"""
		self.write_u16(len(value))
		self.write_string(value)

	def write_string_u32(self, value: str) -> None:
		"""Writes a string prepended with a u32 showing the length of the string into the buffer.

		Args:
			value: The string to write into the buffer.
		"""
		self.write_u32(len(value))
		self.write_string(value)

	def write_tlv(self, tlv: TLV) -> None:
		"""Writes the specified TLV into the buffer.

		Args:
			tlv: The TLV to write into the buffer.
		"""
		self.data += tlv.marshal()

	def write_tlvs(self, tlvs: array[TLV]) -> None:
		"""Writes a list of TLVs into the buffer.

		Args:
			tlvs: The list of TLVs to write into the buffer.
		"""
		self.data += marshal_tlvs(tlvs)

	def write_tlv_block(self, tlvs: array[TLV]) -> None:
		"""Writes a list of TLVs prepended with a u16 describing the TLV count in the list, into the buffer.

		Args:
			tlvs: The list of TLVs to write into the buffer.
		"""
		self.write_u16(len(tlvs))
		self.write_tlvs(tlvs)

	def write_tlv_l_block(self, tlvs: array[TLV]) -> None:
		"""Writes a list of TLVs prepended with a u16 describing the length of the total TLV bytes, into the buffer.

		Args:
			tlvs: The list of TLVs to write into the buffers.
		"""
		marshalled_tlvs = marshal_tlvs(tlvs)

		self.write_u16(len(marshalled_tlvs))
		self.write_bytes(marshalled_tlvs)
