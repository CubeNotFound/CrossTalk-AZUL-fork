Y64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._'

def Y64Encode(string_encode: bytes) -> bytes:
	limit = len(string_encode) - (len(string_encode) % 3)
	out = bytearray()
	buff = [0] * len(string_encode)
	
	for i in range(len(string_encode)):
		buff[i] = string_encode[i] & 0xff
	
	for i in range(0, limit, 3):
		out.extend([Y64[buff[i] >> 2],
					Y64[((buff[i] << 4) & 0x30) | (buff[i + 1] >> 4)],
					Y64[((buff[i + 1] << 2) & 0x3c) | (buff[i + 2] >> 6)],
					Y64[buff[i + 2] & 0x3f]])
	
	remaining = len(string_encode) - limit
	if remaining == 1:
		out.extend([Y64[buff[limit] >> 2],
					Y64[(buff[limit] << 4) & 0x30],
					ord('-'),
					ord('-')])
	elif remaining == 2:
		out.extend([Y64[buff[limit] >> 2],
					Y64[((buff[limit] << 4) & 0x30) | (buff[limit + 1] >> 4)],
					Y64[(buff[limit + 1] << 2) & 0x3c],
					ord('-')])
	
	return bytes(out)
