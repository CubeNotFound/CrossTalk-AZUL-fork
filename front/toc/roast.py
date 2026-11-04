from itertools import cycle

ROAST_STRING = b'Tic/Toc'

def roast(password: bytes) -> bytes:
	chars = cycle(ROAST_STRING)
	return bytes(byte ^ next(chars) for byte in password)

def unroast_hex(roasted: bytes) -> bytes:
	text = roasted.decode('ascii', 'replace')
	if text.startswith('0x'):
		text = text[2:]
	return roast(bytes.fromhex(text))