import struct


from util.misc import Logger

from ..proto import bart as bart_store
from ..proto import names
from ..proto.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup

# the largest upload taken; AIM keeps icons well under this
MAX_UPLOAD_BYTES = 0x8000


def _string08(value: str) -> bytes:
	encoded = value.encode('latin-1', errors = 'replace')
	return struct.pack('>B', len(encoded)) + encoded

def _read_bart_ids(data: bytes, count: int) -> list[tuple[int, int, bytes]]:
	ids = []
	for _ in range(count):
		parsed = bart_store.parse_bart_id(data)
		if parsed is None:
			break
		bart_type, flags, hash, data = parsed
		ids.append((bart_type, flags, hash))
	return ids


@Foodgroup(0x0010)
class BARTFoodgroup:
	logger: Logger

	@Subgroup(0x0002)
	def upload_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# BART__UPLOAD_QUERY: u16 type, u16 length, the item
		self.logger.info('[Client] BART__UPLOAD_QUERY')
		bart_type = message.read_u16()
		data = message.read_bytes(message.read_u16())
		client.ctrl.backend.loop.create_task(_upload(client, context, message.request_id, bart_type, data))

	@Subgroup(0x0004)
	def download_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# BART__DOWNLOAD_QUERY: string08 whose, u8 command, then the BART ID
		self.logger.info('[Client] BART__DOWNLOAD_QUERY')
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		message.read_u8()
		ids = _read_bart_ids(message.data, 1)
		if not ids:
			return
		client.ctrl.backend.loop.create_task(_download(client, message.request_id, name, ids[0]))

	@Subgroup(0x0006)
	def download2_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
		# BART__DOWNLOAD2_QUERY: string08 whose, u8 count, then that many BART IDs
		self.logger.info('[Client] BART__DOWNLOAD2_QUERY')
		name = message.read_bytes(message.read_u8()).decode('latin-1')
		count = message.read_u8()
		ids = _read_bart_ids(message.data, count)
		client.ctrl.backend.loop.create_task(_download2(client, message.request_id, name, ids))


async def _upload(client: OSCARClient, context: OSCARContext, request_id: int, bart_type: int, data: bytes) -> None:
	# BART__UPLOAD_REPLY: u8 result, then the BART ID the item is filed under
	reply = SNACMessage(0x0010, 0x0003, 0x0000, request_id)
	if not data:
		reply.write_u8(bart_store.BARTReplyCode.TooSmall)
		reply.write_bytes(bart_store.build_bart_id(bart_type, 0, b''))
		client.send_snac(reply)
		return
	if len(data) > MAX_UPLOAD_BYTES:
		reply.write_u8(bart_store.BARTReplyCode.TooBig)
		reply.write_bytes(bart_store.build_bart_id(bart_type, 0, b''))
		client.send_snac(reply)
		return

	hash = await bart_store.store_item(data)
	bs = context.bs
	icon = bs.front_data.get('oscar0_bart_icon')
	flags = bart_store.BARTFlags.Custom
	if icon is not None and icon[1] == hash:
		# the icon the feedbag said the client was using is here now, so it can go on show
		flags = icon[0] & ~bart_store.BARTFlags.Unknown
		bs.front_data['oscar0_bart_icon'] = (flags, hash)
	reply.write_u8(bart_store.BARTReplyCode.Success)
	reply.write_bytes(bart_store.build_bart_id(bart_type, flags, hash))
	client.send_snac(reply)

	if icon is not None and icon[1] == hash and not bs.closed:
		from .buddy import refresh_contact
		refresh_contact(context.backend, context.user)

async def _download(client: OSCARClient, request_id: int, name: str, bart_id: tuple[int, int, bytes]) -> None:
	# BART__DOWNLOAD_REPLY: string08 whose, the BART ID, u16 length and the item (empty when there's no such item)
	bart_type, flags, hash = bart_id
	data = await bart_store.get_item(hash) or b''
	reply = SNACMessage(0x0010, 0x0005, 0x0000, request_id)
	reply.write_bytes(_string08(name))
	reply.write_bytes(bart_store.build_bart_id(bart_type, flags, hash))
	reply.write_u16(len(data))
	reply.write_bytes(data)
	client.send_snac(reply)

async def _download2(client: OSCARClient, request_id: int, name: str, ids: list[tuple[int, int, bytes]]) -> None:
	# BART__DOWNLOAD2_REPLY, one per item: string08 whose, the query's BART ID, u8 code (0 found), the reply's BART ID, data
	for bart_type, flags, hash in ids:
		data = await bart_store.get_item(hash)
		reply = SNACMessage(0x0010, 0x0007, 0x0000, request_id)
		reply.write_bytes(_string08(name))
		reply.write_bytes(bart_store.build_bart_id(bart_type, flags, hash))
		reply.write_u8(0x00 if data is not None else bart_store.BARTReplyCode.NotFound)
		reply.write_bytes(bart_store.build_bart_id(bart_type, flags, hash))
		reply.write_u16(len(data or b''))
		reply.write_bytes(data or b'')
		client.send_snac(reply)
