import os
from insclient import INSClient
import settings

def ins_client(identifier: str = 'AzuL-SERV') -> INSClient:
	host = ('127.0.0.1' if settings.INS_HOST in ('0.0.0.0', '::', '') else settings.INS_HOST)
	return INSClient(
		identifier, key_file = os.path.join(settings.INS_KEY_DIR, '{}.client.key'.format(identifier.lower())),
		enrollment_code = os.environ.get('INS_ENROLLMENT_CODE') or None, host = host, port = settings.INS_PORT, keepalive = False,
		client_name = 'azul-script', client_version = settings.VERSION, label = 'azul scripts',
	)
