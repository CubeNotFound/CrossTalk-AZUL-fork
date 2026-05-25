import asyncio, ast, json, settings
from insclient.cmds import list_sessions, session_detail, session_delete

async def main(action: str, id: str | None):
	try:
		def _print_sessions(resp):
			if not resp or resp[0] != 'ALLTHESESSIONS':
				print("No sessions returned or unexpected response format")
				return
			tokens = resp[2:]
			buf = []
			sessions = []
			i = 0
			while i < len(tokens):
				tok = tokens[i]
				if tok.startswith('"'):
					buf = [tok]
					while not buf[-1].endswith('"') and i + 1 < len(tokens):
						i += 1
						buf.append(tokens[i])
					raw = " ".join(buf).strip('"')
					try:
						sid, uuid, email, raw_meta = raw.split('|', 3)
						meta = ast.literal_eval(raw_meta)
						sessions.append((sid, uuid, email, meta))
					except Exception:
						pass
				else:
					buf = [tok]
					if tok.endswith('}'):
						raw = " ".join(buf)
						try:
							sid, uuid, email, raw_meta = raw.split('|', 3)
							meta = ast.literal_eval(raw_meta)
							sessions.append((sid, uuid, email, meta))
						except Exception:
							pass
				i += 1

			for sid, uuid, email, meta in sessions:
				print(
					f"  Session ID:\t {sid}\n"
					f"  UUID:\t\t {uuid}\n"
					f"  Email:\t {email}\n"
					f"  Client:\t {meta.get('program')}\n"
					f"  Version:\t {meta.get('version')}\n"
					f"  Method:\t {meta.get('via')}\n"
				)

		if action == 'list_all':
			resp = await list_sessions(None, b'AzuL-SERV', settings.INS_LINK_PASSWORD)
			_print_sessions(resp)
			return

		elif action == 'list_by_user':
			resp = await list_sessions(id, b'AzuL-SERV', settings.INS_LINK_PASSWORD)
			_print_sessions(resp)
			return

		elif action == 'details':
			resp = await session_detail(id, b'AzuL-SERV', settings.INS_LINK_PASSWORD)
			if not resp or resp[0] != 'SESSION':
				print("No such session or unexpected response")
				return

			if len(resp) >= 3 and resp[2] == 'KILLED':
				print(f"Session {id} was killed")
				return

			_, ts, sess_id, username, uuid, email, uin = resp[:7]
			chat_enabled = resp[-1]
			meta_tokens = resp[7:-1]

			raw_client = ''
			if not meta_tokens:
				raw_client = ''
			elif len(meta_tokens) == 1:
				token = meta_tokens[0]
				if token.startswith('"') and token.endswith('"'):
					raw_client = token.strip('"')
				else:
					raw_client = token
			else:
				combined = " ".join(meta_tokens)
				if combined.startswith('"') and combined.endswith('"'):
					raw_client = combined.strip('"')
				else:
					raw_client = combined

			try:
				client_meta = ast.literal_eval(raw_client) if raw_client else {}
			except Exception:
				client_meta = {}

			print(f"  Details for session {sess_id}:")
			print(f"  Username:\t {username}")
			print(f"  UUID:\t\t {uuid}")
			print(f"  Email:\t {email}")
			print(f"  UIN:\t\t {uin}")
			print(f"  Chat enabled:\t {chat_enabled}")
			print("  Client info:")
			for k, v in client_meta.items():
				print(f"\t{k}: {v}")
			return

		elif action in ('close', 'kill'):
			await session_delete(id, b'AzuL-SERV', settings.INS_LINK_PASSWORD)
			print("Operation successful")
			return

		else:
			print('Unknown action. Valid actions: list_all, list_by_user, details, close, kill')
			return

	except Exception as e:
		print("Operation failed:", e)


if __name__ == '__main__':
	import sys

	_, action, *rest = sys.argv
	id_arg = rest[0] if rest else None

	asyncio.run(main(action, id_arg))