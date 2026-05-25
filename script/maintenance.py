import asyncio, settings
from insclient.cmds import maintenance

async def main(minutes: str):
	try:
		resp = await maintenance(minutes, b'AzuL-SERV', settings.INS_LINK_PASSWORD)
		print("Operation successful!")
	except Exception as e:
		print("Operation failed:", e)


if __name__ == '__main__':
	import sys
	_, minutes = sys.argv
	asyncio.run(main(minutes))
