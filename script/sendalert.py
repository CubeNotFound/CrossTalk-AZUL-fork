import asyncio, settings
from insclient.cmds import alert

async def main(emails: str):
	message = input('Enter alert message: ').strip()
	if not message:
		print('Message is required.')
		return

	url = input('Enter a URL (or leave blank): ').strip() or ''
	icon = input('Enter an icon URL (or leave blank): ').strip() or ''
	targets = emails if emails.strip() and emails.strip() != '*' else 'all'

	try:
		await alert(message, b'AzuL-SERV', settings.INS_LINK_PASSWORD, url, icon, targets)
		print("Operation successful!")
	except Exception as e:
		print("Operation failed:", e)


if __name__ == '__main__':
	import sys
	_, emails = sys.argv
	asyncio.run(main(emails))
