# TODO: holy shit clean this up this is awful
import argparse, asyncio, getpass, settings
from insclient.cmds import usercreate, userupdate, userdelete
from core.conn import Conn
from core import db

def _parse_args():
	p = argparse.ArgumentParser(prog='manageuser.py')
	sub = p.add_subparsers(dest='cmd', required=True)

	sc_create = sub.add_parser('create')
	sc_create.add_argument('email')
	sc_create.add_argument('username')
	sc_create.add_argument('first_name')
	sc_create.add_argument('last_name')
	sc_create.add_argument('uin', type=int)
	sc_create.add_argument('--password', '-p', help='user password (if omitted, prompted)')
	sc_create.add_argument('--oldmsn', action='store_true')
	sc_create.add_argument('--yahoo', action='store_true')
	sc_create.add_argument('--oldaim', action='store_true')
	sc_create.add_argument('--msim', action='store_true')

	sc_mod = sub.add_parser('modify')
	sc_mod.add_argument('email')
	sc_mod.add_argument('field')
	sc_mod.add_argument('value')
	sc_mod.add_argument('--oldmsn', action='store_true', help='also (re)generate legacy MSN MD5 hash when changing password')
	sc_mod.add_argument('--yahoo', action='store_true', help='also (re)generate legacy Yahoo hashes when changing password')
	sc_mod.add_argument('--oldaim', action='store_true', help='also (re)generate legacy AIM MD5 hash when changing password')
	sc_mod.add_argument('--msim', action='store_true', help='also (re)generate legacy MSIM SHA-1 hash when changing password')

	sc_del = sub.add_parser('delete')
	sc_del.add_argument('email', help='email of the user to delete')

	return p.parse_args()

async def _do_create(email: str, username: str, first_name: str, last_name: str, uin: int, user_password: str, oldmsn: bool, yahoo: bool, oldaim: bool, msim: bool) -> None:
	try:
		await usercreate(
			email, username, first_name, last_name, uin, user_password,
			oldmsn, yahoo, oldaim, msim, b'AzuL-SERV', settings.INS_LINK_PASSWORD
		)
		print("Operation successful!")
	except Exception as e:
		print("Operation failed:", e)

async def _do_modify(email: str, field: str, value: str, oldmsn: bool, yahoo: bool, oldaim: bool, msim: bool) -> None:
	conn = Conn(settings.DB)
	with conn.session() as sess:
		user = sess.query(db.User).filter(db.User.email == email).first()
		if not user:
			print('User does not exist.')
			return
		uuid = user.uuid

	if field == 'password' and value == '-':
		value = getpass.getpass('Password: ')

	try:
		if field == 'password':
			await userupdate(uuid, field, value, b'AzuL-SERV', settings.INS_LINK_PASSWORD, support_old_msn=oldmsn, support_yahoo=yahoo, support_aim=oldaim, support_msim=msim)
		else:
			await userupdate(uuid, field, value, b'AzuL-SERV', settings.INS_LINK_PASSWORD)
		print("Operation successful!")
	except Exception as e:
		print("Operation failed:", e)

async def _do_delete(email: str) -> None:
	conn = Conn(settings.DB)
	with conn.session() as sess:
		user = sess.query(db.User).filter(db.User.email == email).first()
		if not user:
			print('User does not exist.')
			return
		uuid = user.uuid

	try:
		await userdelete(uuid, b'AzuL-SERV', settings.INS_LINK_PASSWORD)
		print("Operation successful!")
	except Exception as e:
		print("Operation failed:", e)

def main():
	args = _parse_args()
	if args.cmd == 'create':
		pw = args.password
		if not pw:
			pw = getpass.getpass('Password: ')
		asyncio.run(_do_create(
			args.email, args.username, args.first_name, args.last_name, args.uin,
			pw, args.oldmsn, args.yahoo, args.oldaim, args.msim
		))
	elif args.cmd == 'modify':
		asyncio.run(_do_modify(
			args.email, args.field, args.value, args.oldmsn, args.yahoo, args.oldaim, args.msim
		))
	elif args.cmd == 'delete':
		asyncio.run(_do_delete(args.email))

if __name__ == '__main__':
	main()
