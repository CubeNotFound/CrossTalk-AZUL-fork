import getpass, hashlib, sys
import settings
from core import db

def main() -> None:
	args = sys.argv[1:]
	if args[:1] == ['--hash-key']:
		key = getpass.getpass('Admin key: ')
		if len(key) < 12:
			print('Use at least 12 characters.')
			return
		if key != getpass.getpass('Again: '):
			print('Those don\'t match.')
			return
		print('ADMIN_KEY = \'{}\''.format(hashlib.sha256(key.encode('utf-8')).hexdigest()))
		return
	off = '--off' in args
	logins = [arg for arg in args if not arg.startswith('--')]
	if len(logins) != 1:
		print('Usage: python script/makeadmin.py <e-mail or username> [--off]')
		print('       python script/makeadmin.py --hash-key')
		return
	db.ensure_schema(db.engine)
	login = logins[0]
	with db.Session() as sess:
		row = sess.query(db.User).filter((db.User.email == login) | (db.User.username == login)).one_or_none()
		if row is None:
			print('No account is called {}.'.format(login))
			return
		row.is_admin = not off
		print('{} ({}) is {} an administrator.'.format(row.username, row.email, 'no longer' if off else 'now'))

if __name__ == '__main__':
	main()
