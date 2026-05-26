from core import db
from core.conn import Conn
import settings

# TODO: INS-ize this
def main(*ids: str) -> None:
	if not ids:
		print("Nothing to do.")
		return
	print("Deleting {} circles:".format(len(ids)))
	for i in ids:
		print('=>', i)
	ans = input("Are you sure? (y/N) ")
	if ans.lower() != 'y':
		print("Operation cancelled.")
		return
	print("Deleting.")
	
	conn = Conn(settings.DB)
	with conn.session() as sess:
		circles = sess.query(db.Circle).filter(db.Circle.chat_id.in_(ids))
		circlememberships = sess.query(db.CircleMembership).filter(db.CircleMembership.chat_id.in_(ids))
		print("delete circles", len(ids))
		circlememberships.delete(synchronize_session = False)
		circles.delete(synchronize_session = False)
		sess.flush()

if __name__ == '__main__':
	import funcli
	funcli.main()
