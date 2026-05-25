from core import db
from core.conn import Conn
import settings

# TODO: INS-ize this
def main(*, verbose: bool = False) -> None:
	total = 0
	conn = Conn(settings.DB)
	with conn.session() as sess:
		for circle in sess.query(db.Circle).all():
			total += 1
			if verbose:
				print(circle.chat_id, circle.name)
	
	print("Total:", total)

if __name__ == '__main__':
	import funcli
	funcli.main()
