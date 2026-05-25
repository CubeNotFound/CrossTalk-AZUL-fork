from core import db, stats
from core.conn import Conn
import settings

def main() -> None:
	create_dbs()

def create_dbs() -> None:
	conn_db = Conn(settings.DB)
	db.Base.metadata.create_all(conn_db.engine)
	conn_stats = Conn(settings.STATS_DB)
	stats.Base.metadata.create_all(conn_stats.engine)

if __name__ == '__main__':
	main()
