# General server settings
# Legacy - SQLite
# DB = 'sqlite:///../crosstalk.sqlite'
# STATS_DB = 'sqlite:///../stats.sqlite'
# Current - MySQL/MariaDB
DB = 'mysql+pymysql://username:password@127.0.0.1/crosstalk?charset=utf8mb4' 
STATS_DB = 'mysql+pymysql://username:password@127.0.0.1/ctstats?charset=utf8mb4'
DEBUG = False
DEBUG_FULL = False
DEBUG_LOG_SQL_QUERIES = False
FORCE_HOSTS_UPDATE = False
CERT_DIR = 'path/to/cert'
CERT_ROOT = 'CERT_ROOT'
TARGET_HOST = 'ms.msgrsvcs.ctsrv.gay'
APPDIR_HOST = 'mactivites.msgrsvcs.ctsrv.gay'
LOGIN_HOST = 'ctas.login.ugnet.gay'
ADDRESSBOOK_HOST = 'ctsvcs.addressbook.ugnet.gay'
USERSTORAGE_HOST = 'cts.storage.ugnet.gay'
STORAGE_HOST = 'storage.ugnet.gay'
STATIC_HOST = 'static.ugnet.gay'
TARGET_IP = '127.0.0.1'
SMTP_HOST = 'mail-server-here'
SMTP_PORT = 587
SMTP_USERNAME = 'administration@ugnet.gay'
SMTP_PASSWORD = ''
ENABLE_NAT_RELAY = False
CF_REALTIME_API_KEY = ''
VERSION = '0.5.22'
# While not necessary for debugging, it is recommended you change the password variables in production for obvious security reasons.
INS_LINK_PASSWORD = 'password'
STRESS_TEST_ACTIVE = False

# What frontends are enabled
ENABLE_INS = True
ENABLE_FRONT_MSN = True
ENABLE_FRONT_YMSG = True
ENABLE_FRONT_IRC = False
ENABLE_FRONT_IRC_SSL = False
ENABLE_FRONT_OSCAR = True
ENABLE_FRONT_MSIM = False
ENABLE_FRONT_API = True
ENABLE_FRONT_BOT = False
ENABLE_FRONT_DEVBOTS = False

# Frontend-specific settings
YAHOOHELPER_MSG = "CHANGE ME"
OSCAR_MOTD_ENABLED = False
HTTP_PORT = 80

SERVICE_KEYS = [] # type: ignore

try:
	from config.settings_local import *
except ImportError as ex:
	raise Exception("Please create settings_local.py") from ex
