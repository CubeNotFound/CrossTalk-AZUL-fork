# General server settings
# Legacy - SQLite
# DB = 'sqlite:///../crosstalk.sqlite'
# STATS_DB = 'sqlite:///../stats.sqlite'
# Current - MySQL/MariaDB
VERSION = '0.6.0'
DB = 'mysql+pymysql://username:password@127.0.0.1/crosstalk?charset=utf8mb4' 
STATS_DB = 'mysql+pymysql://username:password@127.0.0.1/ctstats?charset=utf8mb4'

DEBUG = False
DEBUG_FULL = False
DEBUG_LOG_SQL_QUERIES = False

CERT_DIR = 'path/to/cert'
CERT_ROOT = 'CERT_ROOT'

TARGET_HOST = 'ms.msgrsvcs.ctsrv.xyz'
APPDIR_HOST = 'mactivites.msgrsvcs.ctsrv.xyz'
LOGIN_HOST = 'ctas.login.ugnet.xyz'
ADDRESSBOOK_HOST = 'ctsvcs.addressbook.ugnet.xyz'
USERSTORAGE_HOST = 'cts.storage.ugnet.xyz'
STORAGE_HOST = 'storage.ugnet.xyz'
STATIC_HOST = 'static.ugnet.xyz'
AD_HOST = 'ctsvcs.advertising.ugnet.xyz'
TODAY_HOST = 'today.msgrsvcs.ctsrv.xyz'
SOCIAL_HOST = 'social.ugnet.xyz'
WEBSITE_HOST = 'crosstalk.im'
TARGET_IP = '127.0.0.1'

# While not necessary for debugging, it is recommended you change the password variables in production for obvious security reasons.
INS_LINK_PASSWORD = 'password'

INS_HOST = '0.0.0.0'
INS_PORT = 4309
INS_KEY_DIR = 'config/ins'
INS_ALLOWED_IPS = ['127.0.0.1', '::1']
INS_IDENTIFIERS = ['WEB', 'AzuL-SERV', 'WTV', 'uMaIL', 'sBOOK', 'NOTBAY', 'CrossBot', 'SEARCH', 'WebTalk']
INS_AUTH_TIMEOUT = 15
INS_IDLE_TIMEOUT = 180
INS_PING_INTERVAL = 60
INS_CHALLENGE_INTERVAL = 900
INS_CHALLENGE_TIMEOUT = 60

ENABLE_ADMIN = True
ADMIN_HOST = '127.0.0.1'
ADMIN_PORT = 8090
ADMIN_KEY = ''
ADMIN_SESSION_LIFETIME = 8 * 3600
ADMIN_COOKIE_SECURE = False

ALERT_SITE_URL = 'https://crosstalk.im/'
SUSPENDED_ACCOUNT_DAYS = 30

# SMTP 
SMTP_HOST = 'mail-server-here'
SMTP_PORT = 587
SMTP_USERNAME = 'administration@ugnet.xyz'
SMTP_PASSWORD = ''

# What frontends are enabled
ENABLE_INS = True
ENABLE_FRONT_MSN = True
ENABLE_FRONT_YMSG = True
ENABLE_FRONT_IRC = False
ENABLE_FRONT_IRC_SSL = False
ENABLE_FRONT_OSCAR = True
# the pre-OSCAR ICQ protocols (V1-V5) over UDP
ENABLE_FRONT_ICQ = True
ENABLE_FRONT_TOC = True
ENABLE_FRONT_MSIM = False


CF_REALTIME_API_KEY = ''
FORCE_HOSTS_UPDATE = False
STRESS_TEST_ACTIVE = False
ENABLE_NAT_RELAY = True

# Frontend-specific settings
YAHOOHELPER_MSG = "CHANGE ME"
YMSG_TOKEN_LIFETIME = 86400
OSCAR_MOTD_ENABLED = False
ICQ_LEGACY_PORT = 4000
# hand V5 clients each other's IP address and port for direct connections (file transfers, chat); off, it stays private
ICQ_DIRECT_CONNECTIONS = False
HTTP_PORT = 80



SERVICE_KEYS = [] # type: ignore

try:
	from config.settings_local import *
except ImportError as ex:
	raise Exception("Please create settings_local.py") from ex
