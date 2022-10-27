from navconfig import config

# Basic configuration:
APP_NAME = config.get('APP_NAME', fallback='Navigator')
APP_TITLE = config.get("APP_TITLE", fallback="NAVIGATOR").upper()
DOMAIN = config.get("DOMAIN", fallback="dev.local")

### System Timezone:
TIMEZONE = config.get('TIMEZONE', fallback='UTC')
TZ = config.get("TZ", fallback=TIMEZONE)

### Session information:
# User Object saved onto Response/Request Object
AUTH_SESSION_OBJECT = config.get(
    "AUTH_SESSION_OBJECT", fallback="session"
)
"""
Session Storage
"""
SESSION_PREFIX = config.get('SESSION_PREFIX', fallback='navigator')
SESSION_NAME = f"{APP_TITLE}_SESSION"
JWT_ALGORITHM = config.get("JWT_ALGORITHM", fallback="HS256")
SESSION_PREFIX = f'{SESSION_PREFIX}_session'
SESSION_TIMEOUT = config.getint('SESSION_TIMEOUT', fallback=360000)
SESSION_STORAGE = 'NAVIGATOR_SESSION_STORAGE'
SESSION_OBJECT = 'NAV_SESSION'


# SESSION BACKEND:
SESSION_BACKEND = config.get('SESSION_BACKEND', fallback='redis')

# IF REDIS:
REDIS_HOST = config.get("REDIS_HOST", fallback="localhost")
REDIS_PORT = config.get("REDIS_PORT", fallback=6379)
REDIS_SESSION_DB = config.get("REDIS_SESSION_DB", fallback=0)
SESSION_URL = f"{SESSION_BACKEND}://{REDIS_HOST}:{REDIS_PORT}/{REDIS_SESSION_DB}"


# User Attributes:
SESSION_USER_PROPERTY = config.get('SESSION_USER_PROPERTY', fallback='user')
SESSION_KEY = config.get('SESSION_KEY', fallback='id')
