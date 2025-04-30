from configparser import ConfigParser
from pathlib import Path

from app.exceptions import SectionNotFoundError

# locale.setlocale(locale.LC_ALL, "pt_BR.UTF-8")

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent


def load_config(filename: Path, section: str):
    parser = ConfigParser()
    parser.read(str(filename))

    config = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            config[param[0]] = param[1]
    else:
        msg = f"Section {section} not found in the {filename} file"
        raise SectionNotFoundError(msg)

    return config


CONFIG_PATH = BASE_DIR / "config.ini"

super_config = load_config(CONFIG_PATH, "admin")
postgres_config = load_config(CONFIG_PATH, "postgresql")
mail_config = load_config(CONFIG_PATH, "mail")
redis_config = load_config(CONFIG_PATH, "redis")
jwt_config = load_config(CONFIG_PATH, "jwt")
misc = load_config(CONFIG_PATH, "misc")
security = load_config(CONFIG_PATH, "security")
app_type = misc.get("app_type", "local")

if app_type == "local":
    devel_config = load_config(CONFIG_PATH, "devel_mode")

# admin user
SUPERUSER_EMAIL = super_config["email"]
SUPERUSER_PASSWORD = super_config["password"]

# postgres database
POSTGRES_DB = postgres_config["database"]
POSTGRES_USER = postgres_config["user"]
POSTGRES_PASSWORD = postgres_config["password"]

if app_type == "local":
    POSTGRES_HOST = devel_config["pg_host"]
    POSTGRES_PORT = int(devel_config["pg_port"])
else:
    POSTGRES_HOST = postgres_config["host"]
    POSTGRES_PORT = int(postgres_config["port"])

# references for brazilian ids
CEP_LEN = 8
CNPJ_LEN = 14
CPF_LEN = 11

# mail
MAIL_HOST = mail_config["host"]
MAIL_PORT = int(mail_config["port"])
MAIL_USER = mail_config["user"]
MAIL_PWD = mail_config["password"]
MAIL_FROM = mail_config["from"]
MAIL_TIMEOUT = int(mail_config["timeout"])
MAIL_USE_TLS = bool(mail_config["use_tls"])
MAIL_FAIL_SILENTLY = bool(mail_config["fail_silently"])
EMAIL_SSL_KEYFILE = mail_config.get("ssl_keyfile", None)
EMAIL_SSL_CERTFILE = mail_config.get("ssl_certfile", None)
MAIL_ADMIN = mail_config["admin"]

# JWT config
with (BASE_DIR / "private_key.pem").open("r") as f:
    PRIVATE_KEY = f.read()
with (BASE_DIR / "public_key.pem").open("r") as f:
    PUBLIC_KEY = f.read()

JWT_ALGORITHM = jwt_config["algorithm"]
ACCESS_TOKEN_EXPIRE = int(jwt_config["access_token_expire"])
REFRESH_TOKEN_EXPIRE = int(jwt_config["refresh_token_expire"])
VERIFICATION_TOKEN_EXPIRE = int(jwt_config["verification_token_expire"])
LIMITED_TOKEN_EXPIRE = int(jwt_config["limited_token_expire"])
RESET_PASSWORD_TOKEN_EXPIRE = int(jwt_config["reset_password_expire"])

# REDIS
if app_type == "local":
    REDIS_HOST = devel_config["redis_host"]
    REDIS_PORT = int(devel_config["redis_port"])
else:
    REDIS_HOST = redis_config["host"]
    REDIS_PORT = int(redis_config["port"])
REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}"
# celery
CELERY_URL = f"{REDIS_URL}/{redis_config['celery_db']}"
CELERY_BROKER_URL = CELERY_RESULT_BACKEND = CELERY_URL
# repository
REPOSITORY_HOST = REDIS_HOST
REPOSITORY_DB = int(redis_config["repository_db"])
REPOSITORY_URL = f"{REDIS_URL}/{REPOSITORY_DB}"
# cache
CACHE_HOST = REDIS_HOST
CACHE_DB = int(redis_config["cache_db"])
CACHE_URL = f"{REDIS_URL}/{CACHE_DB}"

# security
SECURITY_DB = int(redis_config["security_db"])
SECURITY_URL = f"{REDIS_URL}/{SECURITY_DB}"
ABUSEIPDB_API_KEY = security["abuseipdb_api"]
ABUSEIPDB_SUSPICIOUS_THRESHOLD = 20
ABUSEIPDB_ATTACKER_THRESHOLD = 80
AUTH_FAILURES_THRESHOLD = 5
AUTH_FAILURES_TIMESPAN_THRESHOLD = 5 * 60  # 5 minutes
SECURITY_EVENTS_THRESHOLD = 3
MARK_IP_MALICIOUS_EVENTS_THRESHOLD = 5
SECURITY_DATA_EXPIRE = 24 * 60 * 60  # 1 day
IP_REPUTATION_EXPIRE = 60 * 60  # 1 hour
IP_THREAT_EXPIRES = 24 * 60 * 60  # 1 day
IP_EVENT_EXPIRES = 7 * 24 * 60 * 60  # 7 day
IP_AUTH_FAILURE_EXPIRES = 60 * 60  # 1 hour
IP_AUTH_FAILURE_TIME_EXPIRES = 24 * 60 * 60  # 1 day
USER_AUTH_FAILURE_EXPIRES = 60 * 60  # 1 hour
USER_AUTH_FAILURE_IPS_EXPIRES = 24 * 60 * 60  # 1 day
SECURITY_EVENTS_EXPIRES = 60 * 60  # 1 hour
MARK_IP_MALICIOUS_EVENTS_EXPIRES = 2 * 60 * 60  # 2 hours

COUNTRY_ACCESS_EXPIRE = 60 * 60 * 24 * 180  # 180 days
RECENT_SUSPICIOUS_EXPIRE = 24 * 60 * 60  # 1 day

# frontend
FRONTEND_DOMAIN = misc.get("front_end", "localhost:5173")
FRONTEND_URL = f"http://{FRONTEND_DOMAIN}"

# Backend
API_VERSION = misc.get("api_version", "1.0.0")
API_VERSION_PREFIX = f"/api/v{API_VERSION.split('.')[0]}"
BACKEND_DOMAIN = misc.get("domain", "localhost:8000")
BACKEND_URL = f"http://{BACKEND_DOMAIN}"
BACKEND_API_URL = f"{BACKEND_URL}{API_VERSION_PREFIX}"
BACKEND_CORS_ORIGINS = [
    "http://localhost:8080",
    FRONTEND_URL,
    BACKEND_URL,
    BACKEND_API_URL,
]
