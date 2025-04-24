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
postgres_local_config = load_config(CONFIG_PATH, "postgresql_local")
misc = load_config(CONFIG_PATH, "misc")
app_type = misc.get("app_type", "local")

# admin user
SUPERUSER_EMAIL = super_config["email"]
SUPERUSER_PASSWORD = super_config["password"]

# postgres database
if app_type == "local":
    POSTGRES_HOST = postgres_local_config["host"]
    POSTGRES_PORT = int(postgres_local_config["port"])
    POSTGRES_DB = postgres_local_config["database"]
    POSTGRES_USER = postgres_local_config["user"]
    POSTGRES_PASSWORD = postgres_local_config["password"]
else:
    POSTGRES_HOST = postgres_config["host"]
    POSTGRES_PORT = int(postgres_config["port"])
    POSTGRES_DB = postgres_config["database"]
    POSTGRES_USER = postgres_config["user"]
    POSTGRES_PASSWORD = postgres_config["password"]

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

JWT_ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
VERIFICATION_TOKEN_EXPIRE_DAYS = 1
LIMITED_TOKEN_EXPIRE_MINUTES = 60

# redis
REDIS_URL = f"redis://{redis_config['host']}:{redis_config['port']}/0"
# celery
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL

# frontend
FRONTEND_URL = misc.get("front_end_url", "http://localhost:5173")

# Backend
DOMAIN = misc.get("domain", "http://localhost:8000")
BACKEND_CORS_ORIGINS = ["http://localhost:8080", FRONTEND_URL]
API_VERSION_PREFIX = "/api/v1"
API_VERSION = "1.0.0"
