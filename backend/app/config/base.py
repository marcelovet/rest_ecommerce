import locale
import sys
from configparser import ConfigParser
from pathlib import Path

from app.exceptions import SectionNotFoundError

locale.setlocale(locale.LC_ALL, "pt_BR.UTF-8")

BASE_DIR = Path(__file__).resolve().parent.parent


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


CONFIG_PATH = BASE_DIR / ".envs" / "config.ini"

postgres_config = load_config(CONFIG_PATH, "postgresql")
mail_config = load_config(CONFIG_PATH, "mail")

# postgres database
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

# jwt
with (BASE_DIR / "private_key.pem").open("r") as f:
    PRIVATE_KEY = f.read()
with (BASE_DIR / "public_key.pem").open("r") as f:
    PUBLIC_KEY = f.read()

# JWT config
JWT_ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

sys.path.append(str(Path(__file__).parent.parent / "config"))
