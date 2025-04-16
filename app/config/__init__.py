from pathlib import Path

from config import base


class Settings:
    BASE_DIR: Path
    POSTGRES_HOST: str
    POSTGRES_PORT: int
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    CEP_LEN: int
    CNPJ_LEN: int
    CPF_LEN: int
    MAIL_HOST: str
    MAIL_PORT: int
    MAIL_USER: str
    MAIL_PWD: str
    MAIL_FROM: str
    MAIL_TIMEOUT: int
    MAIL_USE_TLS: bool
    MAIL_FAIL_SILENTLY: bool
    EMAIL_SSL_KEYFILE: str | None
    EMAIL_SSL_CERTFILE: str | None
    MAIL_ADMIN: str
    PRIVATE_KEY: str
    PUBLIC_KEY: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int

    def __init__(self):
        for setting in dir(base):
            if setting.isupper():
                setattr(self, setting, getattr(base, setting))


settings = Settings()
