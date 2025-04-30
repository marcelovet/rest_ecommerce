from pathlib import Path

from . import base


class Settings:
    BASE_DIR: Path

    SUPERUSER_EMAIL: str
    SUPERUSER_PASSWORD: str

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
    ACCESS_TOKEN_EXPIRE: int
    REFRESH_TOKEN_EXPIRE: int
    VERIFICATION_TOKEN_EXPIRE: int
    LIMITED_TOKEN_EXPIRE: int
    RESET_PASSWORD_TOKEN_EXPIRE: int

    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_URL: str
    CELERY_URL: str
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str

    REPOSITORY_HOST: str
    REPOSITORY_DB: int
    REPOSITORY_URL: str

    CACHE_HOST: str
    CACHE_DB: int
    CACHE_URL: str

    SECURITY_DB: int
    SECURITY_URL: str
    ABUSEIPDB_API_KEY: str
    ABUSEIPDB_SUSPICIOUS_THRESHOLD: int
    ABUSEIPDB_ATTACKER_THRESHOLD: int
    SECURITY_DATA_EXPIRE: int
    IP_REPUTATION_EXPIRE: int
    COUNTRY_ACCESS_EXPIRE: int
    AUTH_FAILURES_THRESHOLD: int
    SECURITY_EVENTS_THRESHOLD: int
    RECENT_SUSPICIOUS_EXPIRE: int
    IP_THREAT_EXPIRES: int
    IP_EVENT_EXPIRES: int
    IP_AUTH_FAILURE_EXPIRES: int
    IP_AUTH_FAILURE_TIME_EXPIRES: int
    USER_AUTH_FAILURE_EXPIRES: int
    USER_AUTH_FAILURE_IPS_EXPIRES: int
    AUTH_FAILURES_TIMESPAN_THRESHOLD: int
    SECURITY_EVENTS_EXPIRES: int
    MARK_IP_MALICIOUS_EVENTS_THRESHOLD: int
    MARK_IP_MALICIOUS_EVENTS_EXPIRES: int

    FRONTEND_URL: str
    DOMAIN: str
    BACKEND_CORS_ORIGINS: list[str]
    API_VERSION: str
    API_VERSION_PREFIX: str

    def __init__(self):
        for setting in dir(base):
            if setting.isupper():
                setattr(self, setting, getattr(base, setting))


settings = Settings()
