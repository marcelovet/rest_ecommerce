import tracemalloc
import urllib.parse
from unittest.mock import AsyncMock
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.dependencies import get_db
from app.core.config import settings as st
from app.main import app
from app.models.response_models import AccessTokenData
from app.models.response_models import TokenData
from app.models.response_models import TokenType
from app.schemas import BaseUser
from app.schemas import User

CONN_STRING = "postgresql+psycopg://"
CONN_STRING += f"{urllib.parse.quote_plus(st.POSTGRES_USER)}"
CONN_STRING += f":{urllib.parse.quote_plus(st.POSTGRES_PASSWORD)}@"
CONN_STRING += f"{st.POSTGRES_HOST}:{st.POSTGRES_PORT}/"
CONN_STRING += f"{st.POSTGRES_DB}"
engine = create_engine(
    CONN_STRING,
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="session", autouse=True)
def enable_tracemalloc():
    """Enable tracemalloc for debugging ResourceWarnings."""
    tracemalloc.start(20)  # Capture 20 frames
    yield
    tracemalloc.stop()


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    # Create tables
    BaseUser.metadata.create_all(bind=engine)
    yield
    # Drop tables after all tests are done
    BaseUser.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def clean_tables():
    # Clean all tables before each test
    with TestingSessionLocal() as db:
        db.query(User).delete()
        db.commit()


def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture
def db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


@pytest.fixture(scope="session")
def valid_jwt_token():
    """Fixture providing a valid JWT token format."""
    # This is a mock JWT token with the correct format but not a real token
    return (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )


@pytest.fixture(scope="session")
def token_data_instance(valid_jwt_token):
    """Fixture providing a valid TokenData instance."""
    return TokenData(token=valid_jwt_token, token_type=TokenType.ACCESS)


@pytest.fixture
def access_token_data_instance(token_data_instance):
    """Fixture providing a valid AccessTokenData instance."""
    return AccessTokenData(
        access_token=token_data_instance,
        refresh_token=TokenData(
            token=token_data_instance.token,
            token_type=TokenType.REFRESH,
        ),
    )


@pytest.fixture
def mock_redis():
    """Fixture to create a mock Redis client."""
    mock = AsyncMock()
    mock.ping = AsyncMock(return_value=True)
    mock.get = AsyncMock(return_value=None)
    mock.set = AsyncMock(return_value=True)
    mock.setex = AsyncMock(return_value=True)
    mock.sadd = AsyncMock(return_value=True)
    mock.sismember = AsyncMock(return_value=False)
    mock.smembers = AsyncMock(return_value=set())
    mock.expire = AsyncMock(return_value=True)
    mock.delete = AsyncMock(return_value=True)
    mock.hset = AsyncMock(return_value=True)
    mock.hgetall = AsyncMock(return_value={})
    mock.incr = AsyncMock(return_value=1)
    mock.lpush = AsyncMock(return_value=True)
    mock.ltrim = AsyncMock(return_value=True)
    mock.lrange = AsyncMock(return_value=[])
    mock.pipeline = MagicMock(return_value=mock)
    mock.execute = AsyncMock(return_value=[])
    mock.close = AsyncMock(return_value=True)
    return mock
