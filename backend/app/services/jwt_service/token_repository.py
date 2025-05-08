import json
import logging
from datetime import UTC
from datetime import datetime
from typing import Any
from typing import ClassVar

import redis.asyncio as redis
from redis.asyncio.client import Redis
from redis.exceptions import RedisError

from app.core.config import settings as st

from .exceptions import TokenRevokedError

# Configure Token Repository logger
logger = logging.getLogger("token_repository")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class TokenRepository:
    """Handle token storage and validation for revocation checks"""

    __initialized: ClassVar[bool] = False
    __redis_client: ClassVar[Redis | None] = None

    @classmethod
    async def initialize(
        cls,
        redis_url: str | None = None,
    ) -> None:
        """Initialize the Token Repository

        Args:
            redis_url: Redis connection URL
        """
        if cls.__initialized:
            return

        if redis_url:
            try:
                cls.__redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                )
                await cls._redis_client.ping()
                logger.info("Token Repository connected to Redis")
                cls.__initialized = True
            except Exception as e:
                msg = f"Failed to connect to Redis: {e}"
                logger.exception(msg)
                cls.__redis_client = None
        else:
            try:
                redis_host = getattr(st, "REPOSITORY_HOST", "localhost")
                redis_port = getattr(st, "REDIS_PORT", 6379)
                redis_db = getattr(st, "REPOSITORY_DB", 1)

                cls.__redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    decode_responses=True,
                )
                await cls._redis_client.ping()
                logger.info("Token Repository connected to Redis")
                cls.__initialized = True
            except Exception as e:
                msg = f"Failed to connect to Redis: {e}"
                logger.exception(msg)
                cls.__redis_client = None

    @classmethod
    async def shutdown(cls) -> None:
        """Shut down the manager and clean up resources"""
        if cls.__redis_client:
            await cls.__redis_client.close()
            cls.__redis_client = None

        cls.__initialized = False
        logger.info("Token Repository shutdown complete")

    @classmethod
    def _redis_client(cls) -> Redis:
        """Get the Redis client"""
        if not isinstance(cls.__redis_client, Redis):
            msg = "Redis client not initialized"
            raise RedisError(msg)
        return cls.__redis_client

    @classmethod
    async def store_jti(cls, jti: str, user_id: str, expiration: datetime) -> bool:
        """
        Store JTI in Redis with expiration matching the token's expiration
        Key format: jti:{jti_value}
        Value format: {user_id}
        """
        try:
            ttl = int((expiration - datetime.now(UTC)).total_seconds())
            key = f"jti:{jti}"
            await cls._redis_client().setex(key, ttl, user_id)
        except Exception as e:
            msg = f"Error when storing JTI: {e}"
            logger.exception(msg)
            return False
        return True

    @classmethod
    async def is_jti_revoked(cls, jti: str) -> bool:
        """
        Check if a JTI has been revoked

        Returns:
            - True if JTI is found in the revoked list
            - False if JTI is not revoked
        """
        try:
            key = f"revoked:jti:{jti}"
            return await cls._redis_client().exists(key) == 1
        except Exception as e:
            msg = f"Redis error when checking revoked JTI: {e}"
            logger.exception(msg)
            # Safer to assume revoked if we can't check
            return True

    @classmethod
    async def validate_jti(cls, jti: str) -> None:
        """
        Validate if a JTI is not revoked

        Raises:
            - TokenRevokedError if JTI is revoked
        """
        if await cls.is_jti_revoked(jti):
            raise TokenRevokedError

    @classmethod
    async def revoke_token(cls, jti: str, expiration: datetime) -> bool:
        """
        Revoke a token by its JTI
        Store in a separate Redis key with same expiration as the token
        """
        try:
            ttl = int((expiration - datetime.now(UTC)).total_seconds())
            if ttl <= 0:
                return True  # Token already expired
            # Mark as revoked
            key = f"revoked:jti:{jti}"
            await cls._redis_client().setex(key, ttl, "1")
        except Exception as e:
            msg = f"Redis error when revoking JTI: {e}"
            logger.exception(msg)
            return False
        return True

    @classmethod
    async def store_refresh_token(
        cls,
        jti: str,
        user_id: str,
        access_token_jti: str,
        expiration: datetime,
    ) -> bool:
        """Store refresh token JTI and link it to the associated access token"""
        try:
            ttl = int((expiration - datetime.now(UTC)).total_seconds())
            key = f"refresh_token:{jti}"
            value = json.dumps(
                {
                    "user_id": user_id,
                    "access_token_jti": access_token_jti,
                    "created_at": datetime.now(UTC).isoformat(),
                },
            )
            await cls._redis_client().setex(key, ttl, value)

            # Also track by user for multi-device management
            user_refresh_key = f"user:{user_id}:refresh_tokens"
            await cls._redis_client().sadd(user_refresh_key, jti)  # type: ignore[call-arg]
        except Exception as e:
            msg = f"Redis error when storing refresh token: {e}"
            logger.exception(msg)
            return False
        return True

    @classmethod
    async def validate_refresh_token(cls, jti: str) -> dict[str, Any] | None:
        """Validate a refresh token JTI and return associated metadata"""
        try:
            key = f"refresh_token:{jti}"
            token_data_json = await cls._redis_client().get(key)
            if not token_data_json:
                return None  # Token not found or expired
            return json.loads(token_data_json)
        except Exception as e:
            msg = f"Error validating refresh token: {e}"
            logger.exception(msg)
            return None

    @classmethod
    async def delete_refresh_token(cls, user_id: str, refresh_jti: str) -> bool:
        """Removes a refresh token for and revoke its associated access token"""
        try:
            # Get all refresh tokens for the user
            user_refresh_key = f"user:{user_id}:refresh_tokens"
            refresh_tokens = await cls._redis_client().smembers(user_refresh_key)  # type: ignore[call-arg]

            pipe = cls._redis_client().pipeline()

            # Mark each access token as revoked and delete refresh token
            for jti in refresh_tokens:
                if jti != refresh_jti:
                    continue
                # Get linked access token
                key = f"refresh_token:{jti}"
                token_data_json = await cls._redis_client().get(key)

                if token_data_json:
                    token_data = json.loads(token_data_json)
                    access_token_jti = token_data.get("access_token_jti")

                    # Revoke access token if it exists
                    if access_token_jti:
                        pipe.set(
                            f"revoked:jti:{access_token_jti}",
                            "1",
                        )
                pipe.delete(key)
            await pipe.execute()
            # Remove the refresh token from the user's list
            await cls._redis_client().srem(user_refresh_key, refresh_jti)  # type: ignore[call-arg]
        except Exception as e:
            msg = f"Error revoking all user tokens: {e}"
            logger.exception(msg)
            return False
        return True

    @classmethod
    async def revoke_all_user_tokens(cls, user_id: str) -> bool:
        """Revoke all tokens for a user (for logout from all devices)"""
        try:
            # Get all refresh tokens for the user
            user_refresh_key = f"user:{user_id}:refresh_tokens"
            refresh_tokens = await cls._redis_client().smembers(user_refresh_key)  # type: ignore[call-arg]

            pipe = cls._redis_client().pipeline()

            # Mark each access token as revoked and delete refresh tokens
            for jti in refresh_tokens:
                # Get linked access token
                key = f"refresh_token:{jti}"
                token_data_json = await cls._redis_client().get(key)

                if token_data_json:
                    token_data = json.loads(token_data_json)
                    access_token_jti = token_data.get("access_token_jti")

                    # Revoke access token if it exists
                    if access_token_jti:
                        pipe.set(
                            f"revoked:jti:{access_token_jti}",
                            "1",
                        )
                pipe.delete(key)
            pipe.delete(user_refresh_key)

            await pipe.execute()
        except Exception as e:
            msg = f"Error revoking all user tokens: {e}"
            logger.exception(msg)
            return False
        return True
