# Using Redis for fast token lookups
import json
from datetime import UTC
from datetime import datetime
from typing import Any

import jwt
import redis
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordBearer
from redis.exceptions import RedisError

from app.core.config import settings
from app.exceptions import TokenRevokedError
from app.models.token import TokenType

from .token_factory import TokenFactory

# Configure Redis client
redis_client = redis.Redis(
    host=settings.REPOSITORY_HOST,
    port=settings.REDIS_PORT,
    db=settings.REPOSITORY_DB,
    decode_responses=True,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class TokenRepository:
    """Handle token storage and validation for revocation checks"""

    @staticmethod
    async def store_jti(jti: str, user_id: str, expiration: datetime) -> bool:
        """
        Store JTI in Redis with expiration matching the token's expiration
        Key format: jti:{jti_value}
        Value format: {user_id}
        """
        try:
            # Calculate TTL in seconds
            ttl = int((expiration - datetime.now(UTC)).total_seconds())

            # Store in Redis with expiration
            key = f"jti:{jti}"
            await redis_client.setex(key, ttl, user_id)
        except RedisError as e:
            print(f"Redis error when storing JTI: {e}")
            return False
        return True

    @staticmethod
    async def is_jti_revoked(jti: str) -> bool:
        """
        Check if a JTI has been revoked

        Returns:
            - True if JTI is found in the revoked list
            - False if JTI is not revoked
        """
        try:
            key = f"revoked:jti:{jti}"
            return await redis_client.exists(key) == 1
        except RedisError as e:
            print(f"Redis error when checking revoked JTI: {e}")
            # Safer to assume revoked if we can't check
            return True

    @staticmethod
    async def validate_jti(jti: str) -> None:
        """
        Validate if a JTI is not revoked

        Raises:
            - TokenRevokedError if JTI is revoked
        """
        if await TokenRepository.is_jti_revoked(jti):
            raise TokenRevokedError

    @staticmethod
    async def revoke_token(jti: str, expiration: datetime) -> bool:
        """
        Revoke a token by its JTI
        Store in a separate Redis key with same expiration as the token
        """
        try:
            # Calculate TTL in seconds
            ttl = int((expiration - datetime.now(UTC)).total_seconds())
            if ttl <= 0:
                return True  # Token already expired

            # Mark as revoked
            key = f"revoked:jti:{jti}"
            await redis_client.setex(key, ttl, "1")
        except RedisError as e:
            print(f"Redis error when revoking JTI: {e}")
            return False
        return True

    @staticmethod
    async def store_refresh_token(
        jti: str,
        user_id: str,
        access_token_jti: str,
        expiration: datetime,
    ) -> bool:
        """Store refresh token JTI and link it to the associated access token"""
        try:
            # Calculate TTL in seconds
            ttl = int((expiration - datetime.now(UTC)).total_seconds())

            # Store in Redis with expiration and link to access token
            key = f"refresh_token:{jti}"
            value = json.dumps(
                {
                    "user_id": user_id,
                    "access_token_jti": access_token_jti,
                    "created_at": datetime.now(UTC).isoformat(),
                },
            )
            await redis_client.setex(key, ttl, value)

            # Also track by user for multi-device management
            user_refresh_key = f"user:{user_id}:refresh_tokens"
            await redis_client.sadd(user_refresh_key, jti)
        except RedisError as e:
            logger.error(f"Redis error when storing refresh token: {e}")
            return False
        return True

    @staticmethod
    async def validate_refresh_token(jti: str) -> dict[str, Any] | None:
        """Validate a refresh token JTI and return associated metadata"""
        try:
            key = f"refresh_token:{jti}"
            token_data_json = await redis_client.get(key)

            if not token_data_json:
                return None  # Token not found or expired

            return json.loads(token_data_json)
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error validating refresh token: {e}")
            return None

    @staticmethod
    async def revoke_all_user_tokens(user_id: str) -> bool:
        """Revoke all tokens for a user (for logout from all devices)"""
        try:
            # Get all refresh tokens for the user
            user_refresh_key = f"user:{user_id}:refresh_tokens"
            refresh_tokens = await redis_client.smembers(user_refresh_key)

            pipe = redis_client.pipeline()

            # Mark each refresh token as revoked
            for jti in refresh_tokens:
                # Get linked access token
                key = f"refresh_token:{jti}"
                token_data_json = await redis_client.get(key)

                if token_data_json:
                    token_data = json.loads(token_data_json)
                    access_token_jti = token_data.get("access_token_jti")

                    # Revoke access token if it exists
                    if access_token_jti:
                        pipe.set(
                            f"revoked:jti:{access_token_jti}",
                            "1",
                            ex=86400,
                        )  # 24h

                # Revoke refresh token
                pipe.delete(key)

            # Clear the user's refresh token set
            pipe.delete(user_refresh_key)

            # Execute all commands
            await pipe.execute()
        except (RedisError, json.JSONDecodeError) as e:
            logger.error(f"Error revoking all user tokens: {e}")
            return False
        return True


async def verify_token(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    """
    Verify token validity and check if it has been revoked
    """
    try:
        payload = jwt.decode(
            token,
            settings.PUBLIC_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.BACKEND_CORS_ORIGINS,
            issuer=settings.DOMAIN,
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "strict_aud": False,
                "require": [
                    "iss",
                    "sub",
                    "exp",
                    "iat",
                    "nbf",
                    "aud",
                    "scope",
                    "verified",
                    "role",
                    "jti",
                ],
            },
        )

        # if not present in payload, will raise an exception above
        await TokenRepository.validate_jti(payload.get("jti"))

    except jwt.ImmatureSignatureError:
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not yet valid",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidSignatureError:
        # TODO: signature is invalid, do something about it
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.MissingRequiredClaimError:
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except TokenRevokedError:
        raise HTTPException(  # noqa: B904
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def create_access_token(
    subject: str,
    scopes: list[str],
    token_type: TokenType,
    **kwargs: Any,
) -> str:
    """
    Create a JWT with appropriate claims including a unique jti
    """
    token_factory = TokenFactory(token_type)
    token_data = token_factory(subject, scopes, **kwargs)
    return jwt.encode(
        token_data,
        settings.PRIVATE_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
