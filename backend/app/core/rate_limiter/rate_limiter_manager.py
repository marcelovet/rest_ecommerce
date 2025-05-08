import logging
import time
from typing import ClassVar

import redis.asyncio as redis
from redis.asyncio.client import Redis
from redis.exceptions import RedisError

from app.core.config import settings as st

from .exceptions import ElasticWindowCheckError
from .exceptions import FixedWindowCheckError
from .exceptions import SlidingWindowCheckError
from .utils import HTTP_CALLBACK
from .utils import IDENTIFIER
from .utils import WS_CALLBACK
from .utils import WindowType
from .utils import default_identifier
from .utils import http_default_callback
from .utils import ws_default_callback

# Configure Rate limit logger
logger = logging.getLogger("rate_limiter")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class RateLimiterManager:
    __initialized: ClassVar[bool] = False
    __redis_client: ClassVar[Redis | None] = None

    prefix: str = "ratelimit"
    identifier: IDENTIFIER = default_identifier
    http_callback: HTTP_CALLBACK = http_default_callback
    ws_callback: WS_CALLBACK = ws_default_callback
    strategy: WindowType = WindowType.FIXED_WINDOW
    disabled: bool = False

    @classmethod
    async def initialize(  # noqa: PLR0913
        cls,
        redis_url: str | None = None,
        *,
        identifier: IDENTIFIER = default_identifier,
        http_callback: HTTP_CALLBACK = http_default_callback,
        ws_callback: WS_CALLBACK = ws_default_callback,
        strategy: WindowType = WindowType.FIXED_WINDOW,
        disabled: bool = False,
    ) -> None:
        """Initialize the rate limiter.

        Args:
            prefix: The prefix to use for the keys. Defaults to "ratelimit".
            identifier: The function to use to get the identifier. Defaults to the IP address.
            http_callback: The callback to use when the ratelimit is hit for HTTP requests. Defaults to a 429 error.
            ws_callback: The callback to use when the ratelimit is hit for WebSocket messages. Defaults to a 1013 error.
            strategy: The strategy to use. Defaults to WindowType.FIXED_WINDOW.
            disabled: Whether to disable the rate limiter. Defaults to False.
        """  # noqa: E501
        cls.identifier = identifier
        cls.http_callback = http_callback
        cls.ws_callback = ws_callback
        cls.strategy = strategy
        cls.disabled = disabled

        if cls.__initialized:
            return

        if redis_url:
            try:
                cls.__redis_client = redis.from_url(
                    redis_url,
                    decode_responses=True,
                )
                await cls.__redis_client.ping()
                logger.info("Rate limiter connected to Redis")
                cls.__initialized = True
            except Exception as e:
                msg = f"Failed to connect to Redis: {e}"
                logger.exception(msg)
                cls.__redis_client = None
        else:
            try:
                redis_host = getattr(st, "RATE_LIMITER_HOST", "localhost")
                redis_port = getattr(st, "REDIS_PORT", 6379)
                redis_db = getattr(st, "RATE_LIMITER_DB", 1)

                cls.__redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    decode_responses=True,
                )
                await cls.__redis_client.ping()
                logger.info("Rate limiter connected to Redis")
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
        logger.info("Rate limiter shutdown complete")

    @classmethod
    def is_initialized(cls) -> bool:
        """Check if the rate limiter is initialized"""
        return cls.__initialized

    @classmethod
    def _redis_client(cls) -> Redis:
        """Get the Redis client"""
        if not isinstance(cls.__redis_client, Redis):
            msg = "Redis client not initialized"
            raise RedisError(msg)
        return cls.__redis_client

    @classmethod
    async def check_fixed_window(cls, key: str, limit: int, window_ms: int) -> int:
        """
        Check rate limit using fixed window algorithm
        Returns 0 if not rate limited, otherwise returns TTL in milliseconds
        """
        try:
            current = await cls._redis_client().get(key)
            if current is not None:
                current = int(current)
                if current + 1 > limit:
                    ttl = await cls._redis_client().pttl(key)
                    return ttl if ttl > 0 else 0
                await cls._redis_client().incr(key)
                return 0
            await cls._redis_client().set(key, 1, px=window_ms)
        except Exception as e:
            msg = f"Failed to check rate limit: {e}"
            logger.exception(msg)
            raise FixedWindowCheckError(msg) from e
        return 0

    @classmethod
    async def check_sliding_window(cls, key: str, limit: int, window_ms: int) -> int:
        """
        Check rate limit using sliding window algorithm
        Returns 0 if not rate limited, otherwise returns TTL in milliseconds
        """
        try:
            current_time = int(time.time())
            start_time = current_time - (window_ms / 1000)
            await cls._redis_client().zremrangebyscore(key, 0, start_time)
            current = await cls._redis_client().zcard(key)
            if current >= limit:
                ttl = await cls._redis_client().pttl(key)
                return ttl if ttl > 0 else 0
            await cls._redis_client().zadd(key, {str(current_time): current_time})
            await cls._redis_client().pexpire(key, window_ms)
        except Exception as e:
            msg = f"Failed to check rate limit: {e}"
            logger.exception(msg)
            raise SlidingWindowCheckError(msg) from e
        return 0

    @classmethod
    async def check_elastic_window(cls, key: str, limit: int, window_ms: int) -> int:
        """
        Check rate limit using elastic window algorithm
        Returns 0 if not rate limited, otherwise returns TTL in milliseconds
        """
        try:
            current = await cls._redis_client().get(key)
            if current is not None:
                current = int(current)
                if current + 1 > limit:
                    ttl = await cls._redis_client().pttl(key)
                    if ttl > 0:
                        # Extend timeout
                        new_ttl = ttl + window_ms
                        await cls._redis_client().pexpire(key, new_ttl)
                        return new_ttl
                    await cls._redis_client().set(key, 1, px=window_ms)
                    return 0
                await cls._redis_client().incr(key)
                return 0
            await cls._redis_client().set(key, 1, px=window_ms)
        except Exception as e:
            msg = f"Failed to check rate limit: {e}"
            logger.exception(msg)
            raise ElasticWindowCheckError(msg) from e
        return 0

    @classmethod
    async def check(
        cls,
        key: str,
        times: int,
        window_ms: int,
        strategy: WindowType,
    ) -> int:
        """
        Check rate limit using specified strategy
        Returns 0 if not rate limited, otherwise returns TTL in milliseconds

        Args:
            key (str): the key to check
            times (int): the limit number of access considering the window_ms
            window_ms (int): the time window in milliseconds
            strategy (WindowType): the rate limit strategy to use

        Raises:
            FixedWindowCheckError: an error checking the rate limit using fixed window algorithm
            SlidingWindowCheckError: an error checking the rate limit using the sliding window algorithm
            ElasticWindowCheckError: an error checking the rate limit using the elastic window algorithm
        """  # noqa: E501
        if strategy == WindowType.FIXED_WINDOW:
            return await cls.check_fixed_window(key, times, window_ms)
        if strategy == WindowType.SLIDING_WINDOW:
            return await cls.check_sliding_window(key, times, window_ms)
        return await cls.check_elastic_window(key, times, window_ms)
