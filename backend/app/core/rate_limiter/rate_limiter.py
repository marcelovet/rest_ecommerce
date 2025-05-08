from fastapi.routing import APIRoute
from starlette.requests import Request
from starlette.responses import Response
from starlette.websockets import WebSocket

from .exceptions import TimesLimitDefinitionError
from .exceptions import TimeWindowDefinitionError
from .exceptions import WindowCheckError
from .rate_limiter_manager import RateLimiterManager
from .rate_limiter_manager import logger
from .utils import HTTP_CALLBACK
from .utils import IDENTIFIER
from .utils import WS_CALLBACK
from .utils import WindowType


class RateLimiter:
    """
    RateLimiter is a class that provides methods for rate limiting.
    This class is intended to be used as dependency for FastAPI routes.

    Example:
    ```python
    from typing import Annotated
    from contextlib import asynccontextmanager

    from fastapi import Depends, FastAPI
    from rate_limiter import RateLimiter, RateLimiterManager

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await RateLimiterManager.initialize(redis_url="redis://localhost:6379/0")
        yield
        await RateLimiterManager.shutdown()

    app = FastAPI()

    # accepts 2 requests per 5 seconds per IP (default)
    @app.get("/foo", dependencies=[Depends(RateLimiter(times=2, seconds=5))])
    async def get_foo():
        return {"foo": 1}
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        times: int = 1,
        milliseconds: int = 0,
        seconds: int = 0,
        minutes: int = 0,
        hours: int = 0,
        identifier: IDENTIFIER | None = None,
        callback: HTTP_CALLBACK | None = None,
        strategy: WindowType = WindowType.FIXED_WINDOW,
    ):
        self.times = times
        if self.times <= 0:
            msg = "times must be greater than 0"
            raise TimesLimitDefinitionError(msg)

        self.time_window = (
            milliseconds + (1000 * seconds) + (60000 * minutes) + (3600000 * hours)
        )
        if self.time_window <= 0:
            msg = "time window must be greater than 0"
            raise TimeWindowDefinitionError(msg)
        self.identifier = identifier
        self.callback = callback
        self.strategy = strategy

        self.route_index = 0
        self.dep_index = 0
        self._index_set = False

    def _set_indexes(self, request: Request):
        for i, route in enumerate(request.app.routes):
            if not isinstance(route, APIRoute):
                continue
            if route.path == request.scope["path"] and request.method in route.methods:
                self.route_index = i
                for j, dependency in enumerate(route.dependencies):
                    if self is dependency.dependency:
                        self.dep_index = j
                        break
        self._index_set = True

    async def __call__(self, request: Request, response: Response):
        if RateLimiterManager.disabled:
            return None
        if not RateLimiterManager.is_initialized():
            msg = (
                "RateLimiterManager must be initialized at application startup "
                "for http rate limiting"
            )
            logger.warning(msg)
            return None

        if not self._index_set:
            self._set_indexes(request)

        identifier = self.identifier or RateLimiterManager.identifier
        strategy = self.strategy or RateLimiterManager.strategy
        rate_key = await identifier(request)
        key = f"{RateLimiterManager.prefix}:{rate_key}:{self.route_index}:{self.dep_index}"  # noqa: E501
        try:
            pexpire = await RateLimiterManager.check(
                key,
                self.times,
                self.time_window,
                strategy,
            )
        except WindowCheckError:
            return None
        if pexpire != 0:
            callback = self.callback or RateLimiterManager.http_callback
            return await callback(request, response, pexpire)
        return None


class WebSocketRateLimiter:
    """
    WebSocketRateLimiter is a class that provides methods for rate limiting
    data transfer over the socket.

    Example:
    ```python
    from typing import Annotated
    from contextlib import asynccontextmanager

    from fastapi import WebSocket, FastAPI
    from rate_limiter import WebSocketRateLimiter, RateLimiterManager

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await RateLimiterManager.initialize(redis_url="redis://localhost:6379/0")
        yield
        await RateLimiterManager.shutdown()

    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        ratelimit = WebSocketRateLimiter(times=1, seconds=1)
        while True:
            try:
                data = await websocket.receive_text()
                await ratelimit(websocket)
                await websocket.send_text(f"Hello, world")
            except WebSocketRateLimitException:
                await websocket.send_text(f"Hello again")
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        times: int = 1,
        milliseconds: int = 0,
        seconds: int = 0,
        minutes: int = 0,
        hours: int = 0,
        identifier: IDENTIFIER | None = None,
        callback: WS_CALLBACK | None = None,
        strategy: WindowType = WindowType.FIXED_WINDOW,
    ):
        self.times = times
        if self.times <= 0:
            msg = "times must be greater than 0"
            raise TimesLimitDefinitionError(msg)
        self.time_window = (
            milliseconds + 1000 * seconds + 60000 * minutes + 3600000 * hours
        )
        if self.time_window <= 0:
            msg = "time window must be greater than 0"
            raise TimeWindowDefinitionError(msg)
        self.identifier = identifier
        self.callback = callback
        self.strategy = strategy

    async def __call__(self, ws: WebSocket, context_key: str = ""):
        if RateLimiterManager.disabled:
            return None
        if not RateLimiterManager.is_initialized():
            msg = (
                "RateLimiterManager must be initialized at application startup "
                "for websocket rate limiting"
            )
            logger.warning(msg)
            return None

        identifier = self.identifier or RateLimiterManager.identifier
        strategy = self.strategy or RateLimiterManager.strategy
        rate_key = await identifier(ws)
        key = f"{RateLimiterManager.prefix}:ws:{rate_key}:{context_key}"
        try:
            pexpire = await RateLimiterManager.check(
                key,
                self.times,
                self.time_window,
                strategy,
            )
        except WindowCheckError:
            return None
        if pexpire != 0:
            callback = self.callback or RateLimiterManager.ws_callback
            return await callback(ws, pexpire)
        return None
