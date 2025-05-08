import typing as t
from enum import IntEnum

from fastapi import HTTPException
from fastapi import WebSocketException
from starlette.requests import Request
from starlette.responses import Response
from starlette.status import HTTP_429_TOO_MANY_REQUESTS
from starlette.status import WS_1013_TRY_AGAIN_LATER
from starlette.websockets import WebSocket


class WindowType(IntEnum):
    """
    Rate limit window types for the rate limiter.
    """

    FIXED_WINDOW = 0
    SLIDING_WINDOW = 1
    FIXED_WINDOW_ELASTIC = 2


HTTP_CALLBACK = t.Callable[[Request, Response, int], t.Awaitable[t.Any]]
IDENTIFIER = t.Callable[[Request | WebSocket], t.Awaitable[str]]
WS_CALLBACK = t.Callable[[WebSocket, int], t.Awaitable[t.Any]]


async def default_identifier(request: Request | WebSocket) -> str:
    """default identifier function

    Args:
        request: The Request or WebSocket object.

    Returns:
        The identifier.
    """
    host = request.client.host if request.client else "unknown"
    ip = (
        forwarded.split(",")[0]
        if (forwarded := request.headers.get("X-Forwarded-For"))
        else host
    )
    return ip + ":" + request.scope["path"]


async def http_default_callback(request: Request, response: Response, pexpire: int):
    """default callback when too many requests

    Args:
        request: The Request object.
        response: The Response object.
        pexpire: The remaining milliseconds.
    """
    raise HTTPException(
        status_code=HTTP_429_TOO_MANY_REQUESTS,
        detail="Too Many Requests",
        headers={"Retry-After": str(pexpire)},
    )


async def ws_default_callback(ws: WebSocket, pexpire: int):
    """default callback when too many messages

    Args:
        ws: The WebSocket connection.
        pexpire: The remaining milliseconds.
    """
    raise WebSocketException(
        code=WS_1013_TRY_AGAIN_LATER,
        reason=f"Too Many Messages. Retry-After: {pexpire}",
    )
