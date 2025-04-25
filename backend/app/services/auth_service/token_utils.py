import inspect
import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC
from datetime import datetime
from functools import wraps
from typing import Any

import jwt
from fastapi import Request
from fastapi import Response
from fastapi.responses import JSONResponse
from jwt import PyJWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import RequestResponseEndpoint

# Configure structured logger with proper formatting
logger = logging.getLogger("token_security")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class TokenSecurityMetrics:
    """Track token operation metrics for anomaly detection"""

    # Store operation counts with timeframes
    operation_counts = {
        "1min": {},  # Last minute
        "5min": {},  # Last 5 minutes
        "1hour": {},  # Last hour
    }

    # Store operation latencies
    operation_latencies = {}

    # Store error rates
    error_rates = {}

    @classmethod
    def record_operation(cls, event_type: str, duration_ms: int, success: bool):  # noqa: FBT001
        """Record an operation for metrics tracking"""
        now = int(time.time())

        # Record in appropriate time buckets
        minute_bucket = now - (now % 60)
        five_min_bucket = now - (now % 300)
        hour_bucket = now - (now % 3600)

        buckets = {
            "1min": minute_bucket,
            "5min": five_min_bucket,
            "1hour": hour_bucket,
        }

        # Update counts for each timeframe
        for timeframe, bucket in buckets.items():
            if bucket not in cls.operation_counts[timeframe]:
                # Clean old buckets if needed
                cls.operation_counts[timeframe] = {bucket: {}}

            counts = cls.operation_counts[timeframe][bucket]
            if event_type not in counts:
                counts[event_type] = {"total": 0, "success": 0, "error": 0}

            counts[event_type]["total"] += 1
            if success:
                counts[event_type]["success"] += 1
            else:
                counts[event_type]["error"] += 1

        # Record latency
        if event_type not in cls.operation_latencies:
            cls.operation_latencies[event_type] = {
                "count": 0,
                "total_ms": 0,
                "min_ms": float("inf"),
                "max_ms": 0,
            }

        stats = cls.operation_latencies[event_type]
        stats["count"] += 1
        stats["total_ms"] += duration_ms
        stats["min_ms"] = min(stats["min_ms"], duration_ms)
        stats["max_ms"] = max(stats["max_ms"], duration_ms)

    @classmethod
    def check_anomalies(cls, event_type: str) -> dict[str, Any]:
        """Check for anomalies in token operations"""
        anomalies = {}

        # Check error rate anomalies
        for timeframe, buckets in cls.operation_counts.items():
            if not buckets:
                continue

            latest_bucket = max(buckets.keys())
            counts = buckets[latest_bucket]

            if event_type in counts:
                event_counts = counts[event_type]
                if event_counts["total"] > 10:  # noqa: PLR2004
                    error_rate = event_counts["error"] / event_counts["total"]
                    if error_rate > 0.3:  # error rate threshold  # noqa: PLR2004
                        anomalies[f"high_error_rate_{timeframe}"] = error_rate

        # Check volume anomalies (sudden spike in operations)
        if len(cls.operation_counts["1min"]) >= 2:  # noqa: PLR2004
            buckets = sorted(cls.operation_counts["1min"].keys(), reverse=True)
            current = buckets[0]
            previous = buckets[1]

            current_count = (
                cls.operation_counts["1min"][current]
                .get(event_type, {})
                .get("total", 0)
            )
            previous_count = (
                cls.operation_counts["1min"][previous]
                .get(event_type, {})
                .get("total", 0)
            )

            if previous_count > 0 and current_count > previous_count * 2:
                # Volume more than doubled
                anomalies["volume_spike"] = {
                    "current": current_count,
                    "previous": previous_count,
                    "ratio": current_count / previous_count,
                }

        return anomalies


class TokenLogger:
    """Event logger with security monitoring capabilities"""

    @staticmethod
    def log_token_event(  # noqa: C901, PLR0913
        event_type: str,
        user_id: str,
        token_type: str,
        jti: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
        details: dict[str, Any] | None = None,
        duration_ms: int | None = None,
        success: bool = True,  # noqa: FBT001, FBT002
    ):
        """
        Log token-related events
        """
        # Create the core event data
        event_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": f"token_{event_type}",
            "user_id": user_id,
            "token_type": token_type,
            "jti": jti,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }

        # Record metrics if duration is provided
        if duration_ms is not None:
            event_data["duration_ms"] = duration_ms
            TokenSecurityMetrics.record_operation(event_type, duration_ms, success)

            # Check for performance anomalies
            if token_type in TokenSecurityMetrics.operation_latencies:
                stats = TokenSecurityMetrics.operation_latencies[token_type]
                if stats["count"] > 10:  # noqa: PLR2004
                    avg_ms = stats["total_ms"] / stats["count"]
                    if duration_ms > avg_ms * 3:  # 3x slower than average
                        event_data["performance_alert"] = {
                            "duration_ms": duration_ms,
                            "avg_ms": avg_ms,
                            "ratio": duration_ms / avg_ms,
                        }

        # Check for security anomalies
        anomalies = TokenSecurityMetrics.check_anomalies(event_type)
        if anomalies:
            event_data["anomalies"] = anomalies

            # Elevate log level for anomalies
            log_level = logging.WARNING

            # Critical anomalies require higher visibility
            if "volume_spike" in anomalies and anomalies["volume_spike"]["ratio"] > 5:  # noqa: PLR2004
                log_level = logging.CRITICAL
        else:
            log_level = logging.INFO

        # Add any additional details
        if details:
            event_data.update(details)

            # Check for explicit security alerts
            if details.get("security_alert"):
                log_level = logging.CRITICAL

            # Check for error indicators
            if "error" in details:
                log_level = logging.ERROR

        # Log at appropriate level
        logger.log(log_level, json.dumps(event_data))

        # Trigger alerts for high-severity events
        if log_level >= logging.CRITICAL:
            TokenLogger.trigger_security_alert(event_data)

    @staticmethod
    def trigger_security_alert(event_data: dict[str, Any]):
        """Trigger a security alert for suspicious activity"""
        alert_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "alert_type": "token_security",
            "severity": "HIGH",
            "title": (
                "Suspicious token activity detected for "
                f"user {event_data.get('user_id')}"
            ),
            "description": (
                f"Abnormal token operation detected: {event_data.get('event')}"
            ),
            "details": event_data,
            "recommendations": [
                "Review recent user activity",
                "Consider forcing password reset",
                "Check for unauthorized access",
            ],
        }

        msg = f"SECURITY ALERT: {json.dumps(alert_data)}"
        logger.critical(msg)

        # TODO: integrate with security systems:
        # 1. Send to SIEM system
        # 2. Trigger incident response workflow
        # 3. Send alerts to security team


def monitor_token_operation(event_type: str):
    """
    Advanced decorator for monitoring token operations with security analytics.

    Args:
        event_type: Type of token event (create, verify, revoke, refresh, etc.)

    Example:
        @app.post("/auth/token")
        @monitor_token_operation("create")
        async def create_token(request: Request, ...):
            # Function implementation
    """

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()

            # Extract request if available using introspection
            request: Request | None = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            # Also check kwargs for request
            if not request and "request" in kwargs:
                request = kwargs["request"]

            # Get client info if request is available
            client_ip = user_agent = None
            if request is not None:
                client_ip = request.client.host if request.client else None
                user_agent = request.headers.get("user-agent", "unknown")

            # Extract token details from kwargs or try to infer from signatures
            user_id = kwargs.get("user_id")
            token_type = kwargs.get("token_type", "unknown")
            jti = kwargs.get("jti")

            # Try to extract token info from token_data if available
            token_data = kwargs.get("token_data")
            if token_data and isinstance(token_data, dict):
                if not user_id and "sub" in token_data:
                    user_id = token_data["sub"]
                    if user_id and user_id.startswith("user:"):
                        user_id = user_id.replace("user:", "")

                if not jti and "jti" in token_data:
                    jti = token_data["jti"]

            # Generate context map with callable parameters for detailed logging
            context = {}
            signature = inspect.signature(func)
            for param_name in signature.parameters:
                if param_name in kwargs and param_name not in ["request", "password"]:
                    context[param_name] = kwargs[param_name]

            pre_op_details = {
                "operation": "start",
                "phase": "attempt",
                "context": context,
            }

            # For security-sensitive operations, log attempts
            if event_type in [
                "create",
                "verify",
                "revoke",
                "refresh",
                "login",
                "logout",
            ]:
                TokenLogger.log_token_event(
                    f"{event_type}_attempt",
                    user_id,
                    token_type,
                    jti,
                    client_ip,
                    user_agent,
                    pre_op_details,
                )

            result = None
            try:
                result = (
                    await func(*args, **kwargs)
                    if inspect.iscoroutinefunction(func)
                    else func(*args, **kwargs)
                )

                # Update JTI from result if available
                if isinstance(result, dict):
                    if not jti and "jti" in result:
                        jti = result["jti"]
                    elif (
                        not jti
                        and "token_data" in result
                        and isinstance(result["token_data"], dict)
                    ):
                        jti = result["token_data"].get("jti")

                # Extract user_id from result if not already available
                if not user_id and isinstance(result, dict):
                    if "user_id" in result:
                        user_id = result["user_id"]
                    elif "user" in result and isinstance(result["user"], dict):
                        user_id = result["user"].get("id")

                duration_ms = round((time.time() - start_time) * 1000)
                # Post-operation success logging with result summary
                result_summary = {}
                if isinstance(result, dict):
                    # Create safe summary of result without sensitive data
                    result_summary = {
                        k: v
                        for k, v in result.items()
                        if k
                        not in ["token", "access_token", "refresh_token", "password"]
                        and not isinstance(v, (bytes, bytearray))
                    }

                post_op_details = {
                    "operation": "complete",
                    "status": "success",
                    "duration_ms": duration_ms,
                    "result_summary": result_summary,
                }

                TokenLogger.log_token_event(
                    event_type,
                    user_id,
                    token_type,
                    jti,
                    client_ip,
                    user_agent,
                    post_op_details,
                    duration_ms,
                    True,
                )

            except Exception as e:
                duration_ms = round((time.time() - start_time) * 1000)
                # Detailed error logging with stack trace for debugging
                error_details = {
                    "operation": "failed",
                    "status": "error",
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "duration_ms": duration_ms,
                }

                # Add stack trace for internal server errors
                import traceback

                error_details["stack_trace"] = traceback.format_exc()
                TokenLogger.log_token_event(
                    f"{event_type}_error",
                    user_id,
                    token_type,
                    jti,
                    client_ip,
                    user_agent,
                    error_details,
                    duration_ms,
                    False,
                )

                raise
            return result

        return wrapper

    return decorator


class TokenSecurityMiddleware(BaseHTTPMiddleware):
    """Middleware for monitoring token operations across the application"""

    def __init__(
        self,
        app,
        jwt_secret_key: str,
        token_endpoints: dict[str, str] | None = None,
    ):
        super().__init__(app)
        self.token_endpoints = token_endpoints or {
            r"/auth/token": "create",
            r"/auth/refresh": "refresh",
            r"/auth/revoke": "revoke",
            r"/auth/verify": "verify",
            r"/auth/logout": "logout",
            r"/auth/sessions": "view_sessions",
        }
        # Compile regex patterns for faster matching
        self.token_endpoint_patterns = {
            re.compile(pattern): event_type
            for pattern, event_type in self.token_endpoints.items()
        }
        self.jwt_secret_key = jwt_secret_key

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Skip excluded paths
        path = request.url.path
        if all(pattern.match(path) is None for pattern in self.token_endpoint_patterns):
            return await call_next(request)

        event_type = self._get_event_type(path)
        start_time = time.time()

        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent", "unknown")

        token = await self._extract_token_from_request(request, event_type)
        jti, user_id = (
            self._extract_token_info_from_token(token)
            if token
            else ("unknown", "unknown")
        )
        token_type = event_type
        request_id = str(uuid.uuid4())
        event_prefix = event_type if event_type != "unknown" else "request"

        # Log request attempt
        request_details = {
            "operation": "start",
            "phase": "request",
            "request_id": request_id,
            "method": request.method,
            "path": path,
            "query_params": str(request.query_params),
        }

        TokenLogger.log_token_event(
            f"{event_prefix}_attempt",
            user_id,
            token_type,
            jti,
            client_ip,
            user_agent,
            request_details,
        )

        # Process the request and capture response
        response = None
        success = True
        error_detail = None
        status_code = 200

        try:
            response = await call_next(request)
            status_code = response.status_code

            # Check if response status indicates success
            if status_code >= 400:
                success = False
                # Try to extract error detail from response
                if isinstance(response, JSONResponse):
                    try:
                        response_body = response.body
                        response_data = json.loads(response_body)
                        error_detail = response_data.get("detail")
                    except:
                        pass
        except Exception as e:
            # Capture unhandled exceptions
            success = False
            error_detail = str(e)
            status_code = HTTP_500_INTERNAL_SERVER_ERROR

            # Create a new response for the unhandled exception
            response = JSONResponse(
                content={"detail": "Internal server error"},
                status_code=status_code,
            )

        # Calculate duration
        duration_ms = round((time.time() - start_time) * 1000)

        # Extract token info from response if possible
        response_token_info = await self._extract_token_info_from_response(response)

        # Use response token info if we couldn't get it from request
        if response_token_info:
            if not user_id and "user_id" in response_token_info:
                user_id = response_token_info["user_id"]
            if not jti and "jti" in response_token_info:
                jti = response_token_info["jti"]
            if "token_type" in response_token_info:
                token_type = response_token_info["token_type"]

        # Create response details for logging
        response_details = {
            "operation": "complete" if success else "failed",
            "phase": "response",
            "request_id": request_id,
            "status_code": status_code,
            "duration_ms": duration_ms,
        }

        # Add error details if present
        if not success:
            response_details["error"] = (
                error_detail if error_detail else "Unknown error"
            )

            # Add stack trace for 500 errors
            if status_code >= 500:
                response_details["stack_trace"] = traceback.format_exc()

        # Log response
        TokenLogger.log_token_event(
            event_prefix if success else f"{event_prefix}_error",
            user_id,
            token_type,
            jti,
            client_ip,
            user_agent,
            response_details,
            duration_ms,
            success,
        )

        return response

    def _get_event_type(self, path: str) -> str:
        """Determine the token event type based on the request path"""
        for pattern, event_type in self.token_endpoint_patterns.items():
            if pattern.match(path):
                return event_type
        return "unknown"

    async def _extract_token_from_request(
        self, request: Request, event_type: str
    ) -> str | None:
        """Extract token from request if possible"""
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and " " in auth_header:
            _, token = auth_header.split(" ", 1)

        # For token refresh/verify endpoints, look for token in request body
        token_from_body = None
        if not token and event_type in ["refresh", "verify"]:
            try:
                body_bytes = await request.body()
                # Try to parse as JSON
                try:
                    body = json.loads(body_bytes)
                    token_from_body = body.get("token") or body.get("refresh_token")
                except json.JSONDecodeError:
                    # Try to parse as form data
                    body_text = body_bytes.decode()
                    if "token=" in body_text or "refresh_token=" in body_text:
                        # Simple parsing for form data
                        form_items = body_text.split("&")
                        for item in form_items:
                            if item.startswith(("token=", "refresh_token=")):
                                _, value = item.split("=", 1)
                                token_from_body = value
                                break
            except Exception as e:
                msg = f"Unnabled to extract token from request body: {e!s}"
                logger.exception(msg)

        return token if token else token_from_body

    def _extract_token_info_from_token(self, token: str) -> tuple[str, str]:
        """
        Extract token information from token if possible

        Args:
            token (str): The token to extract information from
        Returns:
            tuple[str, str]: The extracted token information (jti, user_id)
        """
        try:
            payload = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "strict_aud": False,
                    "require": [
                        "sub",
                        "jti",
                    ],
                },
            )
            jti = str(payload.get("jti", "unknown"))
            sub = str(payload.get("sub", "unknown").replace("user:", ""))
        except PyJWTError as e:
            msg = f"Failed to decode token: {e!s}"
            logger.exception(msg)
            return "unknown", "unknown"
        except Exception as e:
            msg = f"Failed to decode token: {e!s}"
            logger.exception(msg)
            return "unknown", "unknown"
        return jti, sub

    async def _extract_token_info_from_response(
        self, response: Response
    ) -> Dict[str, Any]:
        """Extract token information from response if possible"""
        if not isinstance(response, JSONResponse):
            return {}

        try:
            response_body = response.body
            response_data = json.loads(response_body)

            result = {}

            # Extract user_id
            if "user_id" in response_data:
                result["user_id"] = response_data["user_id"]
            elif "user" in response_data and isinstance(response_data["user"], dict):
                result["user_id"] = response_data["user"].get("id")

            # Extract token_type
            if "token_type" in response_data:
                result["token_type"] = response_data["token_type"]

            # Try to extract JTI by decoding tokens in the response
            for token_key in ["access_token", "token", "refresh_token"]:
                if token_key in response_data and isinstance(
                    response_data[token_key], str
                ):
                    token = response_data[token_key]
                    try:
                        payload = jwt.decode(
                            token,
                            options={"verify_signature": False},
                        )
                        if "jti" in payload:
                            result["jti"] = payload["jti"]
                            break
                    except:
                        continue

            return result
        except:
            return {}
