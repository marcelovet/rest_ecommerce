import json
import logging
import re
import time
import traceback
import uuid
from datetime import UTC
from datetime import datetime
from typing import Any

import jwt
from fastapi import Request
from fastapi import Response
from fastapi import status
from fastapi.responses import JSONResponse
from jwt import PyJWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import RequestResponseEndpoint

from app.core.config import settings as st

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


class TokenSecurityMiddleware(BaseHTTPMiddleware):
    """Middleware for monitoring token operations across the application"""

    def __init__(
        self,
        app,
        jwt_secret_key: str,
        token_endpoints: dict[str, str] | None = None,
        excluded_paths: list[str] | None = None,
    ):
        super().__init__(app)
        self.token_endpoints = token_endpoints or {
            f"{st.API_VERSION_PREFIX}/auth/token": "create",
            f"{st.API_VERSION_PREFIX}/auth/refresh": "refresh",
            f"{st.API_VERSION_PREFIX}/auth/revoke": "revoke",
            f"{st.API_VERSION_PREFIX}/auth/verify": "verify",
            f"{st.API_VERSION_PREFIX}/auth/logout": "logout",
            f"{st.API_VERSION_PREFIX}/auth/sessions": "view_sessions",
            r"/api/v\d+/auth/.*": "auth_operation",
        }

        self.exact_path_mapping = {
            path: event_type
            for path, event_type in self.token_endpoints.items()
            if not any(c in path for c in ".*?+()[]{}^$")
        }
        self.regex_patterns = {
            re.compile(pattern): event_type
            for pattern, event_type in self.token_endpoints.items()
            if any(c in pattern for c in ".*?+()[]{}^$")
        }

        # Excluded paths for faster skipping
        self.excluded_paths = set(
            excluded_paths
            or [
                "/docs",
                "/redoc",
                "/openapi.json",
                "/favicon.ico",
                "/static/",
                "/health",
                "/metrics",
            ],
        )

        self.excluded_regex = [
            re.compile(path)
            for path in self.excluded_paths
            if any(c in path for c in ".*?+()[]{}^$")
        ]

        self.jwt_secret_key = jwt_secret_key
        self.log_data = {
            "event_type": "unknown",
            "user_id": "unknown",
            "token_type": "unknown",
            "jti": "unknown",
            "client_ip": None,
            "user_agent": None,
            "details": None,
            "duration_ms": None,
            "success": True,
        }
        self.request_id = str(uuid.uuid4())
        self.event_prefix = "request"
        self.start_time = 0

    def _should_skip_path(self, path: str) -> bool:
        """Fast check if path should be skipped"""
        if path in self.excluded_paths:
            return True
        return any(pattern.match(path) for pattern in self.excluded_regex)

    def _get_event_type(self, path: str) -> str:
        """Determine the token event type based on the request path"""
        if path in self.exact_path_mapping:
            return self.exact_path_mapping[path]
        for pattern, event_type in self.regex_patterns.items():
            if pattern.match(path):
                return event_type
        return "unknown"

    async def _buffer_request_body(self, request: Request) -> bytes:
        """Buffer the request body for reuse"""
        body = await request.body()
        setattr(request, "_body", body)  # noqa: B010
        return body

    async def _extract_token_from_request(
        self,
        request: Request,
    ) -> str | None:
        """Extract token from request if possible"""
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and " " in auth_header:
            _, token = auth_header.split(" ", 1)
            return token

        content_type = request.headers.get("Content-Type", "")

        if self.log_data["event_type"] in ["refresh", "verify"] and (
            "application/json" in content_type
            or "application/x-www-form-urlencoded" in content_type
        ):
            body_bytes = await self._buffer_request_body(request)

            if "application/json" in content_type:
                try:
                    body_json = json.loads(body_bytes)
                    return body_json.get("token") or body_json.get("refresh_token")
                except json.JSONDecodeError as e:
                    msg = f"Unnabled to decode json from request body: {e!s}"
                    logger.debug(msg)
                except Exception as e:  # noqa: BLE001
                    msg = f"Unnabled to extract token from request body: {e!s}"
                    logger.debug(msg)

            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    body_text = body_bytes.decode()
                    form_data = {}
                    for item in body_text.split("&"):
                        if "=" in item:
                            key, value = item.split("=", 1)
                            form_data[key] = value
                    return form_data.get("token") or form_data.get("refresh_token")
                except Exception as e:  # noqa: BLE001
                    msg = f"Unnabled to extract token from request body: {e!s}"
                    logger.debug(msg)

        return token

    def _extract_token_info_from_token(self, token: str) -> tuple[str, str]:
        """
        Extract token information from token if possible

        Args:
            token (str): The token to extract information from
        Returns:
            tuple[str, str]: The extracted token information (jti, user_id)
        """
        try:
            if token.count(".") == 2:  # noqa: PLR2004
                try:
                    import base64

                    payload_b64 = token.split(".")[1]
                    # Add padding if needed
                    padding_needed = len(payload_b64) % 4
                    if padding_needed:
                        payload_b64 += "=" * (4 - padding_needed)

                    payload_json = base64.urlsafe_b64decode(payload_b64)
                    payload = json.loads(payload_json)

                    jti = str(payload.get("jti", "unknown"))
                    sub = str(payload.get("sub", "unknown").replace("user:", ""))
                except Exception:  # noqa: BLE001, S110
                    pass
                return jti, sub

            payload = jwt.decode(
                token,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
            jti = str(payload.get("jti", "unknown"))
            sub = str(payload.get("sub", "unknown").replace("user:", ""))
        except PyJWTError as e:
            msg = f"Failed to decode token: {e!s}"
            logger.debug(msg)
            return "unknown", "unknown"
        except Exception as e:  # noqa: BLE001
            msg = f"Failed to decode token: {e!s}"
            logger.debug(msg)
            return "unknown", "unknown"
        return jti, sub

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Skip excluded paths or non-token endpoints
        path = request.url.path
        if self._should_skip_path(path):
            return await call_next(request)
        self.log_data["event_type"] = self._get_event_type(path)
        if self.log_data["event_type"] == "unknown":
            return await call_next(request)

        self.log_data["client_ip"] = request.client.host if request.client else None
        self.log_data["user_agent"] = request.headers.get("User-Agent", "unknown")

        token = await self._extract_token_from_request(request)
        self.log_data["jti"], self.log_data["user_id"] = (
            self._extract_token_info_from_token(token)
            if token
            else ("unknown", "unknown")
        )
        self.log_data["token_type"] = self.log_data["event_type"]
        if self.log_data["event_type"] != "unknown":
            self.event_prefix = self.log_data["event_type"]
        self.log_data["event_type"] = f"{self.event_prefix}_attempt"

        # Log request attempt
        self.log_data["details"] = {
            "operation": "start",
            "phase": "request",
            "request_id": self.request_id,
            "method": request.method,
            "path": path,
            "query_params": str(request.query_params),
        }

        TokenLogger.log_token_event(**self.log_data)

        return await self._handle_response(request, call_next)

    def _extract_token_info_from_response(
        self,
        response_data: Any,
        token_key: str,
    ) -> bool:
        """Extract token information from response if possible"""
        try:
            if "token_type" in response_data[token_key]:
                self.log_data["token_type"] = response_data[token_key]["token_type"]

            if "token" not in response_data[token_key] or not isinstance(
                response_data[token_key]["token"],
                str,
            ):
                return False
            self.log_data["jti"], self.log_data["user_id"] = (
                self._extract_token_info_from_token(response_data[token_key]["token"])
                if response_data[token_key]["token"]
                else ("unknown", "unknown")
            )
        except json.JSONDecodeError as e:
            msg = f"Failed to decode response body as JSON: {e!s}"
            logger.debug(msg)
            return False
        except Exception as e:  # noqa: BLE001
            msg = f"Failed to extract token info from response: {e!s}"
            logger.debug(msg)
            return False
        return True

    def log_token_response(
        self,
        status_code: int,
        error_detail: str | None = None,
    ) -> None:
        # Create response details for logging
        response_details = {
            "operation": "complete" if self.log_data["success"] else "failed",
            "phase": "response",
            "request_id": self.log_data["request_id"],
            "status_code": status_code,
            "duration_ms": self.log_data["duration_ms"],
        }

        if not self.log_data["success"]:
            response_details["error"] = (
                error_detail if error_detail else "Unknown error"
            )
            if status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
                response_details["stack_trace"] = traceback.format_exc()

        self.log_data["event_type"] = (
            self.event_prefix
            if self.log_data["success"]
            else f"{self.event_prefix}_error"
        )

        TokenLogger.log_token_event(**self.log_data)

    async def _handle_response(  # noqa: C901
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Handle response"""
        error_detail = None
        response_data = None

        self.start_time = time.perf_counter()
        try:
            response = await call_next(request)

            should_parse_response = (
                self.event_prefix in ["create", "refresh"]
                and response.status_code < status.HTTP_400_BAD_REQUEST
                and response.headers.get("content-type", "").startswith(
                    "application/json",
                )
            )

            if should_parse_response:
                try:
                    response_body = response.body
                    setattr(response, "_body", response_body)  # noqa: B010
                    response_data = json.loads(response_body)
                except Exception as e:  # noqa: BLE001
                    msg = f"Failed to parse response body: {e!s}"
                    logger.debug(msg)

            if response.status_code >= status.HTTP_400_BAD_REQUEST:
                self.log_data["success"] = False
                if isinstance(response, JSONResponse):
                    try:
                        error_body = response.body
                        setattr(response, "_body", error_body)  # noqa: B010
                        error_data = json.loads(error_body)
                        error_detail = error_data.get("detail")
                    except json.JSONDecodeError as e:
                        msg = f"Failed to decode response body as JSON: {e!s}"
                        logger.debug(msg)
                    except Exception as e:  # noqa: BLE001
                        msg = f"Failed to extract token info from response: {e!s}"
                        logger.debug(msg)
        except Exception as e:  # noqa: BLE001
            self.log_data["success"] = False
            error_detail = str(e)
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response = JSONResponse(
                content={"detail": "Internal server error"},
                status_code=status_code,
            )

        self.log_data["duration_ms"] = round(
            (time.perf_counter() - self.start_time) * 1000,
        )

        if not response_data:
            self.log_token_response(response.status_code, error_detail)
        else:
            for token_key in ["access_token", "refresh_token", "token"]:
                has_info = self._extract_token_info_from_response(
                    response_data,
                    token_key,
                )
                if has_info:
                    self.log_token_response(response.status_code, error_detail)

        return response
