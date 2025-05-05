import asyncio
import contextlib
import json
import logging
import re
import sys
import time
import traceback
import uuid
from datetime import UTC
from datetime import datetime
from typing import Any
from typing import ClassVar

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
                if (
                    event_counts["total"] > 10  # noqa: PLR2004
                    and event_counts["error"] / event_counts["total"] > 0.3  # noqa: PLR2004
                ):
                    anomalies[f"high_error_rate_{timeframe}"] = (
                        event_counts["error"] / event_counts["total"]
                    )

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

    _log_queue: ClassVar[list[dict[str, Any]]] = []
    _max_batch_size: ClassVar[int] = 10
    _flush_interval: ClassVar[float] = 5.0  # seconds
    _last_flush_time: ClassVar[float] = time.monotonic()
    _flush_lock: ClassVar[asyncio.Lock] = asyncio.Lock()
    _initialized: ClassVar[bool] = False
    _critical_queue: ClassVar[
        list[dict[str, Any]]
    ] = []  # Separate queue for critical logs
    _background_task: ClassVar[asyncio.Task | None] = None

    @classmethod
    def initialize(
        cls,
        max_batch_size: int = 10,
        flush_interval: float = 5.0,
        start_background_task: bool = True,  # noqa: FBT001, FBT002
    ):
        """Initialize the batched logger configuration"""
        cls._max_batch_size = max_batch_size
        cls._flush_interval = flush_interval
        cls._initialized = True

        # Start background flusher if requested
        if start_background_task and cls._background_task is None:
            cls._background_task = asyncio.create_task(cls._background_flusher())

    @classmethod
    async def _background_flusher(cls):
        """Background task that periodically flushes logs"""
        try:
            while True:
                await asyncio.sleep(cls._flush_interval)
                if cls._log_queue or cls._critical_queue:
                    await cls._flush_logs()
        except asyncio.CancelledError:
            # Ensure logs are flushed when the task is cancelled
            if cls._log_queue or cls._critical_queue:
                await cls._flush_logs()
            raise

    @classmethod
    async def shutdown(cls):
        """Flush remaining logs and cleanup resources during application shutdown"""
        if cls._background_task is not None:
            cls._background_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cls._background_task
            cls._background_task = None
        await cls._flush_logs()

    @classmethod
    async def _should_flush(cls) -> bool:
        """Determine if logs should be flushed based on size or time"""
        return (
            len(cls._log_queue) >= cls._max_batch_size
            or (time.monotonic() - cls._last_flush_time) >= cls._flush_interval
        )

    @classmethod
    async def _flush_logs(cls):
        """Flush queued logs to the logging system"""
        async with cls._flush_lock:
            # Process critical logs first and immediately
            if cls._critical_queue:
                critical_logs = cls._critical_queue.copy()
                cls._critical_queue = []
                for log_entry in critical_logs:
                    try:
                        log_level = logging.CRITICAL
                        logger.log(log_level, json.dumps(log_entry))
                    except Exception as e:  # noqa: BLE001
                        print(f"ERROR LOGGING CRITICAL ENTRY: {e}", file=sys.stderr)  # noqa: T201
                        print(f"LOG ENTRY: {log_entry}", file=sys.stderr)  # noqa: T201

            if not cls._log_queue:
                return
            logs_to_flush = cls._log_queue.copy()
            cls._log_queue = []
            cls._last_flush_time = time.monotonic()
            for log_entry in logs_to_flush:
                try:
                    if log_entry.get("_log_level") is not None:
                        log_level = log_entry.pop("_log_level")
                    else:
                        log_level = cls._determine_log_level(log_entry)

                    logger.log(log_level, json.dumps(log_entry))
                except Exception as e:  # noqa: BLE001
                    print(f"ERROR LOGGING ENTRY: {e}", file=sys.stderr)  # noqa: T201
                    print(f"LOG ENTRY: {log_entry}", file=sys.stderr)  # noqa: T201

    @classmethod
    def _determine_log_level(cls, log_entry: dict[str, Any]) -> int:
        """Determine the appropriate log level for an entry"""
        log_level = logging.INFO

        if not log_entry.get("success", True):
            log_level = logging.ERROR

        details = log_entry.get("details", {})
        if isinstance(details, dict):
            if "error" in details:
                log_level = logging.ERROR
            status_code = details.get("status_code", 0)
            if status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
                log_level = logging.ERROR
            if details.get("security_alert"):
                log_level = logging.CRITICAL

        if "anomalies" in log_entry:
            log_level = max(log_level, logging.WARNING)
            anomalies = log_entry["anomalies"]
            if (
                "volume_spike" in anomalies
                and anomalies["volume_spike"].get("ratio", 0) > 5  # noqa: PLR2004
            ):
                log_level = logging.CRITICAL

        return log_level

    @classmethod
    def log_token_event(  # noqa: C901, PLR0913
        cls,
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
        Queue a token event for batched logging
        """
        if not cls._initialized:
            cls.initialize()

        event_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": f"token_{event_type}",
            "user_id": user_id,
            "token_type": token_type,
            "jti": jti,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }

        event_data["sequence"] = {
            "timestamp_ns": time.time_ns(),
            "request_id": details.get("request_id") if details else str(uuid.uuid4()),
        }

        # Record metrics if duration is provided
        if duration_ms is not None:
            event_data["duration_ms"] = duration_ms
            TokenSecurityMetrics.record_operation(event_type, duration_ms, success)

            # Check for performance anomalies
            if token_type in TokenSecurityMetrics.operation_latencies:
                stats = TokenSecurityMetrics.operation_latencies[token_type]
                if stats["count"] > 10 and stats["total_ms"] > 0:  # noqa: PLR2004
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

        if details:
            event_data.update(details)

        is_critical = False
        if details and details.get("security_alert"):
            is_critical = True

        if (
            anomalies
            and "volume_spike" in anomalies
            and anomalies["volume_spike"].get("ratio", 0) > 5  # noqa: PLR2004
        ):
            is_critical = True

        background_tasks = set()
        if is_critical:
            cls._critical_queue.append(event_data)
            cls._trigger_security_alert(event_data)

            # Schedule immediate flush for critical events
            task = asyncio.create_task(cls._flush_logs())
            background_tasks.add(task)
            task.add_done_callback(background_tasks.discard)
        else:
            cls._log_queue.append(event_data)

            # Check if we should flush based on queue size or time
            if len(cls._log_queue) >= cls._max_batch_size:
                task = asyncio.create_task(cls._flush_logs())
                background_tasks.add(task)
                task.add_done_callback(background_tasks.discard)

    @classmethod
    def _trigger_security_alert(cls, event_data: dict[str, Any]):
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

        # Log critical alerts immediately (bypass batching)
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
        token_endpoints_io: dict[str, str] | None = None,
        token_endpoints_i: dict[str, str] | None = None,
        token_endpoints_o: dict[str, str] | None = None,
        excluded_paths: list[str] | None = None,
    ):
        """
        Initialize the middleware with token endpoints and excluded paths

        Args:
            app: FastAPI application
            token_endpoints_io: Dictionary endpoints wich expects token
            in Request and Response and their associated operations
            token_endpoints_i: Dictionary endpoints wich expects token
            only in Request and their associated operations
            token_endpoints_o: Dictionary endpoints wich expects token
            only in Response and their associated operations
            excluded_paths: List of paths to exclude from token monitoring
            which does not has token in Request or Response
        """
        super().__init__(app)
        self.token_endpoints_io = token_endpoints_io or {
            f"{st.API_VERSION_PREFIX}/auth/refresh": "refresh",
            f"{st.API_VERSION_PREFIX}/auth/sessions": "view_sessions",
        }
        self.token_endpoints_i = token_endpoints_i or {
            f"{st.API_VERSION_PREFIX}/auth/revoke": "revoke",
            f"{st.API_VERSION_PREFIX}/auth/verify": "verify",
            f"{st.API_VERSION_PREFIX}/auth/logout": "logout",
        }
        self.token_endpoints_o = token_endpoints_o or {
            f"{st.API_VERSION_PREFIX}/auth/token": "create",
        }

        self.exact_path_mapping = {
            path: event_type
            for path, event_type in dict(
                **self.token_endpoints_io,
                **self.token_endpoints_i,
                **self.token_endpoints_o,
            ).items()
            if not any(c in path for c in ".*?+()[]{}^$")
        }
        self.regex_patterns = {
            re.compile(pattern): event_type
            for pattern, event_type in dict(
                **self.token_endpoints_io,
                **self.token_endpoints_i,
                **self.token_endpoints_o,
            ).items()
            if any(c in pattern for c in ".*?+()[]{}^$")
        }

        # Excluded paths for faster skipping
        self.excluded_path_in_request = {
            path
            for path in self.token_endpoints_o
            if not any(c in path for c in ".*?+()[]{}^$")
        }
        self.excluded_regex_in_request = [
            re.compile(path)
            for path in self.token_endpoints_o
            if any(c in path for c in ".*?+()[]{}^$")
        ]

        self.excluded_path_in_response = {
            path
            for path in self.token_endpoints_i
            if not any(c in path for c in ".*?+()[]{}^$")
        }
        self.excluded_regex_in_response = [
            re.compile(path)
            for path in self.token_endpoints_i
            if any(c in path for c in ".*?+()[]{}^$")
        ]

        self.excluded_paths = set(
            excluded_paths
            or [
                f"{st.API_VERSION_PREFIX}/docs",
                f"{st.API_VERSION_PREFIX}/redoc",
                f"{st.API_VERSION_PREFIX}/openapi.json",
                f"{st.API_VERSION_PREFIX}/favicon.ico",
                f"{st.API_VERSION_PREFIX}/static/",
                f"{st.API_VERSION_PREFIX}/health",
                f"{st.API_VERSION_PREFIX}/metrics",
            ],
        )
        self.excluded_regex = [
            re.compile(path)
            for path in self.excluded_paths
            if any(c in path for c in ".*?+()[]{}^$")
        ]

    def create_initial_log_data(self) -> dict[str, Any]:
        """Create initial log data"""
        return {
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

    def _should_skip_path(self, path: str) -> bool:
        """Fast check if path should be skipped"""
        if path in self.excluded_paths:
            return True
        return any(pattern.match(path) for pattern in self.excluded_regex)

    def _should_skip_token_eval_in_request(self, path: str) -> bool:
        """Fast check if token evaluation should be skipped in Request"""
        if path in self.excluded_path_in_request:
            return True
        return any(pattern.match(path) for pattern in self.excluded_regex_in_request)

    def _should_skip_token_eval_in_response(self, path: str) -> bool:
        """Fast check if token evaluation should be skipped in Response"""
        if path in self.excluded_path_in_response:
            return True
        return any(pattern.match(path) for pattern in self.excluded_regex_in_response)

    def _get_event_type(self, path: str) -> str:
        """Determine the token event type based on the request path"""
        if path in self.exact_path_mapping:
            return self.exact_path_mapping[path]
        for pattern, event_type in self.regex_patterns.items():
            if pattern.match(path):
                return event_type
        return "unknown"

    async def _buffer_request_body(self, request: Request) -> tuple[bytes, Request]:
        """Buffer the request body for reuse"""
        body = await request.body()
        setattr(request, "_body", body)  # noqa: B010
        return body, request

    async def _extract_token_from_request(
        self,
        request: Request,
        log_data: dict[str, Any],
    ) -> tuple[str | None, Request]:
        """Extract token from request if possible"""
        token = None
        auth_header = request.headers.get("Authorization")
        if auth_header and " " in auth_header:
            _, token = auth_header.split(" ", 1)
            return token, request

        content_type = request.headers.get("Content-Type", "")

        # TODO: set what events are expected to have a token in the body
        # events that expects a token in the body
        if log_data["event_type"] in ["refresh", "verify"] and (
            "application/json" in content_type
            or "application/x-www-form-urlencoded" in content_type
        ):
            body_bytes, request = await self._buffer_request_body(request)

            if "application/json" in content_type:
                try:
                    body_json = json.loads(body_bytes)
                    token = body_json.get("token") or body_json.get("refresh_token")
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
                    token = form_data.get("token") or form_data.get("refresh_token")
                except Exception as e:  # noqa: BLE001
                    msg = f"Unnabled to extract token from request body: {e!s}"
                    logger.debug(msg)

        return token, request

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

    def _extract_token_info_from_response(
        self,
        response_data: Any,
        token_key: str,
        log_data: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        """Extract token information from response if possible"""
        try:
            if token_key == "token" and "token" in response_data:  # noqa: S105
                log_data["token_type"] = response_data["token_type"]
                log_data["jti"], log_data["user_id"] = (
                    self._extract_token_info_from_token(
                        response_data["token"],
                    )
                    if response_data["token"]
                    else ("unknown", "unknown")
                )
                return True, log_data

            if "token_type" in response_data[token_key]:
                log_data["token_type"] = response_data[token_key]["token_type"]

            if "token" not in response_data[token_key] or not isinstance(
                response_data[token_key]["token"],
                str,
            ):
                return False, log_data

            log_data["jti"], log_data["user_id"] = (
                self._extract_token_info_from_token(response_data[token_key]["token"])
                if response_data[token_key]["token"]
                else ("unknown", "unknown")
            )
        except json.JSONDecodeError as e:
            msg = f"Failed to decode response body as JSON: {e!s}"
            logger.debug(msg)
            return False, log_data
        except Exception as e:  # noqa: BLE001
            msg = f"Failed to extract token info from response: {e!s}"
            logger.debug(msg)
            return False, log_data
        return True, log_data

    def log_token_response(
        self,
        status_code: int,
        log_data: dict[str, Any],
        event_prefix: str,
        error_detail: str | None = None,
    ) -> None:
        # Create response details for logging
        response_details = {
            "operation": "complete" if log_data["success"] else "failed",
            "phase": "response",
            "request_id": log_data["request_id"],
            "status_code": status_code,
            "duration_ms": log_data["duration_ms"],
        }

        if not log_data["success"]:
            response_details["error"] = (
                error_detail if error_detail else "Unknown error"
            )
            if status_code >= status.HTTP_500_INTERNAL_SERVER_ERROR:
                response_details["stack_trace"] = traceback.format_exc()

        log_data["event_type"] = (
            event_prefix if log_data["success"] else f"{event_prefix}_error"
        )

        log_data["details"] = response_details

        TokenLogger.log_token_event(**log_data)

    async def _handle_request(
        self,
        request: Request,
        log_data: dict[str, Any],
        request_id: str,
        path: str,
        event_prefix: str,
    ) -> tuple[dict[str, Any], str, Request]:
        log_data["client_ip"] = request.client.host if request.client else None
        log_data["user_agent"] = request.headers.get("User-Agent", "unknown")

        if not self._should_skip_token_eval_in_request(path):
            token, request = await self._extract_token_from_request(request, log_data)
            log_data["jti"], log_data["user_id"] = (
                self._extract_token_info_from_token(token)
                if token
                else ("unknown", "unknown")
            )

        log_data["token_type"] = log_data["event_type"]
        if log_data["event_type"] != "unknown":
            event_prefix = log_data["event_type"]
        log_data["event_type"] = f"{event_prefix}_attempt"

        # Log request attempt
        log_data["details"] = {
            "operation": "start",
            "phase": "request",
            "request_id": request_id,
            "method": request.method,
            "path": path,
            "query_params": str(request.query_params),
        }

        TokenLogger.log_token_event(**log_data)

        return log_data, event_prefix, request

    async def _handle_response(  # noqa: PLR0913
        self,
        response: Response,
        start_time: float,
        path: str,
        event_prefix: str,
        log_data: dict[str, Any],
        error_detail: str | None,
    ) -> Response:
        """Handle response"""
        response_data = None

        if (
            not self._should_skip_token_eval_in_response(path)
            and response.status_code < status.HTTP_400_BAD_REQUEST
        ):
            try:
                response_body = response.body
                setattr(response, "_body", response_body)  # noqa: B010
                response_data = json.loads(response_body)
            except Exception as e:  # noqa: BLE001
                msg = f"Failed to parse response body: {e!s}"
                logger.debug(msg)

        if response.status_code >= status.HTTP_400_BAD_REQUEST:
            log_data["success"] = False
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

        log_data["duration_ms"] = round(
            (time.perf_counter() - start_time) * 1000,
        )

        if response_data is None:
            self.log_token_response(
                response.status_code,
                log_data,
                event_prefix,
                error_detail,
            )
        else:
            for token_key in [
                "access_token",
                "refresh_token",
                "limited_token",
                "token",
            ]:
                has_info, log_data = self._extract_token_info_from_response(
                    response_data,
                    token_key,
                    log_data,
                )
                if has_info:
                    self.log_token_response(
                        response.status_code,
                        log_data,
                        event_prefix,
                        error_detail,
                    )

        return response

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Skip non-token endpoints
        path = request.url.path
        if self._should_skip_path(path):
            return await call_next(request)

        log_data = self.create_initial_log_data()
        request_id = str(uuid.uuid4())
        event_prefix = "request"
        log_data["event_type"] = self._get_event_type(path)

        # event type was not set before
        if log_data["event_type"] == "unknown":
            return await call_next(request)

        log_data, event_prefix, request = await self._handle_request(
            request,
            log_data,
            request_id,
            path,
            event_prefix,
        )

        error_detail = None
        start_time = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as e:  # noqa: BLE001
            log_data["success"] = False
            error_detail = str(e)
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response = JSONResponse(
                content={"detail": "Internal server error"},
                status_code=status_code,
            )

        return await self._handle_response(
            response,
            start_time,
            path,
            event_prefix,
            log_data,
            error_detail,
        )
