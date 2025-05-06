import hashlib
import secrets
import time
import uuid
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import Any

from app.core.config import settings
from app.models.token import TokenModel
from app.models.token import TokenType
from app.models.user import RoleEnum


class TokenFactory:
    """
    Factory class for creating tokens
    """

    registry: dict[str, Any] = {}

    @classmethod
    def register_token_type(
        cls,
        token_type: TokenType,
        base_scopes: list[str],
    ) -> None:
        """
        Registers a new Token type with its basic scopes.

        Args:
            token_type: Enum value indicating token type
            base_scopes: list of scopes to be included in the token

        Side Effects:
            - Adds token type configuration to registry
        """
        cls.registry[token_type.value] = {
            "base_scopes": base_scopes,
            "type": token_type.value,
        }

    def __init__(self, token_type: TokenType) -> None:
        """
        Initializes factory for specified token type.

        Args:
            token_type: Type of token to create

        Raises:
            ValueError: If token type not registered

        Side Effects:
            - Sets token configuration for instance
        """
        if not isinstance(token_type, TokenType):
            msg = "Invalid token type"
            raise ValueError(msg)  # noqa: TRY004
        tk_base = self.registry.get(token_type.value, {})
        if not tk_base:
            msg = f"Token type {token_type.value} is not registered"
            raise ValueError(msg)
        self.tk_base = tk_base

    def create_jti(self, prefix: str, user_id: str) -> str:
        """
        Generate a cryptographically secure JTI for the token.
        Format: {prefix}-{timestamp}-{randomness}-{user_component}-{hash}
        """
        timestamp = hex(int(time.time()))[2:]
        random_part = secrets.token_hex(8)
        unique_id = str(uuid.uuid4())

        user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:8]
        user_component = f"-{user_hash}"

        return f"{prefix}-{timestamp}-{random_part}{user_component}-{unique_id}"

    def __call__(  # noqa: PLR0913
        self,
        subject: str,
        scopes: list[str],
        verified: bool = False,  # noqa: FBT001, FBT002
        expires_delta: timedelta | None = None,
        issuer: str = settings.DOMAIN,
        audience: list[str] = settings.BACKEND_CORS_ORIGINS,
        role: RoleEnum = RoleEnum.CUSTOMER,
    ) -> dict[str, Any]:
        expires_delta = expires_delta or timedelta(days=1)

        # Calculate timestamps
        now = datetime.now(UTC)
        expire = now + expires_delta

        base_scopes = self.tk_base["base_scopes"]
        final_scope = base_scopes + scopes
        jti = self.create_jti(self.tk_base["type"], subject)

        return TokenModel(
            iss=issuer,
            sub=subject,
            exp=expire,
            iat=now,
            nbf=now,
            aud=audience,
            scope=" ".join(final_scope),
            verified=verified,
            role=role,
            jti=jti,
        ).model_dump()


# for limited access token
BASE_CUSTOMER_SCOPES = [
    "read:users.self",
    "update:users.self",
    "read:products.available",
    "read:carts.self",
    "update:carts.self",
    "create:carts.self",
    "delete:carts.self",
]
# for access token
EXTENDED_CUSTOMER_SCOPES = [
    "delete:users.self",
    "read:orders.self",
    "create:orders.self",
    "delete:orders.self",
    "read:payments.self",
    "create:payments.self",
    "read:reviews.available",
    "create:reviews.self",
    "update:reviews.self",
    "delete:reviews.self",
]
# TODO: create scopes for other roles

TokenFactory.register_token_type(
    TokenType.ACCESS,
    ["access", *BASE_CUSTOMER_SCOPES, *EXTENDED_CUSTOMER_SCOPES],
)

TokenFactory.register_token_type(
    TokenType.LIMITED,
    ["verification:status", *BASE_CUSTOMER_SCOPES],
)

TokenFactory.register_token_type(
    TokenType.VERIFY,
    ["verification:email"],
)

TokenFactory.register_token_type(
    TokenType.PASSWORD_RESET,
    ["reset:password"],
)

TokenFactory.register_token_type(
    TokenType.REFRESH,
    ["refresh:token"],
)
