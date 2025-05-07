from datetime import datetime
from enum import Enum

from pydantic import BaseModel

from app.models.user import RoleEnum


class TokenType(str, Enum):
    """
    Define token types for use in JWT claims
    """

    ACCESS = "tk"
    LIMITED = "lt"
    REFRESH = "rt"
    VERIFY = "vt"
    PASSWORD_RESET = "pt"  # noqa: S105
    ACTIVATE = "ac"


class TokenModel(BaseModel):
    """
    Define token model for use in JWT claims
    """

    iss: str
    sub: str
    exp: datetime
    iat: datetime
    nbf: datetime
    aud: list[str]
    scope: str
    verified: bool
    role: RoleEnum
    jti: str
