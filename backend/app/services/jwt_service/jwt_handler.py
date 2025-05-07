from datetime import timedelta
from typing import Any

import jwt
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import settings as st
from app.exceptions import TokenRevokedError
from app.models.response_models import AccessTokenData
from app.models.response_models import TokenData
from app.models.response_models import TokenType as TokenTypeModel
from app.models.token import TokenType
from app.models.user import RoleEnum
from app.services.jwt_service.token_factory import TokenFactory
from app.services.jwt_service.token_repository import TokenRepository

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class JWTHandler:
    """
    JWTHandler is a class that provides methods for handling JWT tokens.
    """

    async def verify_token(self, token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
        """
        Verify token validity and check if it has been revoked
        """
        try:
            payload = jwt.decode(
                token,
                st.PUBLIC_KEY,
                algorithms=[st.JWT_ALGORITHM],
                audience=st.BACKEND_CORS_ORIGINS,
                issuer=st.BACKEND_URL,
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
                detail="Invalid token signature",
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

    def create_token(
        self,
        token_type: TokenType,
        **kwargs: Any,
    ) -> str:
        """
        Create a JWT with appropriate claims including a unique jti
        """
        token_factory = TokenFactory(token_type)
        token_data = token_factory(**kwargs)
        print(token_data)
        return jwt.encode(
            token_data,
            st.PRIVATE_KEY,
            algorithm=st.JWT_ALGORITHM,
        )

    def create_access_token(  # noqa: PLR0913
        self,
        user_id: str,
        scopes: list[str],
        verified: bool = True,  # noqa: FBT001, FBT002
        issuer: str = st.BACKEND_URL,
        audience: list[str] = st.BACKEND_CORS_ORIGINS,
        role: RoleEnum = RoleEnum.CUSTOMER,
    ):
        # base token data for factory
        tk_data = {
            "subject": user_id,
            "verified": verified,
            "issuer": issuer,
            "audience": audience,
            "role": role,
        }
        # create refresh token
        refresh_token = self.create_token(
            TokenType.REFRESH,
            **tk_data,
            expires_delta=timedelta(seconds=st.REFRESH_TOKEN_EXPIRE),
            scopes=[],
        )
        refresh_token_model = TokenData(
            token=refresh_token,
            token_type=TokenTypeModel.REFRESH,
        )
        # create access token
        access_token = self.create_token(
            TokenType.ACCESS,
            **tk_data,
            expires_delta=timedelta(seconds=st.ACCESS_TOKEN_EXPIRE),
            scopes=scopes,
        )
        access_token_model = TokenData(
            token=access_token,
            token_type=TokenTypeModel.ACCESS,
        )
        return AccessTokenData(
            access_token=access_token_model,
            refresh_token=refresh_token_model,
        )
