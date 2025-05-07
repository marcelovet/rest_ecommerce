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

    # TODO: change create_ methods to async since TokenRepository is async

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
        # TODO: Must return jwt and jti for token repository
        return jwt.encode(
            token_data,
            st.PRIVATE_KEY,
            algorithm=st.JWT_ALGORITHM,
        )

    def create_access_token(  # noqa: PLR0913
        self,
        user_id: str,
        scopes: list[str] | None = None,
        verified: bool = True,  # noqa: FBT001, FBT002
        issuer: str = st.BACKEND_URL,
        audience: list[str] = st.BACKEND_CORS_ORIGINS,
        role: RoleEnum = RoleEnum.CUSTOMER,
    ) -> AccessTokenData:
        """
        Create an access token data for a user with an access and a refresh token.

        Token's jti are generated and stored in the database for validation/revocation.

        This method is intended to create access/refresh tokens for users who have
        already been authenticated and verified.

        Args:
            user_id (str): The user ID
            scopes (list[str] | None): additional scopes for the token beyond the
            default
            verified (bool): Whether the user has email verified
            issuer (str): The issuer of the token
            audience (list[str]): The audience for the token
            role (RoleEnum): The role of the user

        Returns:
            AccessTokenData: pydantic model with access and refresh tokens
        """
        if scopes is None:
            scopes = []
        tk_data = {
            "subject": user_id,
            "verified": verified,
            "issuer": issuer,
            "audience": audience,
            "role": role,
        }
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
        # TODO: add jtis to token repository
        return AccessTokenData(
            access_token=access_token_model,
            refresh_token=refresh_token_model,
        )

    def create_limited_token(
        self,
        user_id: str,
        issuer: str = st.BACKEND_URL,
        audience: list[str] = st.BACKEND_CORS_ORIGINS,
        role: RoleEnum = RoleEnum.CUSTOMER,
    ) -> TokenData:
        """
        Create a limited access token data for a user.

        Token's jti are generated and stored in the database for validation/revocation.

        This method is intended to create limited access token for users who have
        created a new account, but have not yet verified their email, allowing them
        to have basic access to the application.

        Args:
            user_id (str): The user ID
            issuer (str): The issuer of the token
            audience (list[str]): The audience for the token
            role (RoleEnum): The role of the user

        Returns:
            TokenData: pydantic model with token and token type
        """
        tk_data = {
            "subject": user_id,
            "verified": False,
            "issuer": issuer,
            "audience": audience,
            "role": role,
        }
        limited_token = self.create_token(
            TokenType.LIMITED,
            **tk_data,
            expires_delta=timedelta(seconds=st.LIMITED_TOKEN_EXPIRE),
            scopes=[],
        )
        # TODO: add jtis to token repository
        return TokenData(
            token=limited_token,
            token_type=TokenTypeModel.ACCESS,
        )

    def create_email_verification_token(
        self,
        user_id: str,
        issuer: str = st.BACKEND_URL,
        audience: list[str] = st.BACKEND_CORS_ORIGINS,
        role: RoleEnum = RoleEnum.CUSTOMER,
    ) -> TokenData:
        """
        Create an email verification token data for a user.

        Token's jti are generated and stored in the database for validation/revocation.

        This method is intended to create limited access token for users who have
        created a new account, but have not yet verified their email, allowing them
        to verify their email.

        Args:
            user_id (str): The user ID
            issuer (str): The issuer of the token
            audience (list[str]): The audience for the token
            role (RoleEnum): The role of the user

        Returns:
            TokenData: pydantic model with token and token type
        """
        tk_data = {
            "subject": user_id,
            "verified": False,
            "issuer": issuer,
            "audience": audience,
            "role": role,
        }
        verification_token = self.create_token(
            TokenType.VERIFY,
            **tk_data,
            expires_delta=timedelta(seconds=st.VERIFICATION_TOKEN_EXPIRE),
            scopes=[],
        )
        # TODO: add jtis to token repository
        return TokenData(
            token=verification_token,
            token_type=TokenTypeModel.VERIFY,
        )

    def create_password_reset_token(
        self,
        user_id: str,
        verified: bool = True,  # noqa: FBT001, FBT002
        issuer: str = st.BACKEND_URL,
        audience: list[str] = st.BACKEND_CORS_ORIGINS,
        role: RoleEnum = RoleEnum.CUSTOMER,
    ) -> TokenData:
        """
        Create a password reset token data for a user.

        Token's jti are generated and stored in the database for validation/revocation.

        This method is intended to create password reset tokens for users who have
        already been verified, alllowing them to reset their password (e.g. users
        who have forgotten their password).

        Args:
            user_id (str): The user ID
            verified (bool): Whether the user has email verified
            issuer (str): The issuer of the token
            audience (list[str]): The audience for the token
            role (RoleEnum): The role of the user

        Returns:
            TokenData: pydantic model with token and token type
        """
        tk_data = {
            "subject": user_id,
            "verified": verified,
            "issuer": issuer,
            "audience": audience,
            "role": role,
        }
        pwd_reset_token = self.create_token(
            TokenType.PASSWORD_RESET,
            **tk_data,
            expires_delta=timedelta(seconds=st.RESET_PASSWORD_TOKEN_EXPIRE),
            scopes=[],
        )
        # TODO: add jtis to token repository
        return TokenData(
            token=pwd_reset_token,
            token_type=TokenTypeModel.PASSWORD_RESET,
        )

    def create_account_activation_token(
        self,
        user_id: str,
        verified: bool = True,  # noqa: FBT001, FBT002
        issuer: str = st.BACKEND_URL,
        audience: list[str] = st.BACKEND_CORS_ORIGINS,
        role: RoleEnum = RoleEnum.CUSTOMER,
    ) -> TokenData:
        """
        Create an account activation token data for a user.

        Token's jti are generated and stored in the database for validation/revocation.

        This method is intended to create account activation tokens for users who have
        already been authenticated, verified and deleted (inactivate) their account,
        allowing them to reactivate their account.

        Args:
            user_id (str): The user ID
            verified (bool): Whether the user has email verified
            issuer (str): The issuer of the token
            audience (list[str]): The audience for the token
            role (RoleEnum): The role of the user

        Returns:
            TokenData: pydantic model with token and token type
        """
        tk_data = {
            "subject": user_id,
            "verified": verified,
            "issuer": issuer,
            "audience": audience,
            "role": role,
        }
        activation_token = self.create_token(
            TokenType.ACTIVATE,
            **tk_data,
            expires_delta=timedelta(seconds=st.VERIFICATION_TOKEN_EXPIRE),
            scopes=[],
        )
        # TODO: add jtis to token repository
        return TokenData(
            token=activation_token,
            token_type=TokenTypeModel.ACTIVATE,
        )

    def fetch_scopes(self, scope: str) -> dict[str, Any]:
        """
        Fetches scopes from token
        """

        def scope_to_dict(scopes: list[str], target_scope: str) -> dict[str, str]:
            return {
                scope.replace(f"{target_scope}:", "").split(".")[0]: scope.replace(
                    f"{target_scope}:",
                    "",
                ).split(
                    ".",
                )[1]
                for scope in scopes
                if scope.startswith(f"{target_scope}:")
            }

        if not scope:
            return {}
        scopes = scope.split(" ")
        return {
            "token_scope": scopes[0],
            "read": scope_to_dict(scopes, "read"),
            "create": scope_to_dict(scopes, "create"),
            "update": scope_to_dict(scopes, "update"),
            "delete": scope_to_dict(scopes, "delete"),
        }
