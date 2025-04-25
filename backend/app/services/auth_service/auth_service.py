import json
import time
import uuid
from datetime import UTC
from datetime import datetime
from datetime import timedelta

from jose import jwt
from passlib.context import CryptContext
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import logger
from app.exceptions import AuthServiceError
from app.exceptions import DatabaseError
from app.exceptions import InsertError
from app.exceptions import UserAlreadyExistsError
from app.exceptions import UserServiceError
from app.models.request_models import RegisterForm
from app.models.response_models import TokenData
from app.models.user import UserOut
from app.schemas.user import VerificationToken
from app.services.tasks import send_verification_email
from app.services.user_service import UserService

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.user_service = UserService(db)

    def validate_user_not_exists(self, email: str) -> None:
        """Validate if the user already exists."""
        user = self.user_service.get_user_by_email(email)
        if user is not None:
            raise UserAlreadyExistsError

    def generate_jti(self, prefix: str = "tk") -> str:
        """
        Generate a unique JWT ID with an optional prefix.
        Format: {prefix}-{uuid4}

        Prefixes can identify token types:
        - tk: Standard access token
        - rt: Refresh token
        - vt: Verification token
        - pt: Password reset token
        - lt: Limited access token
        """
        unique_id = str(uuid.uuid4())
        timestamp = hex(int(time.time()))[2:]  # Remove '0x' prefix
        return f"{prefix}-{timestamp}-{unique_id}"

    def create_verification_token(self, user_id: int) -> str:
        """
        Creates a JWT account verication token using RS256
        """
        to_encode = {
            "iss": settings.DOMAIN,
            "sub": f"user:{user_id}",
            "exp": datetime.now(UTC)
            + timedelta(days=settings.VERIFICATION_TOKEN_EXPIRE_DAYS),
            "iat": datetime.now(UTC),
            "nbf": datetime.now(UTC),
            "aud": settings.BACKEND_CORS_ORIGINS,
            "scope": "verification:email",
            "email": "user@example.com",
            "jti": self.generate_jti("vt"),
        }
        return jwt.encode(
            to_encode,
            settings.PRIVATE_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )

    def create_limited_token(self, user_id: int) -> TokenData:
        # TODO: implement the logic to generate a limited token
        return TokenData(access_token="", token_type="")

    def decode_token(self, token):
        payload = jwt.decode(
            token,
            settings.PUBLIC_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

    def serialize_verification_email(self, email: str, token: str):
        json_data = {
            "email": email,
            "token": token,
        }
        return json.dumps(json_data)

    def insert_verification_token(self, user: UserOut, verification_token: str):
        try:
            self.db.add(
                VerificationToken(
                    user_id=user.id,
                    token=verification_token,
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
            )
            self.db.commit()
        except SQLAlchemyError as e:
            logger.error(f"InsertError: {e!s}")
            raise InsertError(e)  # noqa: B904
        except Exception as e:  # noqa: BLE001
            logger.error(f"AuthServiceError: {e!s}")
            raise AuthServiceError(e)  # noqa: B904

    def register_user(self, form: RegisterForm) -> dict:
        """
        Register a new user with the provided form data.

        Args:
            form: The registration form data

        Returns:
            A dictionary containing registration result
        """
        try:
            self.validate_user_not_exists(form.email)
            user = self.user_service.create_user(form, hash_password(form.password))
            verification_token = self.create_verification_token(user.id)
            self.insert_verification_token(user, verification_token)
            send_verification_email.delay(
                self.serialize_verification_email(form.email, verification_token),
            )  # type: ignore[call-arg]
            limited_token = self.create_limited_token(user.id)
        except UserAlreadyExistsError:
            return {
                "success": False,
                "message": "User already exists",
                "user_already_exists": True,
            }
        except (DatabaseError, UserServiceError, AuthServiceError):
            return {
                "success": False,
            }
        except Exception as e:  # noqa: BLE001
            logger.error(f"AuthServiceError: {e!s}")
            return {
                "success": False,
            }
        return {
            "success": True,
            "user": user,
            "token": limited_token,
            "message": "User registered successfully",
        }
