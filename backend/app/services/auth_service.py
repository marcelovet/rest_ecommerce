import json
from datetime import UTC
from datetime import datetime
from datetime import timedelta

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.exceptions import UserAlreadyExistsError
from app.models.request_models import RegisterForm
from app.models.response_models import TokenData
from app.schemas.user import VerificationToken

from .tasks import send_verification_email
from .user_service import UserService

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.user_service = UserService(db)

    def validate_user_not_exists(self, email: str):
        user = self.user_service.get_user_by_email(email)
        if user:
            raise UserAlreadyExistsError

    def generate_verification_token(self, user_id: int) -> str:
        # TODO: implement the logic to generate a verification token
        return "CREATE A LOGIC"

    def generate_limited_token(self, user_id: int) -> TokenData:
        # TODO: implement the logic to generate a limited token
        return TokenData(access_token="", token_type="")

    def serialize_verification_email(self, email: str, token: str):
        json_data = {
            "email": email,
            "token": token,
        }
        return json.dumps(json_data)

    def register_user(self, form: RegisterForm) -> dict:
        """
        Register a new user with the provided form data.

        Args:
            form: The registration form data

        Returns:
            A dictionary containing registration result
        """
        # Original implementation logic here
        # For example:
        try:
            self.validate_user_not_exists(form.email)
            hashed_password = hash_password(form.password)
            user = self.user_service.create_user(form, hashed_password)
            verification_token = self.generate_verification_token(user.id)
            self.db.add(
                VerificationToken(
                    user_id=user.id,
                    token=verification_token,
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
            )
            self.db.commit()
            send_verification_email.delay(
                self.serialize_verification_email(form.email, verification_token),
            )  # type: ignore[call-arg]
            limited_token = self.generate_limited_token(user.id)
        except UserAlreadyExistsError:
            return {
                "success": False,
                "message": "User already exists",
                "user_already_exists": True,
            }
        except Exception as e:
            return {
                "success": False,
                "message": str(e),
            }
        return {
            "success": True,
            "user": user,
            "token": limited_token,
            "message": "User registered successfully",
        }
