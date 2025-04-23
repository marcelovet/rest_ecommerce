from sqlalchemy.orm import Session

from app.models.request_models import RegisterForm
from app.models.user.user_out import UserOut


class UserService:
    def __init__(self, db: Session):
        self.db = db

    def get_user_by_email(self, email: str):
        return "CREATE A LOGIC"

    def create_user(self, form: RegisterForm, hashed_password: str) -> UserOut:
        # TODO: implement the logic to create a user

        return UserOut(
            id=1,
            email="test@test.com",
            full_name="test",
            is_active=True,
            is_verified=True,
            role=1,
        )
