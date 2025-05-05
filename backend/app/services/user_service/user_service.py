from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.logging import logger
from app.exceptions import InsertError
from app.exceptions import SelectError
from app.exceptions import UserServiceError
from app.models.request_models import RegisterForm
from app.models.user import UserOut
from app.schemas.user import User


class UserService:
    def __init__(self, db: Session):
        self.db = db

    def get_user_by_email(self, email: str) -> UserOut | None:
        try:
            query = select(User).where(User.email == email)
            user = self.db.scalar(query)
        except SQLAlchemyError as e:
            logger.error(f"SelectError: {e!s}")
            raise SelectError(e)  # noqa: B904
        except Exception as e:  # noqa: BLE001
            logger.error(f"UserServiceError: {e!s}")
            raise UserServiceError(e)  # noqa: B904
        return user.user_out if user else None

    def create_user(self, form: RegisterForm, hashed_password: str) -> UserOut:
        try:
            user = User(
                email=form.email,
                hashed_password=hashed_password,
                full_name=form.full_name,
                is_active=True,
                is_verified=False,
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
        except SQLAlchemyError as e:
            logger.error(f"InsertError: {e!s}")
            raise InsertError(e)  # noqa: B904
        except Exception as e:  # noqa: BLE001
            logger.error(f"UserServiceError: {e!s}")
            raise UserServiceError(e)  # noqa: B904
        return user.user_out
