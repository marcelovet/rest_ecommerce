from collections.abc import Callable
from datetime import UTC
from datetime import datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.exceptions import DatabaseError
from app.exceptions import DeleteError
from app.exceptions import UpdateError


class SoftDeleteMixin:
    _get_current_time: Callable[[], datetime] = datetime.now

    def _execute_transaction(
        self,
        db: Session,
        error_type: type[Exception],
    ) -> None:
        """
        Execute a database transaction with proper error handling.

        Args:
            db: Database session
            error_type: Type of error to raise for general exceptions
        """
        try:
            db.commit()
        except SQLAlchemyError as e:
            db.rollback()
            msg = f"Database error during operation: {e!s}"
            raise DatabaseError(msg)  # noqa: B904
        except Exception as e:  # noqa: BLE001
            db.rollback()
            msg = f"Error during operation: {e!s}"
            raise error_type(msg)  # noqa: B904

    def delete(self, db: Session) -> None:
        """Soft delete a user by marking as inactive and setting deletion timestamp."""

        self.deleted_at = self._get_current_time(UTC)  # type: ignore[call-arg]
        self.updated_at = self._get_current_time(UTC)  # type: ignore[call-arg]
        self.is_active = False

        self._execute_transaction(db, DeleteError)

    def restore(self, db: Session) -> None:
        """Restore a previously deleted user."""

        self.deleted_at = None
        self.updated_at = self._get_current_time(UTC)  # type: ignore[call-arg]
        self.is_active = True

        self._execute_transaction(db, UpdateError)
