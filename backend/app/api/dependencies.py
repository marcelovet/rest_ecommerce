from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db.session import Session as DbSession
from app.services.auth_service import AuthService


def get_db():
    db = DbSession()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


def get_auth_service(db: db_dependency) -> AuthService:
    """Dependency for getting the auth service with DB session."""
    return AuthService(db)


auth_service_dependency = Annotated[AuthService, Depends(get_auth_service)]
