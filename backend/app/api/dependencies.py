from typing import Annotated

from fastapi import Depends
from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
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

# for login (form data with username and password)
oauth2_pwd_access_dependency = Annotated[OAuth2PasswordRequestForm, Depends()]

# for access tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")
oauth2_token_dependency = Annotated[str, Depends(oauth2_scheme)]

# for tokens like password reset, email verification, etc.
base_auth_bearer = HTTPBearer(auto_error=False)


def get_token(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(base_auth_bearer),
    ],
) -> str:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


auth_bearer_dependency = Annotated[str, Depends(get_token)]
