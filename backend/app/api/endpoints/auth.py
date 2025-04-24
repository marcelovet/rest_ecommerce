from typing import Annotated

from fastapi import APIRouter
from fastapi import Form
from fastapi import HTTPException
from fastapi import status

from app.api.dependencies import auth_service_dependency
from app.models.request_models import RegisterForm
from app.models.response_models import ErrorResponse
from app.models.response_models import RegisterResponse

auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    response_model=RegisterResponse,
)
def register(
    form: Annotated[RegisterForm, Form()],
    auth_service: auth_service_dependency,
):
    """
    Register a new user.

    - **form**: Registration form data

    Returns:
        RegisterResponse: User data and authentication token

    Raises:
        HTTPException: If registration fails
    """
    register_result = auth_service.register_user(form)
    if not register_result["success"] and register_result.get(
        "user_already_exists",
        False,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=register_result["message"],
        )
    if not register_result["success"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=ErrorResponse.create_from_code(
                "INTERNAL_ERROR",
            ).detail,
        )
    return {
        "message": "Verification pending",
        "user": register_result["user"],
        "token": register_result["token"],
    }
