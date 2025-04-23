from pydantic import BaseModel
from pydantic import Field

from app.models.response_models.token import TokenData
from app.models.user.user_out import UserOut


class RegisterResponse(BaseModel):
    """Response model for successful registration."""

    message: str = Field(..., description="Success message")
    user: UserOut = Field(..., description="Registered user")
    token: TokenData = Field(..., description="Authentication token")
