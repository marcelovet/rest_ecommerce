from enum import Enum

from pydantic import BaseModel
from pydantic import Field


class RoleEnum(int, Enum):
    """Enum for user roles."""

    CUSTOMER = 0
    STAFF = 1
    INVENTORY_MANAGER = 2
    ORDER_PROCESSOR = 3
    STORE_MANAGER = 4
    ADMIN = 5


class UserOut(BaseModel):
    """
    Pydantic model for user output.

    Attributes:
        - id (int): User ID. This field is excluded from the output.
        - email (str): User email.
        - full_name (str): User full name.
        - is_active (bool): User active status. This field is excluded
        from the output.
        - is_verified (bool): User verification status. This field is excluded
        from the output.
        - role (RoleEnum): User role.
    """

    id: int = Field(..., exclude=True)
    email: str
    full_name: str
    is_active: bool = Field(..., exclude=True)
    is_verified: bool = Field(..., exclude=True)
    role: RoleEnum

    def is_authorized(self) -> bool:
        """
        Check if the user is authorized.

        Returns:
            bool: True if the user is active and verified, False otherwise.
        """
        return self.is_active and self.is_verified
