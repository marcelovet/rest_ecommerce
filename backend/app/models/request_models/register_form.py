from datetime import UTC
from datetime import date
from datetime import datetime
from datetime import timedelta
from enum import Enum
from typing import Annotated

from pydantic import BaseModel
from pydantic import EmailStr
from pydantic import Field
from pydantic import field_validator
from pydantic_extra_types.phone_numbers import PhoneNumber
from pydantic_extra_types.phone_numbers import PhoneNumberValidator

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 64


class Gender(str, Enum):
    male = "male"
    female = "female"
    other = "other"
    prefer_not_to_say = "prefer not to say"


# Error message constants
class ErrorMessages:
    PASSWORD_TOO_SHORT = "Password must be at least 8 characters"  # noqa: S105
    PASSWORD_TOO_LONG = "Password must be less than 64 characters"  # noqa: S105
    PASSWORD_NO_LOWERCASE = "Password must contain a lowercase letter"  # noqa: S105
    PASSWORD_NO_UPPERCASE = "Password must contain an uppercase letter"  # noqa: S105
    PASSWORD_NO_DIGIT = "Password must contain a digit"  # noqa: S105
    PASSWORD_NO_SPECIAL = "Password must contain a special character (@$!%*?&#)"  # noqa: S105
    BIRTH_DATE_FUTURE = "Birth date must be in the past"
    BIRTH_DATE_UNREALISTIC = "There is a problem with the birth date"


def validate_password(password: str) -> str:
    """Validate password according to security rules."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(ErrorMessages.PASSWORD_TOO_SHORT)
    if len(password) > PASSWORD_MAX_LENGTH:
        raise ValueError(ErrorMessages.PASSWORD_TOO_LONG)
    if not any(c.islower() for c in password):
        raise ValueError(ErrorMessages.PASSWORD_NO_LOWERCASE)
    if not any(c.isupper() for c in password):
        raise ValueError(ErrorMessages.PASSWORD_NO_UPPERCASE)
    if not any(c.isdigit() for c in password):
        raise ValueError(ErrorMessages.PASSWORD_NO_DIGIT)
    if not any(c in "@$!%*?&#" for c in password):
        raise ValueError(ErrorMessages.PASSWORD_NO_SPECIAL)
    return password


def validate_birth_date(birth_date: date) -> date:
    """Validate birth date is in the past and realistic."""
    if birth_date > datetime.now(UTC).date():
        raise ValueError(ErrorMessages.BIRTH_DATE_FUTURE)
    if birth_date.year <= (datetime.now(UTC).date() - timedelta(days=365 * 200)).year:
        raise ValueError(ErrorMessages.BIRTH_DATE_UNREALISTIC)
    return birth_date


class RegisterForm(BaseModel):
    email: EmailStr = Field(..., description="Email address")
    password: str
    full_name: str = Field(..., description="Full name", max_length=300, min_length=3)
    phone: Annotated[
        str | PhoneNumber,
        PhoneNumberValidator(
            number_format="NATIONAL",
            supported_regions=["BR"],
            default_region="BR",
        ),
    ] = Field(..., description="Phone number", examples=["(11) 99999-9999"])
    birth_date: date = Field(..., description="Date of birth")
    gender: Gender = Field(..., description="Gender")

    @field_validator("password")
    def validate_password(cls, v):  # noqa: N805
        return validate_password(v)

    @field_validator("birth_date")
    def validate_birth_date(cls, v):  # noqa: N805
        return validate_birth_date(v)
