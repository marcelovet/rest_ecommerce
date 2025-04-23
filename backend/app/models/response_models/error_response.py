from typing import Any
from typing import ClassVar

from pydantic import BaseModel
from pydantic import Field


class ErrorResponse(BaseModel):
    """
    Response model for standardized error responses.

    This model is used across the application to ensure consistent error
    responses in API endpoints. It includes a required detail message and
    optional error code and context information.

    Examples:
        >>> ErrorResponse(detail="Resource not found", code="NOT_FOUND")
        >>> ErrorResponse(detail="Validation error", code="VALIDATION_ERROR",
                         context={"field": "email", "issue": "invalid format"})
    """

    detail: str = Field(
        ...,
        description="Error detail message",
        min_length=1,
        max_length=500,
        examples=["Resource not found", "Validation failed", "Unauthorized access"],
    )
    code: str | None = Field(
        None,
        description="Error code for programmatic identification",
        pattern=r"^[A-Z][A-Z0-9_]*$",
        examples=["NOT_FOUND", "VALIDATION_ERROR", "UNAUTHORIZED"],
        exclude=True,
    )
    context: dict[str, Any] | None = Field(
        None,
        description="Additional context information about the error",
    )

    ERROR_CODES: ClassVar[dict[str, str]] = {
        "NOT_FOUND": "The requested resource was not found",
        "VALIDATION_ERROR": "Input validation failed",
        "UNAUTHORIZED": "Authentication is required",
        "FORBIDDEN": "You don't have permission to access this resource",
        "INTERNAL_ERROR": "An internal server error occurred",
    }

    @classmethod
    def create_from_code(cls, code: str, **context) -> "ErrorResponse":
        """
        Create an ErrorResponse using a predefined error code.

        Args:
            code: One of the predefined error codes
            context: Additional context to include in the error

        Returns:
            An ErrorResponse instance

        Raises:
            ValueError: If the error code is not recognized
        """
        if code not in cls.ERROR_CODES:
            msg = f"Unknown error code: {code}"
            raise ValueError(msg)

        return cls(
            detail=cls.ERROR_CODES[code],
            code=code,
            context=context or None,
        )
