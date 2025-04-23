from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

TOKEN_SEGMENTS = 3


class TokenData(BaseModel):
    """Response model for token data."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")

    @field_validator("access_token")
    @classmethod
    def validate_jwt_format(cls, value):
        """Validate that the access token follows JWT format."""
        segments = value.split(".")

        # Check for three segments
        if len(segments) != TOKEN_SEGMENTS:
            msg = f"Invalid JWT format: expected 3 segments, got {len(segments)}"
            raise ValueError(msg)

        # Check that no segment is empty
        if any(len(segment) == 0 for segment in segments):
            msg = "Invalid JWT format: contains empty segments"
            raise ValueError(msg)

        # Check for valid characters in each segment
        valid_chars = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        )
        for i, segment in enumerate(segments):
            if not all(c in valid_chars for c in segment):
                msg = f"Invalid JWT format: segment {i + 1} contains invalid characters"
                raise ValueError(msg)

        return value
