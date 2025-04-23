import re

import pytest
from pydantic import ValidationError

from app.models.response_models import TokenData


@pytest.fixture
def invalid_jwt_tokens():
    """Fixture providing a list of invalid JWT token formats."""
    return [
        "not-a-jwt",  # No dots
        "header.payload",  # Only two segments
        "header..signature",  # Empty middle segment
        "header.payload.signature.extra",  # Too many segments
        "header#payload#signature",  # Wrong separators
        "he@der.payload.signature",  # Invalid characters
        ".payload.signature",  # Empty header
        "header..signature",  # Empty payload
        "header.payload.",  # Empty signature
    ]


@pytest.fixture
def custom_token_type_instance(valid_jwt_token):
    """Fixture providing a TokenData instance with custom token type."""
    return TokenData(access_token=valid_jwt_token, token_type="custom_type")  # noqa: S106


class TestTokenData:
    """Test suite for the TokenData Pydantic model."""

    def test_create_token_data_with_all_fields(self, valid_jwt_token):
        """Test creating TokenData with all fields specified."""
        token_data = TokenData(access_token=valid_jwt_token, token_type="custom")  # noqa: S106

        assert token_data.access_token == valid_jwt_token
        assert token_data.token_type == "custom"  # noqa: S105

    def test_create_token_data_with_required_fields_only(self, valid_jwt_token):
        """Test creating TokenData with only required fields."""
        token_data = TokenData(access_token=valid_jwt_token)

        assert token_data.access_token == valid_jwt_token
        assert (
            token_data.token_type == "bearer"  # noqa: S105
        )  # Default value should be used

    def test_token_data_missing_access_token(self):
        """Test that ValidationError is raised when access_token is missing."""
        with pytest.raises(ValidationError) as exc_info:
            TokenData()  # type: ignore[call-arg]

        # Verify the error is about the missing access_token
        error_details = exc_info.value.errors()
        assert any(
            error["type"] == "missing" and "access_token" in error["loc"]
            for error in error_details
        )

    def test_token_data_invalid_types(self, valid_jwt_token):
        """Test that ValidationError is raised when field types are invalid."""
        # Test invalid access_token type
        with pytest.raises(ValidationError) as exc_info:
            TokenData(access_token=123)  # type: ignore[arg] # Should be string

        error_details = exc_info.value.errors()
        assert any(
            error["type"] == "string_type" and "access_token" in error["loc"]
            for error in error_details
        )

        # Test invalid token_type
        with pytest.raises(ValidationError) as exc_info:
            TokenData(access_token=valid_jwt_token, token_type=123)  # type: ignore[call-arg] # Should be string

        error_details = exc_info.value.errors()
        assert any(
            error["type"] == "string_type" and "token_type" in error["loc"]
            for error in error_details
        )

    def test_token_data_schema(self):
        """Test that the schema contains the correct field descriptions."""
        schema = TokenData.model_json_schema()

        # Check field descriptions
        properties = schema.get("properties", {})
        assert "access_token" in properties
        assert properties["access_token"].get("description") == "JWT access token"

        assert "token_type" in properties
        assert properties["token_type"].get("description") == "Token type"
        assert properties["token_type"].get("default") == "bearer"

    def test_token_data_dict_conversion(self, token_data_instance):
        """Test converting TokenData to dictionary."""
        data_dict = token_data_instance.model_dump()

        assert data_dict == {
            "access_token": token_data_instance.access_token,
            "token_type": "bearer",
        }

    def test_custom_token_type(self, custom_token_type_instance):
        """Test TokenData with custom token type."""
        assert custom_token_type_instance.token_type == "custom_type"  # noqa: S105
        assert custom_token_type_instance.access_token is not None

    def test_all_invalid_jwt_formats(self, invalid_jwt_tokens):
        """Test validation against all invalid JWT formats."""
        for invalid_jwt in invalid_jwt_tokens:
            with pytest.raises(ValueError) as exc_info:  # noqa: PT011
                TokenData(access_token=invalid_jwt)

            # Check that the error message contains our custom message
            error_message = str(exc_info.value)
            assert "Invalid JWT format" in error_message, (
                f"Failed to validate format: {invalid_jwt}, got error: {error_message}"
            )

    def test_jwt_pattern_matches_valid_token(self, valid_jwt_token):
        """Test that our JWT regex pattern correctly matches valid tokens."""
        jwt_pattern = r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$"
        assert re.match(jwt_pattern, valid_jwt_token), (
            "Valid JWT token should match the pattern"
        )
