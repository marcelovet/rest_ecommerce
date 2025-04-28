import re
from enum import Enum

import pytest
from pydantic import ValidationError

from app.models.response_models.token_response import AccessTokenData
from app.models.response_models.token_response import TokenData
from app.models.response_models.token_response import TokenType


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
def token_data_instance(valid_jwt_token):
    """Fixture providing a valid TokenData instance."""
    return TokenData(token=valid_jwt_token, token_type=TokenType.ACCESS)


@pytest.fixture
def access_token_data_instance(token_data_instance):
    """Fixture providing a valid AccessTokenData instance."""
    return AccessTokenData(
        access_token=token_data_instance,
        refresh_token=TokenData(
            token=token_data_instance.token,
            token_type=TokenType.REFRESH,
        ),
    )


class TestTokenType:
    """Test suite for the TokenType enum."""

    def test_token_type_values(self):
        """Test that TokenType enum has the expected values."""
        assert TokenType.ACCESS == "bearer"
        assert TokenType.REFRESH == "refresh"
        assert TokenType.VERIFY == "verify"
        assert TokenType.RESET == "reset"
        assert TokenType.ACTIVATION == "activation"

    def test_token_type_is_enum(self):
        """Test that TokenType is an Enum."""
        assert issubclass(TokenType, Enum)
        assert issubclass(TokenType, str)


class TestTokenData:
    """Test suite for the TokenData Pydantic model."""

    def test_create_token_data_with_all_fields(self, valid_jwt_token):
        """Test creating TokenData with all fields specified."""
        token_data = TokenData(token=valid_jwt_token, token_type="bearer")  # type: ignore[call-arg] # noqa: S106

        assert token_data.token == valid_jwt_token
        assert token_data.token_type == "bearer"  # noqa: S105

    def test_create_token_data_with_required_fields_only(self, valid_jwt_token):
        """Test creating TokenData with only required fields."""
        token_data = TokenData(token=valid_jwt_token)

        assert token_data.token == valid_jwt_token
        assert (
            token_data.token_type == "bearer"  # noqa: S105
        )  # Default value should be used

    def test_token_data_missing_token(self):
        """Test that ValidationError is raised when token is missing."""
        with pytest.raises(ValidationError) as exc_info:
            TokenData()  # type: ignore[call-arg]

        # Verify the error is about the missing token
        error_details = exc_info.value.errors()
        assert any(
            error["type"] == "missing" and "token" in error["loc"]
            for error in error_details
        )

    def test_token_data_invalid_types(self, valid_jwt_token):
        """Test that ValidationError is raised when field types are invalid."""
        # Test invalid token type
        with pytest.raises(ValidationError) as exc_info:
            TokenData(token=123)  # type: ignore[arg] # Should be string

        error_details = exc_info.value.errors()
        assert any(
            error["type"] == "string_type" and "token" in error["loc"]
            for error in error_details
        )

        # Test invalid token_type
        with pytest.raises(ValidationError) as exc_info:
            TokenData(token=valid_jwt_token, token_type=123)  # type: ignore[call-arg] # Should be string

        error_details = exc_info.value.errors()
        assert any(
            error["type"] == "enum" and "token_type" in error["loc"]
            for error in error_details
        )

    def test_token_data_schema(self):
        """Test that the schema contains the correct field descriptions."""
        schema = TokenData.model_json_schema()

        # Check field descriptions
        properties = schema.get("properties", {})
        assert "token" in properties
        assert properties["token"].get("description") == "JWT access token"

        assert "token_type" in properties
        assert properties["token_type"].get("description") == "Token type"
        assert properties["token_type"].get("default") == "bearer"

    def test_token_data_dict_conversion(self, token_data_instance):
        """Test converting TokenData to dictionary."""
        data_dict = token_data_instance.model_dump()

        assert data_dict == {
            "token": token_data_instance.token,
            "token_type": "bearer",
        }

    def test_all_invalid_jwt_formats(self, invalid_jwt_tokens):
        """Test validation against all invalid JWT formats."""
        for invalid_jwt in invalid_jwt_tokens:
            with pytest.raises(ValueError) as exc_info:  # noqa: PT011
                TokenData(token=invalid_jwt)

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


class TestAccessTokenData:
    """Test suite for the AccessTokenData Pydantic model."""

    def test_create_access_token_data(self, token_data_instance):
        """Test creating AccessTokenData with valid token data instances."""
        refresh_token = TokenData(
            token=token_data_instance.token,
            token_type=TokenType.REFRESH,
        )

        access_token_data = AccessTokenData(
            access_token=token_data_instance,
            refresh_token=refresh_token,
        )

        assert access_token_data.access_token == token_data_instance
        assert access_token_data.refresh_token == refresh_token
        assert access_token_data.access_token.token_type == TokenType.ACCESS
        assert access_token_data.refresh_token.token_type == TokenType.REFRESH

    def test_access_token_data_dict_conversion(self, access_token_data_instance):
        """Test converting AccessTokenData to dictionary."""
        data_dict = access_token_data_instance.model_dump()

        assert "access_token" in data_dict
        assert "refresh_token" in data_dict
        assert data_dict["access_token"]["token_type"] == "bearer"
        assert data_dict["refresh_token"]["token_type"] == "refresh"

    def test_access_token_data_missing_fields(self, token_data_instance):
        """Test that ValidationError is raised when required fields are missing."""
        # Missing access_token
        with pytest.raises(ValidationError) as exc_info:
            AccessTokenData(refresh_token=token_data_instance)  # type: ignore[call-arg]

        error_details = exc_info.value.errors()
        assert any(
            error["type"] == "missing" and "access_token" in error["loc"]
            for error in error_details
        )

        # Missing refresh_token
        with pytest.raises(ValidationError) as exc_info:
            AccessTokenData(access_token=token_data_instance)  # type: ignore[call-arg]

        error_details = exc_info.value.errors()
        assert any(
            error["type"] == "missing" and "refresh_token" in error["loc"]
            for error in error_details
        )

    def test_access_token_data_invalid_types(
        self,
        token_data_instance,
    ):
        """Test that ValidationError is raised when field types are invalid."""
        # Invalid access_token type
        with pytest.raises(ValidationError):
            AccessTokenData(
                access_token="not_a_token_data",  # type: ignore[arg]
                refresh_token=token_data_instance,
            )

        # Invalid refresh_token type
        with pytest.raises(ValidationError):
            AccessTokenData(
                access_token=token_data_instance,
                refresh_token="not_a_token_data",  # type: ignore[arg]
            )
