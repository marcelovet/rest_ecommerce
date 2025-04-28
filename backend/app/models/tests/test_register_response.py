import pytest
from pydantic import ValidationError

from app.models.response_models.register_response import RegisterResponse
from app.models.response_models.token_response import TokenData
from app.models.user.user_out import UserOut


@pytest.fixture
def valid_user_data():
    """Fixture for valid UserOut data."""
    return UserOut(
        id=2,
        email="test@example.com",
        full_name="testuser",
        is_active=True,
        is_verified=True,
        role=1,  # type: ignore[arg-type]
    )


@pytest.fixture
def valid_token_data(valid_jwt_token):
    """Fixture for valid TokenData."""
    return TokenData(
        token=valid_jwt_token,
        token_type="bearer",  # noqa: S106 # type: ignore[call-arg]
    )


@pytest.fixture
def valid_register_response(valid_user_data, valid_token_data):
    """Fixture for a valid RegisterResponse."""
    return RegisterResponse(
        message="User registered successfully",
        user=valid_user_data,
        token=valid_token_data,
    )


class TestRegisterResponse:
    """Tests for the RegisterResponse model."""

    def test_register_response_valid_data(self, valid_user_data, valid_token_data):
        """Test that RegisterResponse can be initialized with valid data."""
        # Act
        response = RegisterResponse(
            message="User registered successfully",
            user=valid_user_data,
            token=valid_token_data,
        )

        # Assert
        assert response.message == "User registered successfully"
        assert response.user == valid_user_data
        assert response.token == valid_token_data

    def test_register_response_missing_fields(self):
        """Test that RegisterResponse raises error when required fields are missing."""
        # Act & Assert
        with pytest.raises(ValidationError) as exc_info:
            RegisterResponse()  # type: ignore[call-arg]

        errors = exc_info.value.errors()
        error_fields = [error["loc"][0] for error in errors]

        assert "message" in error_fields
        assert "user" in error_fields
        assert "token" in error_fields

    def test_register_response_invalid_types(self, valid_user_data, valid_token_data):
        """Test that RegisterResponse validates field types."""
        # Act & Assert
        with pytest.raises(ValidationError):
            RegisterResponse(
                message=123,  # Should be a string # type: ignore[arg-type]
                user=valid_user_data,
                token=valid_token_data,
            )

        with pytest.raises(ValidationError):
            RegisterResponse(
                message="User registered successfully",
                user="not_a_user_object",  # Should be UserOut # type: ignore[arg-type]
                token=valid_token_data,
            )

        with pytest.raises(ValidationError):
            RegisterResponse(
                message="User registered successfully",
                user=valid_user_data,
                token="not_a_token_object",  # Should be TokenData # type: ignore[arg-type]  # noqa: S106
            )

    def test_register_response_schema(self):
        """Test that RegisterResponse schema is correctly defined."""
        # Act
        schema = RegisterResponse.model_json_schema()

        # Assert
        assert schema["title"] == "RegisterResponse"
        assert schema["description"] == "Response model for successful registration."
        assert "message" in schema["properties"]
        assert "user" in schema["properties"]
        assert "token" in schema["properties"]
        assert schema["properties"]["message"]["description"] == "Success message"
        assert schema["properties"]["user"]["description"] == "Registered user"
        assert schema["properties"]["token"]["description"] == "Authentication token"
        assert set(schema["required"]) == {"message", "user", "token"}

    def test_register_response_serialization(
        self,
        valid_register_response,
        valid_jwt_token,
    ):
        """Test that RegisterResponse can be serialized to JSON."""
        # Act
        json_data = valid_register_response.model_dump_json()

        # Assert
        assert isinstance(json_data, str)
        assert "User registered successfully" in json_data
        assert "test@example.com" in json_data
        assert valid_jwt_token in json_data
