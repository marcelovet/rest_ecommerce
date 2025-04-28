import uuid
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from enum import Enum

import pytest

from app.models.token import TokenModel
from app.models.token import TokenType
from app.models.user import RoleEnum


class TestTokenType:
    """Tests for the TokenType enum"""

    def test_token_type_values(self):
        """Test that TokenType enum has the expected values"""
        assert TokenType.ACCESS == "tk"
        assert TokenType.LIMITED == "lt"
        assert TokenType.VERIFY == "vt"
        assert TokenType.PASSWORD_RESET == "pt"  # noqa: S105
        assert TokenType.REFRESH == "rt"
        assert TokenType.ACTIVATE == "ac"

    def test_token_type_is_enum(self):
        """Test that TokenType is an Enum"""
        assert issubclass(TokenType, Enum)
        assert issubclass(TokenType, str)

    def test_token_type_members(self):
        """Test that TokenType has the expected members"""
        expected_members = {
            "ACCESS",
            "LIMITED",
            "VERIFY",
            "PASSWORD_RESET",
            "REFRESH",
            "ACTIVATE",
        }
        actual_members = {member.name for member in TokenType}
        assert actual_members == expected_members


class TestTokenModel:
    """Tests for the TokenModel class"""

    @pytest.fixture
    def valid_token_data(self):
        """Fixture providing valid token data"""
        now = datetime.now(UTC)
        return {
            "iss": "test_issuer",
            "sub": "user123",
            "exp": now + timedelta(hours=1),
            "iat": now,
            "nbf": now,
            "aud": ["test_audience"],
            "scope": "read:profile",
            "verified": True,
            "role": RoleEnum.CUSTOMER,
            "jti": str(uuid.uuid4()),
        }

    def test_create_valid_token(self, valid_token_data):
        """Test creating a valid token model"""
        token = TokenModel(**valid_token_data)

        assert token.iss == valid_token_data["iss"]
        assert token.sub == valid_token_data["sub"]
        assert token.exp == valid_token_data["exp"]
        assert token.iat == valid_token_data["iat"]
        assert token.nbf == valid_token_data["nbf"]
        assert token.aud == valid_token_data["aud"]
        assert token.scope == valid_token_data["scope"]
        assert token.verified == valid_token_data["verified"]
        assert token.role == valid_token_data["role"]
        assert token.jti == valid_token_data["jti"]

    def test_token_serialization(self, valid_token_data):
        """Test token serialization to JSON"""
        token = TokenModel(**valid_token_data)
        token_json = token.model_dump(mode="json")

        # Check that all fields are serialized
        for key in valid_token_data:
            assert key in token_json

        # Datetime fields should be serialized to ISO format strings
        assert isinstance(token_json["exp"], str)
        assert isinstance(token_json["iat"], str)
        assert isinstance(token_json["nbf"], str)

        # Role should be serialized to its value
        assert token_json["role"] == valid_token_data["role"].value

    def test_token_deserialization(self, valid_token_data):
        """Test token deserialization from JSON"""
        # Convert datetime objects to ISO strings for JSON
        json_data = valid_token_data.copy()
        json_data["exp"] = json_data["exp"].isoformat()
        json_data["iat"] = json_data["iat"].isoformat()
        json_data["nbf"] = json_data["nbf"].isoformat()

        # Create model from JSON data
        token = TokenModel.model_validate(json_data)

        # Verify fields
        assert token.iss == valid_token_data["iss"]
        assert token.sub == valid_token_data["sub"]
        assert isinstance(token.exp, datetime)
        assert isinstance(token.iat, datetime)
        assert isinstance(token.nbf, datetime)
        assert token.aud == valid_token_data["aud"]
        assert token.scope == valid_token_data["scope"]
        assert token.verified == valid_token_data["verified"]
        assert token.role == valid_token_data["role"]
        assert token.jti == valid_token_data["jti"]

    def test_missing_required_fields(self):
        """Test that validation fails when required fields are missing"""
        with pytest.raises(ValueError):  # noqa: PT011
            TokenModel()  # type: ignore[call] # No fields provided

    @pytest.mark.parametrize(
        ("field", "invalid_value", "expected_error"),
        [
            ("iss", 123, "Input should be a valid string"),
            ("sub", 123, "Input should be a valid string"),
            ("exp", "not-a-date", "Input should be a valid datetime"),
            ("iat", "not-a-date", "Input should be a valid datetime"),
            ("nbf", "not-a-date", "Input should be a valid datetime"),
            ("aud", "not-a-list", "Input should be a valid list"),
            ("scope", 123, "Input should be a valid string"),
            ("verified", "not-a-bool", "Input should be a valid boolean"),
            ("jti", 123, "Input should be a valid string"),
        ],
    )
    def test_invalid_field_types(
        self,
        valid_token_data,
        field,
        invalid_value,
        expected_error,
    ):
        """Test validation with invalid field types"""
        invalid_data = valid_token_data.copy()
        invalid_data[field] = invalid_value

        with pytest.raises(ValueError) as exc_info:  # noqa: PT011
            TokenModel(**invalid_data)

        assert expected_error in str(exc_info.value)

    def test_invalid_role(self, valid_token_data):
        """Test validation with invalid role"""
        invalid_data = valid_token_data.copy()
        invalid_data["role"] = "invalid_role"

        with pytest.raises(ValueError) as exc_info:  # noqa: PT011
            TokenModel(**invalid_data)

        assert "Input should be 0, 1, 2, 3, 4 or 5" in str(
            exc_info.value,
        ) or "Input should be an instance of enum" in str(exc_info.value)
