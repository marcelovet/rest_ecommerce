from datetime import UTC
from datetime import date
from datetime import datetime
from datetime import timedelta

import pytest
from freezegun import freeze_time  # For mocking datetime
from pydantic import ValidationError

from app.models.request_models.register_form import ErrorMessages
from app.models.request_models.register_form import Gender
from app.models.request_models.register_form import RegisterForm


@pytest.fixture
def valid_data():
    """Fixture providing valid data for RegisterForm."""
    return {
        "email": "user@example.com",
        "password": "Pass1234@",
        "full_name": "John Doe",
        "phone": "(11) 99999-9999",
        "birth_date": date(1990, 1, 1),
        "gender": "male",
    }


@pytest.fixture
def min_valid_data():
    """Fixture providing minimum valid values for RegisterForm fields."""
    return {
        "email": "a@b.co",  # Minimal valid email
        "password": "aA1@1234",  # 8 chars with all required elements
        "full_name": "Bob",  # 3 chars (minimum)
        "phone": "(11) 99999-9999",
        "birth_date": datetime.now(UTC).date() - timedelta(days=1),  # Yesterday
        "gender": "other",
    }


@pytest.fixture
def max_valid_data():
    """
    Fixture providing maximum valid values for RegisterForm fields with upper limits.
    """
    return {
        "email": "very.long.email.address@subdomain.example.com",  # Valid email without length restriction  # noqa: E501
        "password": "aA1@" + "x" * 60,  # 64 chars (maximum)
        "full_name": "A" * 300,  # 300 chars (maximum)
        "phone": "(11) 99999-9999",
        "birth_date": date(1900, 1, 1),  # Old but realistic
        "gender": "female",
    }


class TestRegisterForm:
    """Tests for the RegisterForm Pydantic model."""

    def test_valid_register_form(self, valid_data):
        """Test that a valid registration form passes validation."""
        form = RegisterForm(**valid_data)

        assert form.email == valid_data["email"]
        assert form.password == valid_data["password"]
        assert form.full_name == valid_data["full_name"]
        assert form.phone == valid_data["phone"]
        assert form.birth_date == valid_data["birth_date"]
        assert form.gender == Gender.male

    # Email validation tests
    @pytest.mark.parametrize(
        ("email", "expected_in_error"),
        [
            ("invalid-email", "value is not a valid email address"),  # Invalid format
            (
                "@example.com",
                "value is not a valid email address",
            ),  # Missing local part
            ("user@", "value is not a valid email address"),  # Missing domain
            ("user@example", "value is not a valid email address"),  # Missing TLD
            (
                "us er@example.com",
                "value is not a valid email address",
            ),  # Space in local part
        ],
    )
    def test_invalid_email_format(self, valid_data, email, expected_in_error):
        """Test that invalid email format raises ValidationError."""
        invalid_data = {**valid_data, "email": email}

        with pytest.raises(ValidationError) as exc_info:
            RegisterForm(**invalid_data)

        errors = exc_info.value.errors()
        assert any(expected_in_error in error.get("msg", "") for error in errors)

    def test_rfc_compliant_email_addresses(self):
        """Test that various RFC-compliant email addresses are accepted."""
        rfc_compliant_emails = [
            "simple@example.com",
            "very.common@example.com",
            "disposable.style.email.with+symbol@example.com",
            "other.email-with-hyphen@example.com",
            "fully-qualified-domain@example.com",
            "user.name+tag+sorting@example.com",
            "x@example.com",  # One-letter local-part
            "example-indeed@strange-example.com",
            "example@s.example",  # Short domain
            # Add more RFC-compliant email formats as needed
        ]

        for email in rfc_compliant_emails:
            test_data = {
                "email": email,
                "password": "Pass1234@",
                "full_name": "John Doe",
                "phone": "(11) 99999-9999",
                "birth_date": date(1990, 1, 1),
                "gender": "male",
            }
            form = RegisterForm(**test_data)
            assert form.email == email

    # Password validation tests
    @pytest.mark.parametrize(
        ("password", "expected_error"),
        [
            ("Short1@", ErrorMessages.PASSWORD_TOO_SHORT),
            ("a" * 65 + "A1@", ErrorMessages.PASSWORD_TOO_LONG),
            ("PASSWORD1@", ErrorMessages.PASSWORD_NO_LOWERCASE),
            ("password1@", ErrorMessages.PASSWORD_NO_UPPERCASE),
            ("Password@", ErrorMessages.PASSWORD_NO_DIGIT),
            ("Password123", ErrorMessages.PASSWORD_NO_SPECIAL),
        ],
    )
    def test_password_validation(self, valid_data, password, expected_error):
        """Test various password validation rules."""
        invalid_data = {**valid_data, "password": password}

        with pytest.raises(ValidationError) as exc_info:
            RegisterForm(**invalid_data)

        errors = exc_info.value.errors()
        assert any(expected_error in error["msg"] for error in errors)

    # Full name validation tests
    @pytest.mark.parametrize(
        ("full_name", "expected_loc", "expected_type"),
        [
            ("Jo", "full_name", "string_too_short"),  # Too short (min is 3)
            ("J" * 301, "full_name", "string_too_long"),  # Too long (max is 300)
        ],
    )
    def test_invalid_full_name(
        self,
        valid_data,
        full_name,
        expected_loc,
        expected_type,
    ):
        """Test that invalid full name raises ValidationError."""
        invalid_data = {**valid_data, "full_name": full_name}

        with pytest.raises(ValidationError) as exc_info:
            RegisterForm(**invalid_data)

        errors = exc_info.value.errors()
        assert any(
            expected_loc in error["loc"] and expected_type == error["type"]
            for error in errors
        )

    # Phone validation tests
    @pytest.mark.parametrize(
        "phone",
        [
            "123456",  # Invalid format
            "+1 555-555-5555",  # Non-BR number
            "abc",  # Not a number at all
        ],
    )
    def test_invalid_phone_format(self, valid_data, phone):
        """Test that invalid phone format raises ValidationError."""
        invalid_data = {**valid_data, "phone": phone}

        with pytest.raises(ValidationError) as exc_info:
            RegisterForm(**invalid_data)

        errors = exc_info.value.errors()
        assert any("phone" in error["loc"] for error in errors)

    # Birth date validation tests
    @freeze_time("2023-01-01")  # Freeze time for deterministic tests
    def test_future_birth_date(self, valid_data):
        """Test that future birth date raises ValidationError."""
        future_date = date(2023, 1, 2)  # One day in the future from frozen time
        invalid_data = {**valid_data, "birth_date": future_date}

        with pytest.raises(ValidationError) as exc_info:
            RegisterForm(**invalid_data)

        errors = exc_info.value.errors()
        assert any(ErrorMessages.BIRTH_DATE_FUTURE in error["msg"] for error in errors)

    @freeze_time("2023-01-01")
    def test_unrealistic_birth_date(self, valid_data):
        """Test that unrealistically old birth date raises ValidationError."""
        # The model considers dates older than 200 years as unrealistic
        old_date = date(1822, 12, 31)  # More than 200 years from frozen time
        invalid_data = {**valid_data, "birth_date": old_date}

        with pytest.raises(ValidationError) as exc_info:
            RegisterForm(**invalid_data)

        errors = exc_info.value.errors()
        assert any(
            ErrorMessages.BIRTH_DATE_UNREALISTIC in error["msg"] for error in errors
        )

    # Test boundary conditions for birth date
    @freeze_time("2023-01-01")
    @pytest.mark.parametrize(
        ("test_date", "should_pass"),
        [
            (date(1824, 1, 2), True),  # Just under 200 years - should pass
            (date(1823, 1, 1), False),  # Exactly 200 years - should fail
            (date(1822, 12, 31), False),  # Over 200 years - should fail
            (date(2022, 12, 31), True),  # Yesterday - should pass
            (date(2023, 1, 1), True),  # Today - should pass
            (date(2023, 1, 2), False),  # Tomorrow - should fail
        ],
    )
    def test_birth_date_boundaries(self, valid_data, test_date, should_pass):
        """Test boundary conditions for birth date validation."""
        # Arrange
        test_data = {**valid_data, "birth_date": test_date}

        if should_pass:
            # Should not raise an exception
            RegisterForm(**test_data)
        else:
            # Should raise ValidationError
            with pytest.raises(ValidationError):
                RegisterForm(**test_data)

    # Gender validation tests
    def test_invalid_gender(self, valid_data):
        """Test that invalid gender value raises ValidationError."""
        invalid_data = {**valid_data, "gender": "invalid"}  # Not in enum

        with pytest.raises(ValidationError) as exc_info:
            RegisterForm(**invalid_data)

        errors = exc_info.value.errors()
        assert any("gender" in error["loc"] for error in errors)

    # Edge cases
    def test_minimum_valid_values(self, min_valid_data):
        """Test with minimum acceptable values for all fields."""
        form = RegisterForm(**min_valid_data)

        assert form.email == min_valid_data["email"]
        assert form.full_name == min_valid_data["full_name"]
        assert form.password == min_valid_data["password"]

    def test_maximum_valid_values(self, max_valid_data):
        """Test with maximum acceptable values for fields with upper limits."""
        form = RegisterForm(**max_valid_data)

        assert form.email == max_valid_data["email"]
        assert form.full_name == max_valid_data["full_name"]
        assert form.password == max_valid_data["password"]


# Additional tests for separated validation logic
class TestPasswordValidation:
    """Tests specifically for password validation logic."""

    def test_validate_password_directly(self):
        """Test the password validator function directly."""
        from app.models.request_models.register_form import (
            validate_password,  # This would be the refactored function
        )

        # Valid password
        assert validate_password("Valid123@") == "Valid123@"

        # Invalid passwords
        with pytest.raises(ValueError, match=ErrorMessages.PASSWORD_TOO_SHORT):
            validate_password("Short1@")

        with pytest.raises(ValueError, match=ErrorMessages.PASSWORD_NO_LOWERCASE):
            validate_password("PASSWORD123@")


class TestBirthDateValidation:
    """Tests specifically for birth date validation logic."""

    @freeze_time("2023-01-01")
    def test_validate_birth_date_directly(self):
        """Test the birth date validator function directly."""
        from app.models.request_models.register_form import (
            validate_birth_date,  # This would be the refactored function
        )

        # Valid date
        valid_date = date(1990, 1, 1)
        assert validate_birth_date(valid_date) == valid_date

        # Future date
        future_date = date(2023, 1, 2)
        with pytest.raises(ValueError, match=ErrorMessages.BIRTH_DATE_FUTURE):
            validate_birth_date(future_date)

        # Unrealistic date
        unrealistic_date = date(1822, 12, 31)
        with pytest.raises(ValueError, match=ErrorMessages.BIRTH_DATE_UNREALISTIC):
            validate_birth_date(unrealistic_date)
