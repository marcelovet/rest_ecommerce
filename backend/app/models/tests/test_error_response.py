import pytest
from pydantic import ValidationError

from app.models.response_models import ErrorResponse


class TestErrorResponse:
    """Tests for the ErrorResponse model."""

    def test_create_with_required_fields(self):
        """Test creating an ErrorResponse with only required fields."""
        error = ErrorResponse(detail="Test error message")  # type: ignore[call-arg]

        assert error.detail == "Test error message"
        assert error.code is None
        assert error.context is None

    def test_create_with_all_fields(self):
        """Test creating an ErrorResponse with all fields."""
        context = {"field": "username", "issue": "too short"}
        error = ErrorResponse(
            detail="Validation failed",
            code="VALIDATION_ERROR",
            context=context,
        )

        assert error.detail == "Validation failed"
        assert error.code == "VALIDATION_ERROR"
        assert error.context == context

    def test_detail_min_length_validation(self):
        """Test that detail field validates minimum length."""
        with pytest.raises(ValidationError) as exc_info:
            ErrorResponse(detail="")  # type: ignore[call-arg]

        errors = exc_info.value.errors()
        assert any(
            e["type"] == "string_too_short" and e["loc"] == ("detail",) for e in errors
        )

    def test_detail_max_length_validation(self):
        """Test that detail field validates maximum length."""
        with pytest.raises(ValidationError) as exc_info:
            ErrorResponse(detail="a" * 501)  # type: ignore[call-arg] # Exceeds max length of 500

        errors = exc_info.value.errors()
        assert any(
            e["type"] == "string_too_long" and e["loc"] == ("detail",) for e in errors
        )

    def test_code_pattern_validation(self):
        """Test that code field validates pattern."""
        # Valid patterns
        ErrorResponse(detail="Test", code="ERROR_CODE")  # type: ignore[call-arg]
        ErrorResponse(detail="Test", code="E123")  # type: ignore[call-arg]

        # Invalid patterns
        invalid_codes = ["lowercase", "123_STARTS_WITH_NUMBER", "CONTAINS-HYPHEN"]
        for invalid_code in invalid_codes:
            with pytest.raises(ValidationError) as exc_info:
                ErrorResponse(detail="Test", code=invalid_code)  # type: ignore[call-arg]

            errors = exc_info.value.errors()
            assert any(
                e["type"] == "string_pattern_mismatch" and e["loc"] == ("code",)
                for e in errors
            )

    def test_create_from_code_valid(self):
        """Test create_from_code with valid error codes."""
        for code, expected_detail in ErrorResponse.ERROR_CODES.items():
            error = ErrorResponse.create_from_code(code)

            assert error.detail == expected_detail
            assert error.code == code
            assert error.context is None

    def test_create_from_code_with_context(self):
        """Test create_from_code with context parameters."""
        context = {"user_id": 123, "resource": "profile"}
        error = ErrorResponse.create_from_code("NOT_FOUND", **context)

        assert error.detail == ErrorResponse.ERROR_CODES["NOT_FOUND"]
        assert error.code == "NOT_FOUND"
        assert error.context == context

    def test_create_from_code_invalid(self):
        """Test create_from_code with invalid error code."""
        with pytest.raises(ValueError) as exc_info:  # noqa: PT011
            ErrorResponse.create_from_code("NONEXISTENT_CODE")

        assert "Unknown error code: NONEXISTENT_CODE" in str(exc_info.value)

    def test_with_empty_context(self):
        """Test with empty context dictionary."""
        # Empty dict should be preserved as is
        error = ErrorResponse(detail="Test", context={})  # type: ignore[call-arg]
        assert error.context == {}

        # When using create_from_code with no context, it should be None
        error = ErrorResponse.create_from_code("NOT_FOUND")
        assert error.context is None

    def test_with_nested_context(self):
        """Test with complex nested context values."""
        nested_context = {
            "user": {
                "id": 123,
                "roles": ["admin", "editor"],
            },
            "request": {
                "path": "/api/resource",
                "method": "POST",
            },
            "validation_errors": [
                {"field": "email", "error": "invalid format"},
                {"field": "password", "error": "too short"},
            ],
        }

        error = ErrorResponse(
            detail="Complex error",
            code="VALIDATION_ERROR",
            context=nested_context,
        )

        assert error.context == nested_context

    def test_model_serialization(self):
        """Test model serialization to dict/JSON."""
        error = ErrorResponse(
            detail="Test serialization",
            code="TEST_CODE",
            context={"key": "value"},
        )

        # Convert to dict
        data = error.model_dump()

        # code should be excluded from serialization
        assert "detail" in data
        assert "code" not in data
        assert "context" in data
        assert data["detail"] == "Test serialization"
        assert data["context"] == {"key": "value"}
