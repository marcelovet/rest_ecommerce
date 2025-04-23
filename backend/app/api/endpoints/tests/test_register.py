import datetime
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from app.core.config import settings as st
from app.main import app
from app.models.request_models import RegisterForm
from app.models.request_models.register_form import Gender
from app.models.user.user_out import UserOut
from app.services.auth_service import AuthService

client = TestClient(app)


@pytest.fixture
def valid_register_form():
    """Fixture providing a valid registration form data."""
    return {
        "email": "test@example.com",
        "password": "Password1@",
        "full_name": "Test User",
        "phone": "(11) 99999-9999",
        "birth_date": "1990-01-01",
        "gender": "male",
    }


@pytest.fixture
def mock_auth_service():
    """Fixture to mock the auth service."""
    with patch("app.api.dependencies.AuthService", autospec=True) as mock_service_class:
        mock_service = MagicMock(spec=AuthService)
        mock_service_class.return_value = mock_service
        yield mock_service


@pytest.fixture
def mock_successful_register_response(token_data_instance):
    return {
        "success": True,
        "user": UserOut(
            id=1,
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            is_verified=False,
            role=0,  # type: ignore[arg-type]
        ),
        "token": token_data_instance,
        "message": "User registered successfully",
    }


@pytest.mark.parametrize(
    ("field", "value", "expected_error"),
    [
        (
            "password",
            "short",
            "Password must be at least 8 characters",
        ),
        (
            "password",
            "a" * 65,
            "Password must be less than 64 characters",
        ),
        (
            "password",
            "password1@",
            "Password must contain an uppercase letter",
        ),
        (
            "password",
            "PASSWORD1@",
            "Password must contain a lowercase letter",
        ),
        (
            "password",
            "Password@",
            "Password must contain a digit",
        ),
        (
            "password",
            "Password1",
            "Password must contain a special character (@$!%*?&#)",
        ),
        (
            "email",
            "invalid-email",
            "value is not a valid email address",
        ),
        (
            "full_name",
            "ab",
            "String should have at least 3 characters",
        ),
        (
            "birth_date",
            (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)).strftime(
                "%Y-%m-%d",
            ),
            "Birth date must be in the past",
        ),
        (
            "birth_date",
            "1800-01-01",
            "There is a problem with the birth date",
        ),
        (
            "phone",
            "invalid-phone",
            "value is not a valid phone number",
        ),
        (
            "gender",
            "invalid-gender",
            "Input should be 'male', 'female', 'other' or 'prefer not to say'",
        ),
    ],
)
def test_register_validation_errors(valid_register_form, field, value, expected_error):
    """Test validation errors for each field in the register form."""
    # Arrange
    form_data = valid_register_form.copy()
    form_data[field] = value

    # Act
    response = client.post(f"{st.API_VERSION_PREFIX}/auth/register", data=form_data)

    # Assert
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert expected_error in response.text


def test_register_success(
    mock_auth_service,
    valid_register_form,
    mock_successful_register_response,
):
    """Test successful user registration."""
    # Arrange
    mock_user = mock_successful_register_response["user"]
    mock_token = mock_successful_register_response["token"]
    mock_auth_service.register_user.return_value = {
        "success": True,
        "user": mock_user,
        "token": mock_token,
        "message": "User registered successfully",
    }

    # Act
    response = client.post(
        f"{st.API_VERSION_PREFIX}/auth/register",
        data=valid_register_form,
    )

    # Assert
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json() == {
        "message": "Verification pending",
        "user": mock_user.model_dump(),
        "token": mock_token.model_dump(),
    }
    mock_auth_service.register_user.assert_called_once()
    # Verify the RegisterForm was created correctly with the provided data
    form_arg = mock_auth_service.register_user.call_args[0][0]
    assert isinstance(form_arg, RegisterForm)
    assert form_arg.email == valid_register_form["email"]
    assert form_arg.full_name == valid_register_form["full_name"]
    assert form_arg.gender == Gender.male


def test_register_conflict(mock_auth_service, valid_register_form):
    """Test registration with conflict (e.g., email already exists)."""
    # Arrange
    mock_auth_service.register_user.return_value = {
        "success": False,
        "message": "Email already registered",
        "user_already_exists": True,
    }

    # Act
    response = client.post(
        f"{st.API_VERSION_PREFIX}/auth/register",
        data=valid_register_form,
    )

    # Assert
    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json() == {"detail": "Email already registered"}


def test_register_server_error(mock_auth_service, valid_register_form):
    """Test registration with other server error."""
    # Arrange
    mock_auth_service.register_user.return_value = {
        "success": False,
        "message": "Some server error",
    }

    # Act
    response = client.post(
        f"{st.API_VERSION_PREFIX}/auth/register",
        data=valid_register_form,
    )

    # Assert
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json() == {"detail": "Some server error"}


def test_register_form_handling(mock_auth_service, mock_successful_register_response):
    """Test that the endpoint correctly handles form data."""
    # Arrange
    mock_auth_service.register_user.return_value = mock_successful_register_response

    # Act
    client.post(
        f"{st.API_VERSION_PREFIX}/auth/register",
        data={
            "email": "test@example.com",
            "password": "Password1@",
            "full_name": "Test User",
            "phone": "(11) 99999-9999",
            "birth_date": "1990-01-01",
            "gender": "male",
        },
    )

    # Assert
    mock_auth_service.register_user.assert_called_once()
    form_arg = mock_auth_service.register_user.call_args[0][0]
    assert isinstance(form_arg, RegisterForm)


def test_auth_service_db_integration(mock_successful_register_response):
    """Test that the AuthService is created with the correct DB session."""
    # Create a spy to capture the DB session
    db_spy = MagicMock()
    original_auth_service = AuthService

    # Create a mock for the register_user method
    mock_register_result = mock_successful_register_response

    # Create a spy AuthService class
    class SpyAuthService(original_auth_service):
        def __init__(self, db):
            super().__init__(db)
            db_spy(db)  # Capture the DB session

        def register_user(self, form):
            return mock_register_result

    # Override the AuthService class
    with patch("app.api.dependencies.AuthService", SpyAuthService):
        # Send request
        response = client.post(
            f"{st.API_VERSION_PREFIX}/auth/register",
            data={
                "email": "test@example.com",
                "password": "Password1@",
                "full_name": "Test User",
                "phone": "(11) 99999-9999",
                "birth_date": "1990-01-01",
                "gender": "male",
            },
        )

        # Verify the response
        assert response.status_code == 201

        # Verify the DB session was passed to AuthService
        db_spy.assert_called_once()

        # Verify the DB session is a SQLAlchemy Session
        from sqlalchemy.orm import Session

        assert isinstance(db_spy.call_args[0][0], Session)
