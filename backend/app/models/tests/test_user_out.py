import pytest
from pydantic import ValidationError

from app.models.user.user_out import RoleEnum
from app.models.user.user_out import UserOut


@pytest.fixture
def default_user():
    """
    Fixture that returns a default UserOut instance with common values.

    Returns:
        UserOut: A user with default test values
    """
    return UserOut(
        id=1,
        email="user@example.com",
        full_name="Test User",
        is_active=True,
        is_verified=True,
        role=RoleEnum.CUSTOMER,
    )


@pytest.fixture
def create_user():
    """
    Fixture that returns a factory function to create UserOut instances.
    This allows for customizing specific fields while using defaults for others.

    Returns:
        function: A factory function that creates UserOut instances
    """

    def _create_user(**kwargs):
        user_data = {
            "id": 1,
            "email": "user@example.com",
            "full_name": "Test User",
            "is_active": True,
            "is_verified": True,
            "role": RoleEnum.CUSTOMER,
        }
        user_data.update(kwargs)
        return UserOut(**user_data)

    return _create_user


class TestUserOut:
    """Tests for the UserOut Pydantic model."""

    def test_valid_user_creation_with_enum(self, default_user):
        """Test that a valid user can be created with enum role."""
        assert default_user.id == 1
        assert default_user.email == "user@example.com"
        assert default_user.full_name == "Test User"
        assert default_user.is_active is True
        assert default_user.is_verified is True
        assert default_user.role == RoleEnum.CUSTOMER
        assert default_user.role == 0
        assert isinstance(default_user.role, RoleEnum)

    def test_valid_user_creation_with_integer(self, create_user):
        """Test that a valid user can be created with integer role."""
        user = create_user(role=2)  # Using integer value for INVENTORY_MANAGER

        assert user.role == RoleEnum.INVENTORY_MANAGER
        assert user.role == 2
        assert isinstance(user.role, RoleEnum)

    def test_invalid_role_value(self, create_user):
        """Test that model creation fails with invalid role values."""
        with pytest.raises(ValidationError):
            create_user(role=10)  # Invalid role value

    def test_field_exclusion(self, create_user):
        """Test that fields marked with exclude=True are excluded from JSON output."""
        user = create_user(role=RoleEnum.ADMIN)

        user_dict = user.model_dump(exclude_unset=True)
        user_json = user.model_dump_json(exclude_unset=True)

        assert "id" not in user_dict
        assert "is_active" not in user_dict
        assert "is_verified" not in user_dict
        assert "email" in user_dict
        assert "full_name" in user_dict
        assert "role" in user_dict
        assert user_dict["role"] == 5  # Serialized as integer

        assert '"id":' not in user_json
        assert '"is_active":' not in user_json
        assert '"is_verified":' not in user_json
        assert '"role": 5' in user_json or '"role":5' in user_json

    @pytest.mark.parametrize(
        ("is_active", "is_verified", "expected"),
        [
            (True, True, True),  # Both active and verified
            (True, False, False),  # Active but not verified
            (False, True, False),  # Not active but verified
            (False, False, False),  # Neither active nor verified
        ],
    )
    def test_is_authorized(self, create_user, is_active, is_verified, expected):
        """
        Test the is_authorized method with different combinations of
        is_active and is_verified.
        """
        user = create_user(
            is_active=is_active,
            is_verified=is_verified,
        )

        result = user.is_authorized()

        assert result == expected

    @pytest.mark.parametrize(
        ("role", "expected_role"),
        [
            (RoleEnum.CUSTOMER, RoleEnum.CUSTOMER),
            (RoleEnum.STAFF, RoleEnum.STAFF),
            (RoleEnum.INVENTORY_MANAGER, RoleEnum.INVENTORY_MANAGER),
            (RoleEnum.ORDER_PROCESSOR, RoleEnum.ORDER_PROCESSOR),
            (RoleEnum.STORE_MANAGER, RoleEnum.STORE_MANAGER),
            (RoleEnum.ADMIN, RoleEnum.ADMIN),
            (0, RoleEnum.CUSTOMER),
            (1, RoleEnum.STAFF),
            (2, RoleEnum.INVENTORY_MANAGER),
            (3, RoleEnum.ORDER_PROCESSOR),
            (4, RoleEnum.STORE_MANAGER),
            (5, RoleEnum.ADMIN),
        ],
    )
    def test_role_assignment(self, create_user, role, expected_role):
        """Test that different role values are correctly assigned and converted."""
        user = create_user(role=role)

        assert user.role == expected_role
        assert isinstance(user.role, RoleEnum)
