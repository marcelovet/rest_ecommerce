import enum
from datetime import UTC
from datetime import datetime

from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import Date
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db.base import Base


# Enum types
class Gender(enum.Enum):
    MALE = "MALE"
    FEMALE = "FEMALE"
    OTHER = "OTHER"
    PREFER_NOT_TO_SAY = "PREFER_NOT_TO_SAY"


class AddressType(enum.Enum):
    BILLING = "BILLING"
    SHIPPING = "SHIPPING"


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, doc="Unique identifier for each role")
    name = Column(String(50), nullable=False, doc="Name of the role")

    # Relationships
    users = relationship("User", back_populates="role")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, doc="Unique identifier for each user")
    email = Column(
        String(64 + 1 + 255),  # RFC 64 chars + @ + 255 chars
        unique=True,
        nullable=False,
        doc="User's email address, used for login and communication",
    )
    hashed_password = Column(
        String(255),
        nullable=False,
        doc="Securely stored password hash",
    )
    full_name = Column(Text, nullable=False, doc="User's complete name")
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        doc="Flag indicating if the account is active or disabled",
    )
    is_verified = Column(
        Boolean,
        nullable=False,
        default=False,
        doc="Flag indicating if the email has been verified",
    )
    role_id = Column(
        Integer,
        ForeignKey("roles.id", ondelete="SET DEFAULT"),
        nullable=False,
        default=0,
        doc="Reference to the user's role, determining permissions",
    )
    created_at = Column(DateTime, nullable=False, default=datetime.now(UTC))
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.now(UTC),
        onupdate=datetime.now(UTC),
    )
    deleted_at = Column(DateTime, nullable=True, doc="For soft delete")

    # Relationships
    role = relationship("Role", back_populates="users")
    profile = relationship(
        "UserProfile",
        back_populates="user",
        uselist=False,
        cascade="all, delete",
    )
    addresses = relationship("Address", back_populates="user", cascade="all, delete")
    verification_tokens = relationship(
        "VerificationToken",
        back_populates="user",
        cascade="all, delete",
    )
    password_reset_tokens = relationship(
        "PasswordResetToken",
        back_populates="user",
        cascade="all, delete",
    )

    # TODO: Add relationships for orders, reviews, carts, etc.
    # orders = relationship("Order", back_populates="user")
    # reviews = relationship("ProductReview", back_populates="user")
    # carts = relationship("Cart", back_populates="user")


class UserProfile(Base):
    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, doc="Unique identifier for each profile")
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        doc="Reference to the associated user",
    )
    phone = Column(String(20), nullable=True, doc="User's contact phone number")
    birth_date = Column(
        Date,
        nullable=True,
        doc="User's date of birth for age verification and birthday offers",
    )
    gender = Column(Enum(Gender), nullable=True, doc="User's gender identity")
    preferences = Column(
        JSONB,
        nullable=True,
        doc="JSON containing user preferences (e.g., notification settings, theme)",
    )
    created_at = Column(DateTime, nullable=False, default=datetime.now(UTC))
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.now(UTC),
        onupdate=datetime.now(UTC),
    )

    # Relationships
    user = relationship("User", back_populates="profile")


class Address(Base):
    __tablename__ = "addresses"

    id = Column(Integer, primary_key=True, doc="Unique identifier for each address")
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        doc="Reference to the associated user",
    )
    address_type = Column(
        Enum(AddressType),
        nullable=False,
        doc="Indicates if this is a billing or shipping address",
    )
    is_default = Column(
        Boolean,
        nullable=False,
        default=False,
        doc="Flag indicating if this is the user's default address",
    )
    recipient_name = Column(
        Text,
        nullable=False,
        doc="Name of the person receiving packages",
    )
    street_address = Column(
        String(250),
        nullable=False,
        doc="Primary street address line",
    )
    complement = Column(
        String(50),
        nullable=True,
        doc="Additional address details (apartment, suite, unit)",
    )
    city = Column(String(100), nullable=False, doc="City/town name")
    state = Column(String(100), nullable=False, doc="State/province/region")
    postal_code = Column(String(20), nullable=False, doc="ZIP or postal code")
    country = Column(String(80), nullable=False, doc="Country name")
    phone = Column(
        String(20),
        nullable=False,
        doc="Contact phone for delivery questions",
    )
    created_at = Column(DateTime, nullable=False, default=datetime.now(UTC))
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.now(UTC),
        onupdate=datetime.now(UTC),
    )

    # Relationships
    user = relationship("User", back_populates="addresses")

    # TODO: Add relationships for orders
    # shipping_orders = relationship(
    #     "Order",
    #     foreign_keys="[Order.shipping_address_id]",
    #     back_populates="shipping_address",
    # )
    # billing_orders = relationship(
    #     "Order",
    #     foreign_keys="[Order.billing_address_id]",
    #     back_populates="billing_address",
    # )


class VerificationToken(Base):
    __tablename__ = "verification_tokens"

    id = Column(
        Integer,
        primary_key=True,
        doc="Unique identifier for each verification token",
    )
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        doc="Reference to the user who owns the token",
    )
    token = Column(String(255), nullable=False, doc="Unique token for verification")
    expires_at = Column(DateTime, nullable=False)

    # Relationships
    user = relationship("User", back_populates="verification_tokens")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(
        Integer,
        primary_key=True,
        doc="Unique identifier for each password reset token",
    )
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        doc="Reference to the user who owns the token",
    )
    token = Column(String(255), nullable=False, doc="Unique token for password reset")
    expires_at = Column(DateTime, nullable=False)

    # Relationships
    user = relationship("User", back_populates="password_reset_tokens")
