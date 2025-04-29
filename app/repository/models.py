from sqlalchemy import (
    Column,
    Integer,
    String,
    Date,
    Boolean,
    Enum,
    ForeignKey,
    DateTime,
)
from sqlalchemy.orm import relationship
from datetime import datetime, UTC
from .database import Base
from ..utils.enums import UserRole


class Contact(Base):
    """
    SQLAlchemy model representing a contact entry in the database.

    Attributes:
        id (int): Primary key identifier of the contact.
        first_name (str): First name of the contact.
        last_name (str): Last name of the contact.
        email (str): Email address of the contact (must be unique).
        phone (str): Phone number of the contact.
        birthday (date): Optional birthday of the contact.
        additional_info (str): Optional additional notes about the contact.
    """

    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    phone = Column(String, nullable=False)
    birthday = Column(Date)
    additional_info = Column(String, nullable=True)


class User(Base):
    """
    SQLAlchemy model representing a user account in the database.

    Attributes:
        id (int): Primary key identifier of the user.
        username (str): Unique username.
        email (str): Unique email address of the user.
        hashed_password (str): Hashed user password.
        is_active (bool): Indicates whether the user account is active.
        is_verified (bool): Indicates whether the user's email is verified.
        verification_token (str): Token used for verifying user email.
        avatar_url (str): Optional URL to the user's avatar image.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(
        Enum(UserRole, name="user_role_enum"),
        default=UserRole.user,
        nullable=False,
        comment="User role: 'user', 'admin', etc.",
    )
    last_password_reset = Column(DateTime, default=datetime.now(UTC))
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class RefreshToken(Base):
    """
    SQLAlchemy model for storing refresh tokens.

    Attributes:
        id (int): Primary key identifier.
        user_id (int): Foreign key reference to the User.
        token (str): The actual refresh token string.
        created_at (datetime): Timestamp of when the token was created.
        revoked (bool): Indicates if the token has been revoked.
    """

    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.now(UTC), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    user = relationship("User", back_populates="refresh_tokens")
