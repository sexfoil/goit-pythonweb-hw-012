from sqlalchemy import Column, Integer, String, Date, Boolean
from .database import Base


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
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
