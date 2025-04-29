import pytest
from unittest.mock import MagicMock
from app.services import crud
from app.repository import schemas, models


def test_create_user():
    mock_db = MagicMock()
    user_data = schemas.UserCreate(
        username="testuser", email="test@example.com", password="password123"
    )
    result = crud.create_user(mock_db, user_data)
    assert result.username == "testuser"
    assert result.email == "test@example.com"
    assert result.hashed_password is not None
    assert result.verification_token is not None
    mock_db.add.assert_called_once()
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once()


def test_create_contact():
    mock_db = MagicMock()
    contact_data = schemas.ContactCreate(
        first_name="John",
        last_name="Doe",
        email="john@example.com",
        phone="1234567890",
        birthday="2000-01-01",
        additional_info="Friend",
    )
    result = crud.create_contact(mock_db, contact_data)
    assert result.first_name == "John"
    assert result.last_name == "Doe"
    assert result.email == "john@example.com"
    mock_db.add.assert_called_once()
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once()


def test_get_contact_by_id():
    mock_db = MagicMock()
    mock_contact = models.Contact(id=1, first_name="Jane")

    mock_query = mock_db.query.return_value
    mock_filter = mock_query.filter.return_value
    mock_filter.first.return_value = mock_contact

    result = crud.get_contact_by_id(mock_db, 1)
    assert result.first_name == "Jane"

    mock_query.filter.assert_called_once()


def test_verify_email_success():
    mock_db = MagicMock()
    user = models.User(is_verified=False, verification_token="validtoken")
    mock_db.query().filter().first.return_value = user
    result = crud.verify_email(mock_db, "validtoken")
    assert result.is_verified is True
    assert result.verification_token is None
    mock_db.commit.assert_called_once()
    mock_db.refresh.assert_called_once()


def test_verify_email_fail():
    mock_db = MagicMock()
    mock_db.query().filter().first.return_value = None
    result = crud.verify_email(mock_db, "invalidtoken")
    assert result is None


def test_delete_contact():
    mock_db = MagicMock()
    contact = models.Contact(id=1)
    mock_db.query().filter().first.return_value = contact
    result = crud.delete_contact(mock_db, 1)
    assert result == contact
    mock_db.delete.assert_called_once_with(contact)
    mock_db.commit.assert_called_once()
