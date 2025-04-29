import io
import uuid
import tempfile
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.repository import models


@pytest.fixture
def authorized_client(client, db_session):
    unique_username = f"user_{uuid.uuid4().hex}"
    email = f"{unique_username}@example.com"
    password = "strongpassword123"

    response = client.post(
        "/auth/register",
        json={"username": unique_username, "email": email, "password": password},
    )
    assert response.status_code == 201

    db_user = db_session.query(models.User).filter_by(email=email).first()
    db_user.is_verified = True
    db_session.commit()

    login_response = client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    token = login_response.json()["access_token"]
    client.headers = {"Authorization": f"Bearer {token}"}
    return client


def test_me_route(authorized_client):
    response = authorized_client.get("/me")
    assert response.status_code == 200
    assert "email" in response.json()


def test_create_get_update_delete_contact(authorized_client):
    # Create
    contact_data = {
        "first_name": "John",
        "last_name": "Doe",
        "email": f"johndoe_{uuid.uuid4().hex[:6]}@example.com",
        "phone": "1234567890",
    }
    response = authorized_client.post("/contacts/", json=contact_data)
    assert response.status_code == 201
    contact_id = response.json()["id"]

    # Get all
    response = authorized_client.get("/contacts/")
    assert response.status_code == 200
    assert any(contact["id"] == contact_id for contact in response.json())

    # Get by ID
    response = authorized_client.get(f"/contacts/{contact_id}")
    assert response.status_code == 200
    assert response.json()["first_name"] == "John"

    # Update
    updated_data = {
        "first_name": "Jane",
        "last_name": "Doe",
        "email": contact_data["email"],
        "phone": contact_data["phone"],
    }
    response = authorized_client.put(f"/contacts/{contact_id}", json=updated_data)
    assert response.status_code == 200
    assert response.json()["first_name"] == "Jane"

    # Delete
    response = authorized_client.delete(f"/contacts/{contact_id}")
    assert response.status_code == 200
    assert response.json()["id"] == contact_id


def test_search_and_birthdays(authorized_client):
    # Add contact with specific name and birthday
    contact_data = {
        "first_name": "Birthday",
        "last_name": "Person",
        "email": f"birthday_{uuid.uuid4().hex[:6]}@example.com",
        "phone": "9876543210",
        "birthday": "2099-12-31",
    }
    response = authorized_client.post("/contacts/", json=contact_data)
    assert response.status_code == 201

    # Search
    search_response = authorized_client.get("/search/?query=Birthday")
    assert search_response.status_code == 200
    assert any(
        "Birthday" in contact["first_name"] for contact in search_response.json()
    )

    # Birthdays (likely empty unless mocked)
    bday_response = authorized_client.get("/birthdays/")
    assert bday_response.status_code == 200
    assert isinstance(bday_response.json(), list)


def test_upload_avatar_mocked(authorized_client, monkeypatch):
    def mock_upload_avatar(file_path, public_id):
        return f"https://example.com/avatars/{public_id}.jpg"

    monkeypatch.setattr("app.main.upload_avatar", mock_upload_avatar)

    with tempfile.NamedTemporaryFile(suffix=".jpg") as tmp:
        tmp.write(b"fake image data")
        tmp.seek(0)
        files = {"file": ("avatar.jpg", tmp, "image/jpeg")}
        response = authorized_client.post("/upload-avatar", files=files)
        assert response.status_code == 200
        assert response.json()["avatar_url"].startswith("https://example.com/avatars/")
