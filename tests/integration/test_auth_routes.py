import uuid


def test_register_user(client):
    unique_username = f"testuser_{uuid.uuid4().hex}"
    unique_email = f"{unique_username}@example.com"
    response = client.post(
        "/auth/register",
        json={
            "username": unique_username,
            "email": unique_email,
            "password": "testpassword123",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == unique_email
    assert "id" in data


def test_login_user(client):
    unique_username = f"loginuser_{uuid.uuid4().hex}"
    unique_email = f"{unique_username}@example.com"

    register_response = client.post(
        "/auth/register",
        json={
            "username": unique_username,
            "email": unique_email,
            "password": "testpassword123",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/auth/login",
        data={"username": unique_email, "password": "testpassword123"},
    )
    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_verify_email(client, db_session):
    unique_username = f"verifyuser_{uuid.uuid4().hex}"
    unique_email = f"{unique_username}@example.com"
    response = client.post(
        "/auth/register",
        json={
            "username": unique_username,
            "email": unique_email,
            "password": "testpassword123",
        },
    )
    assert response.status_code == 201

    from app import models

    user = db_session.query(models.User).filter_by(email=unique_email).first()
    token = user.verification_token

    verify_response = client.get(f"/auth/verify-email?token={token}")
    assert verify_response.status_code == 200
    assert verify_response.json() == {"message": "Email successfully verified!"}
