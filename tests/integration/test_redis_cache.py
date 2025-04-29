import uuid
import pytest
from app.repository import models
from fastapi.testclient import TestClient
from app.cache.redis_cache import get_redis_client


def test_user_cached_after_login(client: TestClient, db_session):
    username = f"user_{uuid.uuid4().hex[:6]}"
    email = f"{username}@example.com"
    password = "securepass123"

    response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
        },
    )
    assert response.status_code == 201

    user = db_session.query(models.User).filter_by(email=email).first()
    user.is_verified = True
    db_session.commit()

    login_response = client.post(
        "/auth/login", data={"username": email, "password": password}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    client.headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/me")
    assert response.status_code == 200

    redis_key = f"user:{email}"
    cached_user = get_redis_client().get(redis_key)
    assert cached_user is not None
