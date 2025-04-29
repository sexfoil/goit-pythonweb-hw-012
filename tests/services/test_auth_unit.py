import pytest
from app.routes import auth


def test_get_password_hash_and_verify_password():
    password = "mysecretpassword"
    hashed = auth.get_password_hash(password)
    assert isinstance(hashed, str)
    assert auth.verify_password(password, hashed)
    assert not auth.verify_password("wrongpassword", hashed)


def test_create_access_token():
    data = {"sub": "user@example.com"}
    token = auth.create_access_token(data)
    assert isinstance(token, str)
    decoded = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
    assert decoded["sub"] == "user@example.com"
    assert "exp" in decoded


def test_create_verification_token():
    email = "test@example.com"
    token = auth.create_verification_token(email)
    assert isinstance(token, str)
    decoded = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
    assert decoded["sub"] == email
    assert "exp" in decoded
