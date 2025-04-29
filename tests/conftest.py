import os
import pytest
import redis
import subprocess
import time
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

from app.cache import redis_cache
from app.main import app
from app.repository.database import get_db
from app.repository.models import Base

load_dotenv()

TEST_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        if os.path.exists("test.db"):
            os.remove("test.db")


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session", autouse=True)
def redis_server():
    os.environ["REDIS_HOST"] = "localhost"
    container_name = "test_redis_cache"
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "-p",
                "6379:6379",
                "--name",
                container_name,
                "redis",
            ],
            check=True,
        )
        time.sleep(2)  # Wait a bit for Redis to be ready
        yield
    finally:
        subprocess.run(["docker", "stop", container_name], check=False)
