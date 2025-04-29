import os
import sys
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from .enums import UserRole
from ..repository import models
from ..repository.database import SessionLocal
from ..routes.auth import get_password_hash

load_dotenv()


def create_admin():
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        print("❌ ADMIN_EMAIL or ADMIN_PASSWORD not set in .env")
        sys.exit(1)

    db: Session = SessionLocal()

    try:
        admin = db.query(models.User).filter_by(email=admin_email).first()
        if admin:
            print(f"ℹ️  Administrator with email {admin_email} already exist.")
            return

        hashed_password = get_password_hash(admin_password)
        new_admin = models.User(
            username="admin",
            email=admin_email,
            hashed_password=hashed_password,
            is_verified=True,
            is_active=True,
            role=UserRole.admin,
        )
        db.add(new_admin)
        db.commit()
        print(f"✅ Administrator {admin_email} is registered.")

    finally:
        db.close()


if __name__ == "__main__":
    create_admin()
