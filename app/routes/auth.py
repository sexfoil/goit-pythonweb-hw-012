import os
from datetime import datetime, timedelta, UTC
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Depends, status, Form
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from typing import Optional
from urllib.parse import urlencode
from ..repository import models, schemas
from ..repository.database import get_db
from ..security.utils import require_admin_user, require_admin_user_from_cookie
from ..utils.email_utils import send_verification_email, send_reset_password_email
from ..utils.enums import UserRole
from ..cache.redis_cache import get_redis_client

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
ACCESS_TOKEN_EXPIRE_DAYS = int(os.getenv("ACCESS_TOKEN_EXPIRE_DAYS"))


templates = Jinja2Templates(directory="templates")

router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """
    Hashes the provided password using bcrypt.

    Args:
        password (str): The plain text password.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies that a plain password matches the hashed password.

    Args:
        plain_password (str): The plain text password.
        hashed_password (str): The hashed password to compare against.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a JWT access token.

    Args:
        data (dict): The data to include in the token payload.
        expires_delta (Optional[timedelta]): The token expiration time.

    Returns:
        str: The generated JWT token.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=15)
    to_encode.update({"exp": expire, "iat": datetime.now(UTC).timestamp()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a JWT refresh token.

    Args:
        data (dict): The data to include in the token payload.
        expires_delta (Optional[timedelta]): The token expiration time.

    Returns:
        str: The generated JWT refresh token.
    """
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire, "iat": datetime.now(UTC).timestamp()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(db: Session, email: str, password: str):
    """
    Authenticates a user by verifying email and password.

    Args:
        db (Session): SQLAlchemy session for database access.
        email (str): The user's email.
        password (str): The user's password.

    Returns:
        User or None: The authenticated user or None if authentication fails.
    """
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def create_verification_token(email: str) -> str:
    """
    Creates a JWT token for email verification.

    Args:
        email (str): The email address to verify.

    Returns:
        str: The generated verification token.
    """
    expire = datetime.now(UTC) + timedelta(hours=24)
    data = {"sub": email, "exp": expire}
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


@router.get("/change-role-form", response_class=HTMLResponse)
def get_change_role_form(
    request: Request,
    message: str = "",
    error: str = "",
    current_user: schemas.UserResponse = Depends(require_admin_user_from_cookie),
):
    """
    Renders the HTML form for changing a user's role.

    Args:
        request (Request): The incoming HTTP request.
        message (str): Optional success message to display.
        error (str): Optional error message to display.
        current_user (UserResponse): The currently authenticated admin user.

    Returns:
        HTMLResponse: The rendered change-role form.
    """
    return templates.TemplateResponse(
        "change_role_form.html",
        {"request": request, "message": message, "error": error},
    )


@router.post("/change-role", response_class=HTMLResponse)
def change_user_role(
    email: str = Form(...),
    new_role: UserRole = Form(...),
    db: Session = Depends(get_db),
    current_user: schemas.UserResponse = Depends(require_admin_user_from_cookie),
):
    """
    Handles form submission to change a user's role.

    Args:
        email (str): The target user's email.
        new_role (UserRole): The new role to assign.
        db (Session): The database session.
        current_user (UserResponse): The currently authenticated admin user.

    Returns:
        HTMLResponse: Redirects to the change-role form with a message.
    """
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        params = urlencode({"error": f"User with email '{email}' not found"})
        return RedirectResponse(url=f"/auth/change-role-form?{params}", status_code=303)

    user.role = new_role
    db.commit()

    params = urlencode(
        {"message": f"Role updated to {new_role.value} for user {user.email}"}
    )
    return RedirectResponse(url=f"/auth/change-role-form?{params}", status_code=303)


@router.post("/request-password-reset", status_code=200)
def request_password_reset(email: str, db: Session = Depends(get_db)):
    """
    Handles password reset request by generating a token and sending it via email.

    Args:
        email (str): The user's email address.
        db (Session): SQLAlchemy session for database access.

    Returns:
        dict: Success message.

    Raises:
        HTTPException: If the email is not found.
    """
    user: models.User | None = (
        db.query(models.User).filter(models.User.email == email).first()
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reset_token_expiration = datetime.now(UTC) + timedelta(hours=1)
    reset_token = jwt.encode(
        {"sub": user.email, "exp": reset_token_expiration},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    send_reset_password_email(user.email, reset_token)

    return {"message": "Password reset email sent successfully."}


@router.get("/reset-password", response_class=HTMLResponse)
def get_reset_password_form(request: Request, token: str):
    """
    Renders a simple HTML form to reset the password.
    """
    return templates.TemplateResponse(
        "reset_password_form.html", {"request": request, "token": token}
    )


@router.post("/reset-password", status_code=200)
def reset_password(
    token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)
):
    """
    Resets the user's password using a valid reset token.

    Args:
        token (str): The reset token sent via email.
        new_password (str): The new password to set.
        db (Session): SQLAlchemy session for database access.

    Returns:
        dict: A success message.

    Raises:
        HTTPException: If the token is invalid or the user is not found.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token")

        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.hashed_password = get_password_hash(new_password)
        user.last_password_reset = datetime.now(UTC)
        db.commit()

        redis_client = get_redis_client()
        redis_key = f"user:{user.email}"
        redis_client.delete(redis_key)

        return {"message": "Password reset successful."}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")


@router.post(
    "/register",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Registers a new user and sends a verification email.

    Args:
        user (UserCreate): The user registration data.
        db (Session): SQLAlchemy session for database access.

    Returns:
        UserResponse: The registered user data.

    Raises:
        HTTPException: If the email is already registered.
    """
    existing_user = (
        db.query(models.User).filter(models.User.email == user.email).first()
    )
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")

    verification_token = create_verification_token(user.email)
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        verification_token=verification_token,
        is_verified=False,
        is_active=True,
        role=UserRole.user,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    send_verification_email(user.email, verification_token)

    return db_user


@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """
    Verifies a user's email address using a JWT token.

    Args:
        token (str): The verification token.
        db (Session): SQLAlchemy session for database access.

    Returns:
        dict: A success message if verification succeeds.

    Raises:
        HTTPException: If the token is invalid or the user is already verified.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token")

        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if user.is_verified:
            raise HTTPException(status_code=400, detail="User already verified")

        user.is_verified = True
        user.verification_token = None
        db.commit()

        return {"message": "Email successfully verified!"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token or expired link")


@router.post("/login", response_model=schemas.Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    """
    Authenticates a user and returns a JWT access token.

    Args:
        form_data (OAuth2PasswordRequestForm): The login credentials.
        db (Session): SQLAlchemy session for database access.

    Returns:
        dict: The access token and token type.

    Raises:
        HTTPException: If authentication fails.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    refresh_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    refresh_token = create_refresh_token(
        data={"sub": user.email}, expires_delta=refresh_token_expires
    )
    expires_at = datetime.now(UTC) + refresh_token_expires
    db_token = models.RefreshToken(
        token=refresh_token, user_id=user.id, expires_at=expires_at
    )
    db.add(db_token)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh-token")
def refresh_access_token(refresh_token: str = Form(...), db: Session = Depends(get_db)):
    """
    Generates a new access token using a valid refresh token stored in the database.

    Args:
        refresh_token (str): The refresh token.
        db (Session): The database session.

    Returns:
        dict: A new access token and token type.

    Raises:
        HTTPException: If the refresh token is invalid, expired, or not found.
    """
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token")

        # Validate token in DB
        token_in_db = (
            db.query(models.RefreshToken)
            .filter(models.RefreshToken.token == refresh_token)
            .first()
        )
        if not token_in_db or token_in_db.expires_at < datetime.now(UTC):
            raise HTTPException(
                status_code=401, detail="Refresh token is invalid or expired"
            )

        new_access_token = create_access_token(data={"sub": email})
        return {
            "access_token": new_access_token,
            "token_type": "bearer",
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
