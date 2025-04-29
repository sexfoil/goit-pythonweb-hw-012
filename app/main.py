import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from .services import crud
from .repository import models, schemas
from .routes.auth import get_current_user
from .routes.auth import router as auth_router
from .services.cloudinary import upload_avatar
from .repository.database import engine, get_db


load_dotenv()

FRONTEND_URL = os.getenv("FRONTEND_URL")

app = FastAPI()

origins = [
    "http://localhost:3000",
    "http://localhost:8000",
    FRONTEND_URL,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=engine)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

app.include_router(auth_router)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests. Please try again later."},
    )


@app.get("/me")
@limiter.limit("5/minute")
async def read_users_me(
    request: Request, current_user: schemas.UserResponse = Depends(get_current_user)
):
    return current_user


@app.post("/upload-avatar", response_model=schemas.UserResponse)
async def upload_avatar_route(
    file: UploadFile = File(...),
    current_user: schemas.UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    file_path = f"temp_{file.filename}"
    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())

    avatar_url = upload_avatar(file_path, public_id=str(current_user.id))

    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    user.avatar_url = avatar_url
    db.commit()
    db.refresh(user)

    os.remove(file_path)

    return user


@app.post("/contacts/", response_model=schemas.ContactResponse, status_code=201)
def create_contact(
    contact: schemas.ContactCreate,
    db: Session = Depends(get_db),
    current_user: schemas.UserResponse = Depends(get_current_user),
):
    return crud.create_contact(db, contact)


@app.get("/contacts/", response_model=list[schemas.ContactResponse])
def get_contacts(
    db: Session = Depends(get_db),
    current_user: schemas.UserResponse = Depends(get_current_user),
):
    return crud.get_contacts(db)


@app.get("/contacts/{contact_id}", response_model=schemas.ContactResponse)
def get_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.UserResponse = Depends(get_current_user),
):
    contact = crud.get_contact_by_id(db, contact_id)
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


@app.put("/contacts/{contact_id}", response_model=schemas.ContactResponse)
def update_contact(
    contact_id: int,
    contact: schemas.ContactUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.UserResponse = Depends(get_current_user),
):
    updated_contact = crud.update_contact(db, contact_id, contact)
    if not updated_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return updated_contact


@app.delete("/contacts/{contact_id}", response_model=schemas.ContactResponse)
def delete_contact(
    contact_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.UserResponse = Depends(get_current_user),
):
    deleted_contact = crud.delete_contact(db, contact_id)
    if not deleted_contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return deleted_contact


@app.get("/search/")
def search_contacts(
    query: str,
    db: Session = Depends(get_db),
    current_user: schemas.UserResponse = Depends(get_current_user),
):
    return crud.search_contacts(db, query)


@app.get("/birthdays/")
def get_upcoming_birthdays(
    db: Session = Depends(get_db),
    current_user: schemas.UserResponse = Depends(get_current_user),
):
    return crud.get_upcoming_birthdays(db)
