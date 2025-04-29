from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from ..repository import models, schemas


def create_contact(db: Session, contact: schemas.ContactCreate):
    db_contact = models.Contact(**contact.model_dump())
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact


def get_contacts(db: Session):
    return db.query(models.Contact).all()


def get_contact_by_id(db: Session, contact_id: int):
    return db.query(models.Contact).filter(models.Contact.id == contact_id).first()


def update_contact(db: Session, contact_id: int, contact_update: schemas.ContactUpdate):
    db_contact = get_contact_by_id(db, contact_id)
    if db_contact:
        for key, value in contact_update.model_dump(exclude_unset=True).items():
            setattr(db_contact, key, value)
        db.commit()
        db.refresh(db_contact)
    return db_contact


def delete_contact(db: Session, contact_id: int):
    db_contact = get_contact_by_id(db, contact_id)
    if db_contact:
        db.delete(db_contact)
        db.commit()
    return db_contact


def search_contacts(db: Session, query: str):
    return (
        db.query(models.Contact)
        .filter(
            (models.Contact.first_name.ilike(f"%{query}%"))
            | (models.Contact.last_name.ilike(f"%{query}%"))
            | (models.Contact.email.ilike(f"%{query}%"))
        )
        .all()
    )


def get_upcoming_birthdays(db: Session):
    today = datetime.today().date()
    next_week = today + timedelta(days=7)

    contacts = db.query(models.Contact).all()

    upcoming_birthdays = []
    for contact in contacts:
        if contact.birthday:
            birthday_this_year = contact.birthday.replace(year=today.year)

            if today <= birthday_this_year <= next_week:
                upcoming_birthdays.append(contact)

    return upcoming_birthdays
