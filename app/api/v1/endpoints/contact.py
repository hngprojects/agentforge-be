import logging
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.models.contact import ContactMessage
from app.schemas.auth import MessageResponse
from app.schemas.contact import ContactCreate, ContactResponse
from app.services.email import send_contact_admin_notification

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/contact", tags=["Contact"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


@router.post("/", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def submit_contact(
    payload: ContactCreate,
    db: DBSession,
    background_tasks: BackgroundTasks,
):
    contact = ContactMessage(**payload.model_dump())
    db.add(contact)
    await db.commit()
    await db.refresh(contact)
    try:
        background_tasks.add_task(
            send_contact_admin_notification,
            full_name=contact.full_name,
            email=contact.email,
            phone=contact.phone,
            message=contact.message,
        )
    except Exception:
        logger.exception("Admin notification failed for contact id=%s", contact.id)

    return MessageResponse(
        message="Your message has been received. We'll get back to you shortly."
    )


@router.get("/", response_model=list[ContactResponse])
async def get_all_contacts(db: DBSession):
    result = await db.execute(
        select(ContactMessage).order_by(ContactMessage.created_at.desc())
    )
    return result.scalars().all()
