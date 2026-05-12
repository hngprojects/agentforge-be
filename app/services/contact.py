from sqlalchemy.ext.asyncio import AsyncSession

from app.models.contact import ContactMessage
from app.schemas.contact import ContactCreate


async def create_contact_message(
    db: AsyncSession,
    payload: ContactCreate,
) -> ContactMessage:
    contact_message = ContactMessage(
        fullname=payload.fullname,
        email=payload.email,
        phone_number=payload.phone_number,
        message=payload.message,
    )

    db.add(contact_message)

    await db.commit()

    await db.refresh(contact_message)

    return contact_message
