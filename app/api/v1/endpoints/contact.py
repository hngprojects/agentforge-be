from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session
from app.schemas.contact import ContactCreate, ContactResponse
from app.services.contact import create_contact_message

router = APIRouter()


@router.post(
    "/contact",
    response_model=ContactResponse,
    status_code=status.HTTP_201_CREATED,
)
async def submit_contact_form(
    payload: ContactCreate,
    db: Annotated[AsyncSession, Depends(get_session)],
) -> ContactResponse:
    await create_contact_message(db=db, payload=payload)

    return ContactResponse(
        success="success",
        message="Message submitted successfully",
    )
