from uuid import UUID

from app.models.user import User
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session
from app.schemas.generation import GenerateAgentRequest, GenerateAgentResponse
from app.services.generation_service import GenerationService
from app.api.deps import get_current_user


router = APIRouter()


@router.post("/generate", response_model=GenerateAgentResponse)
async def generate_agent(
    payload: GenerateAgentRequest,
    db: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> GenerateAgentResponse:
    service = GenerationService(db)

    return await service.generate(payload, user_id=current_user.id)
