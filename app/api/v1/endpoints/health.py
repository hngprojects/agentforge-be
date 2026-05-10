from fastapi import APIRouter
from sqlalchemy import text

from app.api.deps import DBSession
from app.schemas.response import ResponseEnvelope

router = APIRouter()


@router.get("/health", response_model=ResponseEnvelope[dict[str, str]])
async def health(db: DBSession) -> ResponseEnvelope[dict[str, str]]:
    await db.execute(text("SELECT 1"))
    return ResponseEnvelope(data={"status": "ok"})
