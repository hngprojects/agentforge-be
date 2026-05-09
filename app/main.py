from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import settings
from app.schemas.auth import MessageResponse
from app.schemas.response import ResponseEnvelope

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", response_model=ResponseEnvelope[MessageResponse])
def root() -> ResponseEnvelope[MessageResponse]:
    message = f"{settings.PROJECT_NAME} is running"
    return ResponseEnvelope(message=message, data=MessageResponse(message=message))
