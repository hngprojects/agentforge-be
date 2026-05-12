from fastapi import APIRouter

from app.api.v1.endpoints import agents, auth, health, contact

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(agents.router, prefix="/agents", tags=["agents"])
api_router.include_router(contact.router, prefix="/contact", tags=["contact"])
