from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class ClarificationAnswer(BaseModel):
    question: str
    answer: str


class GenerateAgentRequest(BaseModel):
    description: str = Field(..., min_length=10, max_length=2000)
    clarifications: list[ClarificationAnswer] = Field(default_factory=list)


class SkillResponse(BaseModel):
    name: str
    slug: str
    description: str


class GeneratedAgentResponse(BaseModel):
    status: Literal["complete"]
    agent_id: UUID
    name: str
    category: str
    description_summary: str
    files: dict[str, str]
    skills: list[SkillResponse]
    generated_at: datetime


class ClarificationResponse(BaseModel):
    status: Literal["needs_clarification"]
    questions: list[str]


GenerateAgentResponse = ClarificationResponse | GeneratedAgentResponse
