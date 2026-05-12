from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent import Agent
from app.models.agent_clarification import AgentClarification
from app.models.agent_file import AgentFile
from app.models.enums import AgentStatus, AgentVisibility
from app.schemas.generation import (
    ClarificationResponse,
    GenerateAgentRequest,
    GeneratedAgentResponse,
)
from app.services.clarification_service import ClarificationService


class GenerationService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.clarification_service = ClarificationService()

    async def generate(
        self,
        payload: GenerateAgentRequest,
        user_id: UUID,
    ) -> ClarificationResponse | GeneratedAgentResponse:
        questions = self.clarification_service.get_questions(
            description=payload.description,
            clarifications=payload.clarifications,
        )

        if questions:
            return ClarificationResponse(
                status="needs_clarification",
                questions=questions,
            )

        # TODO: implement AI generation logic for now its mock
        draft = self._mock_generate_agent(payload)
        files = self._assemble_files(draft)

        agent = Agent(
            user_id=user_id,
            name=draft["name"],
            slug=self._slugify(draft["name"]),
            category=draft["category"],
            description_summary=draft["description_summary"],
            visibility=AgentVisibility.PUBLIC,
            status=AgentStatus.GENERATED,
            clarification_rounds=len(payload.clarifications),
        )

        self.db.add(agent)
        await self.db.flush()

        for path, content in files.items():
            self.db.add(
                AgentFile(
                    agent_id=agent.id,
                    path=path,
                    content=content,
                )
            )

        for item in payload.clarifications:
            self.db.add(
                AgentClarification(
                    agent_id=agent.id,
                    question=item.question,
                    answer=item.answer,
                )
            )

        await self.db.commit()
        await self.db.refresh(agent)

        return GeneratedAgentResponse(
            status="complete",
            agent_id=UUID(str(agent.id)),
            name=agent.name,
            category=str(agent.category),
            description_summary=agent.description_summary,
            files=files,
            skills=[],
            generated_at=datetime.now(UTC),
        )

    def _assemble_files(self, draft: dict) -> dict[str, str]:
        return {
            "identity.md": draft["identity"],
            "soul.md": draft["soul"],
            "dna.md": draft["dna"],
            "heartbeat.md": draft["heartbeat"],
            "README.md": f"""# {draft["name"]}

## Overview

{draft["description_summary"]}

## Category

{draft["category"]}

## Files

- identity.md
- soul.md
- dna.md
- heartbeat.md
- README.md
""",
        }

    def _mock_generate_agent(self, payload: GenerateAgentRequest) -> dict:
        full_context = self._build_context(payload)
        category = self._detect_category(full_context)
        name = self._build_agent_name(category)

        return {
            "name": name,
            "category": category,
            "description_summary": f"An AI agent designed to support users with {category}-focused tasks.",
            "identity": f"""# Identity

{name} is a focused AI agent created from the user's description.

It helps users solve {category}-related problems by giving clear, practical, and structured support.
""",
            "soul": """# Soul

This agent communicates clearly, stays helpful, avoids unnecessary complexity, and adapts to the user's level of understanding.
""",
            "dna": """# DNA

- Be practical
- Be reliable
- Ask for clarity when needed
- Give structured guidance
- Avoid unsupported assumptions
""",
            "heartbeat": """# Heartbeat

The agent works by understanding the user's goal, breaking it into steps, and guiding the user toward a usable outcome.
""",
            "skills_keywords": [category],
        }

    def _build_context(self, payload: GenerateAgentRequest) -> str:
        clarification_text = " ".join(
            f"{item.question} {item.answer}" for item in payload.clarifications
        )
        return f"{payload.description} {clarification_text}".lower()

    def _detect_category(self, text: str) -> str:
        if any(word in text for word in ["marketing", "sales", "growth", "seo"]):
            return "marketing"

        if any(word in text for word in ["code", "api", "software", "developer"]):
            return "development"

        if any(word in text for word in ["research", "academic", "study"]):
            return "research"

        return "business"

    def _build_agent_name(self, category: str) -> str:
        names = {
            "marketing": "GrowthPilot Agent",
            "development": "DevHelper Agent",
            "research": "ResearchMate Agent",
            "business": "StrategyMentor Agent",
        }
        return names.get(category, "AgentForge Assistant")

    def _slugify(self, text: str) -> str:
        return (
            text.lower()
            .replace(" ", "-")
            .replace("_", "-")
        )