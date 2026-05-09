import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.skill import Skill


class AgentSkill(BaseModel):
    __tablename__ = "agent_skills"

    __table_args__ = (UniqueConstraint("agent_id", "skill_id", name="uq_agent_skill"),)

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
    )
    skill_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("skills.id"),
        nullable=False,
    )

    # relationships
    agent: Mapped["Agent"] = relationship(back_populates="agent_skills")
    skill: Mapped["Skill"] = relationship(back_populates="agent_skills")
