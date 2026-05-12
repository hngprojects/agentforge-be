import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import AgentCategory, AgentStatus, AgentVisibility

if TYPE_CHECKING:
    from app.models.agent_skill import AgentSkill
    from app.models.user import User
    from app.models.agent_clarification import AgentClarification
    from app.models.agent_file import AgentFile


class Agent(BaseModel):
    __tablename__ = "agents"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(220), nullable=False, unique=True)
    category: Mapped[AgentCategory] = mapped_column(String(50), nullable=False)
    description_summary: Mapped[str] = mapped_column(Text, nullable=False)
    visibility: Mapped[AgentVisibility] = mapped_column(String(10), nullable=False)
    status: Mapped[AgentStatus] = mapped_column(
        String(30),
        nullable=False,
        default=AgentStatus.DRAFT,
        server_default=AgentStatus.DRAFT,
    )
    clarification_rounds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    github_repo_url: Mapped[str | None] = mapped_column(Text)
    github_clone_url: Mapped[str | None] = mapped_column(Text)
    github_zip_url: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # relationships
    user: Mapped["User"] = relationship(back_populates="agents")
    agent_skills: Mapped[list["AgentSkill"]] = relationship(
        back_populates="agent",
        cascade="all, delete-orphan",
    )
    clarifications: Mapped[list["AgentClarification"]] = relationship(
        back_populates="agent",
        cascade="all, delete-orphan",
    )
    files: Mapped[list["AgentFile"]] = relationship(
        back_populates="agent",
        cascade="all, delete-orphan",
    )
