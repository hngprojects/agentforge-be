import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.agent import Agent


# separate table to store generated files for agents
# to support multiple files per agent and also to keep the agent table clean
class AgentFile(BaseModel):
    __tablename__ = "agent_files"

    __table_args__ = (
        UniqueConstraint("agent_id", "path", name="uq_agent_file_path"),
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)

    agent: Mapped["Agent"] = relationship(back_populates="files")