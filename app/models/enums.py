import enum


class UserProvider(enum.StrEnum):
    EMAIL = "email"
    GOOGLE = "google"
    GITHUB = "github"


class UserPlan(enum.StrEnum):
    FREE = "free"
    PAID = "paid"


class AgentCategory(enum.StrEnum):
    MARKETING = "marketing"
    DEVELOPMENT = "development"
    RESEARCH = "research"
    FINANCE = "finance"


class AgentVisibility(enum.StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


class AgentStatus(enum.StrEnum):
    DRAFT = "draft"
    NEEDS_CLARIFICATION = "needs_clarification"
    GENERATED = "generated"
    PUBLISHED = "published"
    FAILED = "failed"


class SkillSourceRegistry(enum.StrEnum):
    SKILLS_SH = "skills.sh"
    OPENCLAW = "openclaw"
    AGENTFORGE = "agentforge"
