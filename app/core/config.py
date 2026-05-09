from functools import lru_cache

from pydantic import PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "fastapi-starter"
    API_V1_PREFIX: str = "/api/v1"

    DATABASE_URL: PostgresDsn

    # JWT
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"

    @field_validator("JWT_SECRET")
    @classmethod
    def jwt_secret_min_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        return v

    ACCESS_TOKEN_TTL_MINUTES: int = 60
    VERIFICATION_TOKEN_TTL_HOURS: int = 24
    REFRESH_TOKEN_TTL_DAYS: int = 7
    TRUSTED_PROXIES: str = ""

    # Frontend (used in email links)
    FRONTEND_URL: str = "http://localhost:3000"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
