from functools import lru_cache

from pydantic import PostgresDsn, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "agentforge-be"
    API_V1_PREFIX: str = "/api/v1"

    DATABASE_URL: PostgresDsn

    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_TTL_MINUTES: int = 60
    VERIFICATION_TOKEN_TTL_HOURS: int = 24
    REFRESH_TOKEN_TTL_DAYS: int = 7
    TRUSTED_PROXIES: str = ""
    COOKIE_SECURE: bool = False

    # GitHub OAuth
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: SecretStr = SecretStr("")
    GITHUB_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/github/callback"

    # Frontend (used in email links)
    FRONTEND_URL: str = "http://localhost:3000"

    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = {
        "https://staging.agent-forge.hng14.com/auth/callback/google"
    }
    GOOGLE_AUTH_URL: str = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL: str = "https://oauth2.googleapis.com/token"
    GOOGLE_USERINFO_URL: str = "https://openidconnect.googleapis.com/v1/userinfo"
    GOOGLE_SCOPES: str = "openid email profile"

    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = 60

    BREVO_API_KEY: str
    SMTP_FROM_NAME: str = "Agent Forge"
    SMTP_FROM_EMAIL: str


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
