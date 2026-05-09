import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import HTTPException, status
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

from app.core.config import settings

pwd_hash = PasswordHash.recommended()

_ALGORITHM = settings.JWT_ALGORITHM
_SECRET = settings.JWT_SECRET
_REFRESH_TOKEN_BYTES = 64


def hash_password(password: str) -> str:
    return pwd_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_hash.verify(password, password_hash)
    except UnknownHashError:
        return False


def generate_refresh_token() -> str:
    """Return a URL-safe random string suitable for use as a refresh token."""
    return secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def refresh_token_expiry() -> datetime:
    return datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_TTL_DAYS)


def create_token(payload: dict[str, Any], expires: timedelta) -> str:
    """Sign a JWT with an expiry. Caller supplies all claims except `iat`/`exp`."""
    now = datetime.now(UTC)
    data = {**payload, "iat": now, "exp": now + expires}
    return jwt.encode(data, _SECRET, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises HTTP 401 on any failure."""
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            leeway=30,
            options={"require": ["exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def create_access_token(user_id: str) -> str:
    return create_token(
        {"sub": user_id, "purpose": "access"},
        timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES),
    )


def create_verification_token(email: str) -> str:
    return create_token(
        {"sub": email, "purpose": "email_verify"},
        timedelta(hours=settings.VERIFICATION_TOKEN_TTL_HOURS),
    )


def create_oauth_state_token() -> str:
    """Short-lived state token to prevent CSRF in OAuth flows."""
    return create_token({"purpose": "oauth_state"}, timedelta(minutes=10))


def create_password_reset_jwt(user_id: str, password_hash: str) -> str:
    return create_token(
        {"sub": user_id, "purpose": "password_reset", "password_hash": password_hash},
        timedelta(minutes=settings.PASSWORD_RESET_TOKEN_TTL_MINUTES),
    )


def decode_password_reset_jwt(
    token: str, current_password_hash: str | None = None
) -> dict[str, Any] | None:
    """Return payload for a valid password-reset JWT, else None.

    When current_password_hash is supplied, also verifies that the hash embedded
    in the token matches — rejecting any token issued before a password change.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            leeway=30,
            options={"require": ["exp"]},
        )
        if payload.get("purpose") != "password_reset":
            return None
        if (
            current_password_hash is not None
            and payload.get("password_hash") != current_password_hash
        ):
            return None
        return payload
    except jwt.InvalidTokenError:
        return None
