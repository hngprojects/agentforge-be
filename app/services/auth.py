import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address as parse_ip_address

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)
from app.models.enums import UserProvider
from app.models.password_reset_token import PasswordResetToken
from app.models.refresh_token import RefreshToken
from app.models.user import User

_DUMMY_PASSWORD_HASH = hash_password("not-the-password")
_MAX_USER_AGENT_LENGTH = 512


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def register_user(
    db: AsyncSession,
    email: str,
    password: str,
    display_name: str | None = None,
) -> User:
    email = email.lower()

    existing = await get_user_by_email(db, email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = User(
        email=email,
        display_name=display_name,
        password_hash=hash_password(password),
        provider=UserProvider.EMAIL,
        email_verified=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def login_user(
    db: AsyncSession,
    email: str,
    password: str,
    request: Request,
) -> tuple[str, str]:
    user = await get_user_by_email(db, email.lower())

    stored_hash = (
        user.password_hash if user and user.password_hash else _DUMMY_PASSWORD_HASH
    )

    if (
        not verify_password(password, stored_hash)
        or user is None
        or not user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email before logging in",
        )

    access_token = create_access_token(str(user.id))
    user_agent, ip_address = _refresh_token_context(request)
    raw_refresh, _ = await _create_refresh_token(
        db,
        user,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    await db.commit()

    return access_token, raw_refresh


async def logout_user(db: AsyncSession, raw_token: str) -> None:
    token_hash = hash_refresh_token(raw_token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    record = result.scalar_one_or_none()
    if record and not record.revoked:
        record.revoked = True
        await db.commit()


async def rotate_refresh_token(
    db: AsyncSession,
    raw_token: str,
    request: Request,
) -> tuple[str, str]:
    token_hash = hash_refresh_token(raw_token)

    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    record = result.scalar_one_or_none()

    _validate_refresh_record(record)

    record.revoked = True  # type: ignore

    user = await get_user_by_id(db, record.user_id)  # type: ignore[union-attr]
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access_token = create_access_token(str(user.id))
    user_agent, ip_address = _refresh_token_context(request)
    raw_refresh, _ = await _create_refresh_token(
        db,
        user,
        user_agent=user_agent,
        ip_address=ip_address,
    )
    await db.commit()

    return access_token, raw_refresh


def _validate_refresh_record(record: RefreshToken | None) -> None:
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found",
        )
    if record.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )
    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    else:
        expires_at = expires_at.astimezone(UTC)

    if expires_at < datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )


async def _create_refresh_token(
    db: AsyncSession,
    user: User,
    *,
    user_agent: str | None,
    ip_address: str | None,
) -> tuple[str, RefreshToken]:
    raw = generate_refresh_token()
    record = RefreshToken(
        token_hash=hash_refresh_token(raw),
        user_id=user.id,
        expires_at=refresh_token_expiry(),
        user_agent=user_agent,
        ip_address=ip_address,
    )
    db.add(record)
    return raw, record


def _refresh_token_context(request: Request) -> tuple[str | None, str | None]:
    client_host = _valid_ip_address(request.client.host if request.client else None)
    forwarded_for = request.headers.get("x-forwarded-for")

    if forwarded_for and client_host in _trusted_proxies():
        forwarded_ip = _valid_ip_address(forwarded_for.split(",", 1)[0].strip())
        ip_address = forwarded_ip or client_host
    else:
        ip_address = client_host

    return _bounded_header(request.headers.get("user-agent")), ip_address


def _trusted_proxies() -> set[str]:
    return {
        proxy
        for proxy in (
            _valid_ip_address(value.strip())
            for value in settings.TRUSTED_PROXIES.split(",")
        )
        if proxy is not None
    }


def _valid_ip_address(value: str | None) -> str | None:
    if not value or len(value) > 45:
        return None
    try:
        return str(parse_ip_address(value))
    except ValueError:
        return None


def _bounded_header(value: str | None) -> str | None:
    if not value:
        return None
    return value[:_MAX_USER_AGENT_LENGTH]


async def create_password_reset_token(db: AsyncSession, email: str) -> str | None:
    result = await db.execute(select(User).where(User.email == email.lower()))
    user = result.scalar_one_or_none()

    if user is None or user.provider != UserProvider.EMAIL:
        return None

    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    expires_at = datetime.now(UTC) + timedelta(
        minutes=settings.PASSWORD_RESET_TOKEN_TTL_MINUTES
    )
    record = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(record)
    await db.commit()
    return raw


async def reset_password(db: AsyncSession, raw_token: str, new_password: str) -> bool:
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )
    token = result.scalar_one_or_none()

    if token is None:
        return False
    if token.used_at is not None:
        return False

    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    else:
        expires_at = expires_at.astimezone(UTC)
    if expires_at < datetime.now(UTC):
        return False

    user = await get_user_by_id(db, token.user_id)
    if user is None:
        return False

    user.password_hash = hash_password(new_password)
    token.used_at = datetime.now(UTC)
    await db.commit()
    return True
