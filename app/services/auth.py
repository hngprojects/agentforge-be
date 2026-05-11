import uuid
from datetime import UTC, datetime
from ipaddress import ip_address as parse_ip_address
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_password_reset_jwt,
    decode_password_reset_jwt,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)
from app.models.enums import UserProvider
from app.models.refresh_token import RefreshToken
from app.models.user import User

_DUMMY_PASSWORD_HASH = hash_password("not-the-password")
_MAX_USER_AGENT_LENGTH = 512
REFRESH_TOKEN_COOKIE = "refresh_token"
REFRESH_TOKEN_COOKIE_PATH = "/api"
REFRESH_TOKEN_COOKIE_MAX_AGE = settings.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60


def set_refresh_token_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        max_age=REFRESH_TOKEN_COOKIE_MAX_AGE,
        path=REFRESH_TOKEN_COOKIE_PATH,
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )


def clear_refresh_token_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE,
        path=REFRESH_TOKEN_COOKIE_PATH,
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_google_subject(
    db: AsyncSession,
    subject: str,
) -> User | None:
    result = await db.execute(select(User).where(User.google_subject == subject))
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
        email_verified=True,  # TODO: change to send real email
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def get_or_create_github_user(
    db: AsyncSession,
    *,
    email: str,
    display_name: str | None,
    avatar_url: str | None,
    github_username: str | None,
) -> User:
    email = email.lower()
    user = await get_user_by_email(db, email)
    if user:
        if user.provider != UserProvider.GITHUB:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "An account with this email already exists. "
                    "Sign in with the existing provider and link GitHub "
                    "from account settings."
                ),
            )
        user.email_verified = True
        if github_username:
            user.github_username = github_username
        if not user.avatar_url and avatar_url:
            user.avatar_url = avatar_url
        await db.commit()
        await db.refresh(user)
        return user

    user = User(
        email=email,
        display_name=display_name,
        avatar_url=avatar_url,
        provider=UserProvider.GITHUB,
        email_verified=True,
        github_username=github_username,
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

    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email before logging in",
        )

    return await issue_auth_tokens(db, user, request)


async def issue_auth_tokens(
    db: AsyncSession,
    user: User,
    request: Request,
) -> tuple[str, str]:
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
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

    record.revoked = True  # type: ignore[union-attr]

    user = await get_user_by_id(db, record.user_id)  # type: ignore[union-attr]
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    if not user.is_active:
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
    record.revoked = True  # type: ignore[union-attr]
    await db.commit()

    return access_token, raw_refresh


def build_google_auth_url(state: str) -> str:
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": settings.GOOGLE_SCOPES.strip(),
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{settings.GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_google_code(code: str) -> dict[str, Any]:
    data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            settings.GOOGLE_TOKEN_URL,
            data=data,
            headers={"Accept": "application/json"},
        )
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Google token exchange failed",
        )
    return response.json()


async def fetch_google_userinfo(access_token: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(
            settings.GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Google userinfo request failed",
        )
    return response.json()


async def login_or_register_google_user(
    db: AsyncSession,
    profile: dict[str, Any],
    request: Request,
) -> tuple[str, str, User]:
    subject = profile.get("sub")
    email = profile.get("email")
    if not subject or not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google profile missing required fields",
        )
    email = str(email).lower()
    google_verified = bool(profile.get("email_verified"))

    user = await get_user_by_google_subject(db, str(subject))
    if user is None:
        user = await get_user_by_email(db, email)
        if user is not None:
            _apply_google_profile(user, subject, profile, google_verified)
        else:
            user = User(
                email=email,
                display_name=profile.get("name") or None,
                avatar_url=profile.get("picture") or None,
                provider=UserProvider.GOOGLE,
                email_verified=google_verified,
                is_active=True,
                google_subject=str(subject),
            )
            db.add(user)
        try:
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()
            user = await get_user_by_google_subject(db, str(subject))
            if user is None:
                user = await get_user_by_email(db, email)
            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Account already exists",
                ) from exc
            _apply_google_profile(user, subject, profile, google_verified)
            try:
                await db.commit()
            except IntegrityError as exc:
                await db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Account already exists",
                ) from exc
        await db.refresh(user)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
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

    return access_token, raw_refresh, user


def _apply_google_profile(
    user: User,
    subject: str,
    profile: dict[str, Any],
    google_verified: bool,
) -> None:
    if user.google_subject and user.google_subject != subject:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Google account already linked",
        )
    user.google_subject = str(subject)
    if user.provider != UserProvider.GOOGLE:
        user.provider = UserProvider.GOOGLE
    if profile.get("name") and not user.display_name:
        user.display_name = str(profile.get("name"))
    if profile.get("picture") and not user.avatar_url:
        user.avatar_url = str(profile.get("picture"))
    if google_verified:
        user.email_verified = True


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

    if (
        user is None
        or user.provider != UserProvider.EMAIL
        or user.password_hash is None
    ):
        return None

    return create_password_reset_jwt(str(user.id), user.password_hash)


async def reset_password(db: AsyncSession, raw_token: str, new_password: str) -> bool:
    # Phase 1: decode JWT structure only to extract user_id (no hash check yet).
    payload = decode_password_reset_jwt(raw_token)
    if payload is None:
        return False

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        return False

    user = await get_user_by_id(db, user_id)
    if user is None or user.provider != UserProvider.EMAIL or not user.password_hash:
        return False

    # Phase 2: full validation — confirm the stored hash still matches the token.
    # Any password change rotates the hash, instantly invalidating prior tokens.
    if decode_password_reset_jwt(raw_token, user.password_hash) is None:
        return False

    user.password_hash = hash_password(new_password)

    # Revoke active sessions so stolen refresh tokens can't outlive a password reset.
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False))
        .values(revoked=True)
    )

    await db.commit()
    return True
