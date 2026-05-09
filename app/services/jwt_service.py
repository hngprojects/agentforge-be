from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from app.core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# In-memory revocation store — intentionally process-local.
# For multi-worker deployments, replace with a shared cache (e.g. Redis).
_revoked_jtis: set[str] = set()

_TOKEN_TYPE_ACCESS = "access"
_TOKEN_TYPE_REFRESH = "refresh"


def issue_access_token(payload: dict) -> str:
    claims = payload.copy()
    claims["jti"] = str(uuid4())
    claims["type"] = _TOKEN_TYPE_ACCESS
    claims["exp"] = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_TTL_MINUTES
    )
    return jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def issue_refresh_token(payload: dict) -> str:
    claims = payload.copy()
    claims["jti"] = str(uuid4())
    claims["type"] = _TOKEN_TYPE_REFRESH
    claims["exp"] = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_TTL_DAYS
    )
    return jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str, *, expected_type: str = _TOKEN_TYPE_ACCESS) -> dict:
    try:
        claims = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
    if claims.get("type") != expected_type:
        raise HTTPException(status_code=401, detail=f"Expected {expected_type} token")
    if claims.get("jti") in _revoked_jtis:
        raise HTTPException(status_code=401, detail="Token has been revoked")
    return claims


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    return decode_token(token, expected_type=_TOKEN_TYPE_ACCESS)


def refresh_token(token: str) -> str:
    claims = decode_token(token, expected_type=_TOKEN_TYPE_REFRESH)
    claims.pop("exp", None)
    claims.pop("jti", None)
    claims.pop("type", None)
    return issue_access_token(claims)


def revoke_token(token: str) -> None:
    claims = decode_token(token, expected_type=_TOKEN_TYPE_ACCESS)
    _revoked_jtis.add(claims["jti"])
