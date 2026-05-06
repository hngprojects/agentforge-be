from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from app.core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

_revoked_jtis: set[str] = set()


def issue_access_token(payload: dict) -> str:
    claims = payload.copy()
    claims["jti"] = str(uuid4())
    claims["exp"] = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_TTL_MINUTES
    )
    return jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def issue_refresh_token(payload: dict) -> str:
    claims = payload.copy()
    claims["jti"] = str(uuid4())
    claims["exp"] = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_TTL_DAYS
    )
    return jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        claims = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if claims.get("jti") in _revoked_jtis:
        raise HTTPException(status_code=401, detail="Token has been revoked")
    return claims


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    return decode_token(token)


def refresh_token(token: str) -> str:
    claims = decode_token(token)
    claims.pop("exp", None)
    claims.pop("jti", None)
    return issue_access_token(claims)


def revoke_token(token: str) -> None:
    claims = decode_token(token)
    _revoked_jtis.add(claims["jti"])
