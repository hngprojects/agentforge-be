from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from jose import jwt

from app.core.config import settings
from app.services import jwt_service
from app.services.jwt_service import (
    decode_token,
    issue_access_token,
    issue_refresh_token,
    refresh_token,
    revoke_token,
)


@pytest.fixture(autouse=True)
def clear_revoked_jtis():
    jwt_service._revoked_jtis.clear()
    yield
    jwt_service._revoked_jtis.clear()


def test_issue_access_token_returns_decodable_string():
    token = issue_access_token({"sub": "user-123"})
    assert isinstance(token, str) and token

    claims = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    assert claims["sub"] == "user-123"
    assert "jti" in claims
    assert "exp" in claims


def test_issue_refresh_token_has_longer_expiry_than_access_token():
    access = issue_access_token({"sub": "user-123"})
    refresh = issue_refresh_token({"sub": "user-123"})

    access_claims = jwt.decode(access, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    refresh_claims = jwt.decode(refresh, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])

    assert refresh_claims["exp"] > access_claims["exp"]


def test_decode_token_returns_correct_claims():
    token = issue_access_token({"sub": "user-42", "role": "admin"})
    claims = decode_token(token)

    assert claims["sub"] == "user-42"
    assert claims["role"] == "admin"
    assert "jti" in claims


def test_decode_token_raises_401_for_expired_token():
    expired_claims = {
        "sub": "user-99",
        "jti": "some-jti",
        "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
    }
    expired_token = jwt.encode(
        expired_claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM
    )

    with pytest.raises(HTTPException) as exc_info:
        decode_token(expired_token)
    assert exc_info.value.status_code == 401


def test_revoke_token_causes_decode_to_raise_401():
    token = issue_access_token({"sub": "user-55"})

    decode_token(token)

    revoke_token(token)

    with pytest.raises(HTTPException) as exc_info:
        decode_token(token)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token has been revoked"


def test_refresh_token_returns_new_valid_access_token():
    original_refresh = issue_refresh_token({"sub": "user-77"})

    new_access = refresh_token(original_refresh)

    assert isinstance(new_access, str) and new_access
    claims = decode_token(new_access)
    assert claims["sub"] == "user-77"
    assert "jti" in claims
    assert new_access != original_refresh
