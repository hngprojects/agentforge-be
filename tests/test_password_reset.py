"""
Tests for:
  POST /api/v1/auth/forgot-password
  POST /api/v1/auth/reset-password
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from app.core.config import settings
from app.core.security import (
    create_password_reset_jwt,
    hash_password,
    verify_password,
)
from app.models.enums import UserProvider
from app.models.user import User
from app.services import auth as auth_service

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RESET_EP = "/api/v1/auth/reset-password"
_FORGOT_EP = "/api/v1/auth/forgot-password"
_ALGO = settings.JWT_ALGORITHM
_SECRET = settings.JWT_SECRET


def _make_user(
    *,
    email: str = "alice@example.com",
    provider: UserProvider = UserProvider.EMAIL,
    email_verified: bool = True,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        provider=provider,
        email_verified=email_verified,
        is_active=True,
    )
    return user


def _db_with_results(*scalars):
    """MagicMock db whose execute calls return scalars in sequence.
    Uses MagicMock as base so db.add() stays synchronous (matching SQLAlchemy).
    """
    db = MagicMock()
    results = []
    for value in scalars:
        r = MagicMock()
        r.scalar_one_or_none.return_value = value
        results.append(r)
    db.execute = AsyncMock(side_effect=results)
    db.commit = AsyncMock()
    return db


def _db_no_calls():
    db = MagicMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# Case 1: forgot_password_existing_email — returns 200, JWT issued (no DB write)
# ---------------------------------------------------------------------------


class TestForgotPasswordExistingEmail:
    async def test_endpoint_returns_200(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.create_password_reset_token",
                new=AsyncMock(return_value="raw-jwt-token"),
            ),
            patch("app.api.v1.endpoints.auth.send_password_reset_email"),
        ):
            resp = await client.post(_FORGOT_EP, json={"email": "alice@example.com"})

        assert resp.status_code == 200
        assert resp.json() == {
            "message": "If this email exists, a reset link has been sent."
        }

    async def test_service_returns_jwt_no_db_write(self):
        user = _make_user()
        user.password_hash = hash_password("OldPass123")
        db = _db_with_results(user)

        raw = await auth_service.create_password_reset_token(db, user.email)

        assert raw is not None
        db.add.assert_not_called()
        db.commit.assert_not_awaited()

    async def test_endpoint_calls_email_service_with_token_in_url(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.create_password_reset_token",
                new=AsyncMock(return_value="raw-jwt-token"),
            ),
            patch("app.api.v1.endpoints.auth.send_password_reset_email") as mock_send,
        ):
            resp = await client.post(_FORGOT_EP, json={"email": "alice@example.com"})

        assert resp.status_code == 200
        mock_send.assert_called_once()
        _, reset_url = mock_send.call_args.args
        assert reset_url.endswith("#raw-jwt-token")


# ---------------------------------------------------------------------------
# Case 2: forgot_password_nonexistent_email — returns 200, no JWT
# ---------------------------------------------------------------------------


class TestForgotPasswordNonexistentEmail:
    async def test_endpoint_returns_200(self, client):
        with patch(
            "app.api.v1.endpoints.auth.create_password_reset_token",
            new=AsyncMock(return_value=None),
        ):
            resp = await client.post(_FORGOT_EP, json={"email": "ghost@example.com"})

        assert resp.status_code == 200
        assert "reset link has been sent" in resp.json()["message"]

    async def test_service_returns_none_for_unknown_email(self):
        db = _db_with_results(None)

        result = await auth_service.create_password_reset_token(db, "ghost@example.com")

        assert result is None
        db.add.assert_not_called()
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 3: forgot_password_oauth_user — provider=google, returns 200, no JWT
# ---------------------------------------------------------------------------


class TestForgotPasswordOauthUser:
    async def test_endpoint_returns_200(self, client):
        with patch(
            "app.api.v1.endpoints.auth.create_password_reset_token",
            new=AsyncMock(return_value=None),
        ):
            resp = await client.post(_FORGOT_EP, json={"email": "oauth@example.com"})

        assert resp.status_code == 200

    async def test_service_returns_none_for_google_user(self):
        user = _make_user(provider=UserProvider.GOOGLE)
        db = _db_with_results(user)

        result = await auth_service.create_password_reset_token(db, user.email)

        assert result is None
        db.add.assert_not_called()


# ---------------------------------------------------------------------------
# Case 4: reset_password_valid_token — password updated, old rejected, sessions revoked
# ---------------------------------------------------------------------------


class TestResetPasswordValidToken:
    async def test_password_updated_old_rejected_sessions_revoked(self):
        user = _make_user()
        old_password = "OldPass123"
        user.password_hash = hash_password(old_password)

        # Create a valid JWT signed against the user's current password hash
        raw = create_password_reset_jwt(str(user.id), user.password_hash)

        # 2 execute calls: SELECT user (via get_user_by_id), UPDATE refresh_tokens
        db = _db_with_results(user, MagicMock())

        success = await auth_service.reset_password(db, raw, "NewPass456")

        assert success is True
        assert verify_password("NewPass456", user.password_hash)
        assert not verify_password(old_password, user.password_hash)
        db.commit.assert_awaited_once()

    async def test_endpoint_returns_200(self, client):
        with patch(
            "app.api.v1.endpoints.auth.reset_password",
            new=AsyncMock(return_value=True),
        ):
            resp = await client.post(
                _RESET_EP,
                json={"token": "valid-token", "new_password": "NewPass456"},
            )

        assert resp.status_code == 200
        assert resp.json() == {"message": "Password updated. Please sign in."}


# ---------------------------------------------------------------------------
# Case 5: reset_password_used_token — password already changed, fingerprint mismatch
# ---------------------------------------------------------------------------


class TestResetPasswordUsedToken:
    async def test_endpoint_returns_400(self, client):
        with patch(
            "app.api.v1.endpoints.auth.reset_password",
            new=AsyncMock(return_value=False),
        ):
            resp = await client.post(
                _RESET_EP,
                json={"token": "already-used-token", "new_password": "NewPass456"},
            )

        assert resp.status_code == 400
        assert "Invalid or expired reset token" in resp.json()["detail"]

    async def test_service_returns_false_when_password_already_changed(self):
        user = _make_user()
        original_hash = hash_password("OldPass123")
        user.password_hash = original_hash

        # Token fingerprinted against the old hash
        raw = create_password_reset_jwt(str(user.id), original_hash)

        # Simulate: password was already changed by another means
        user.password_hash = hash_password("AlreadyChanged456")

        db = _db_with_results(user)

        result = await auth_service.reset_password(db, raw, "NewPass789")

        assert result is False
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 6: reset_password_expired_token — expired JWT returns 400
# ---------------------------------------------------------------------------


class TestResetPasswordExpiredToken:
    async def test_endpoint_returns_400(self, client):
        with patch(
            "app.api.v1.endpoints.auth.reset_password",
            new=AsyncMock(return_value=False),
        ):
            resp = await client.post(
                _RESET_EP,
                json={"token": "expired-token", "new_password": "NewPass456"},
            )

        assert resp.status_code == 400

    async def test_service_returns_false_for_expired_jwt(self):
        user = _make_user()
        user.password_hash = hash_password("OldPass123")

        expired_token = jwt.encode(
            {
                "sub": str(user.id),
                "purpose": "password_reset",
                "password_hash": user.password_hash,
                "iat": datetime.now(UTC) - timedelta(hours=2),
                "exp": datetime.now(UTC) - timedelta(hours=1),
            },
            _SECRET,
            algorithm=_ALGO,
        )

        db = _db_no_calls()

        result = await auth_service.reset_password(db, expired_token, "NewPass456")

        assert result is False
        db.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 7: reset_password_invalid_token — garbage string returns 400
# ---------------------------------------------------------------------------


class TestResetPasswordInvalidToken:
    async def test_endpoint_returns_400(self, client):
        with patch(
            "app.api.v1.endpoints.auth.reset_password",
            new=AsyncMock(return_value=False),
        ):
            resp = await client.post(
                _RESET_EP,
                json={"token": "not-a-jwt", "new_password": "NewPass456"},
            )

        assert resp.status_code == 400

    async def test_service_returns_false_for_garbage_token(self):
        db = _db_no_calls()

        result = await auth_service.reset_password(db, "garbage", "NewPass456")

        assert result is False
        db.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 8: reset_password_weak_password — schema validation before service
# ---------------------------------------------------------------------------


class TestResetPasswordWeakPassword:
    @pytest.mark.parametrize(
        "bad_password",
        [
            "short1A",  # too short (7 chars)
            "alllowercase1",  # no uppercase
            "AllUpperNoDigit",  # no digit
        ],
    )
    async def test_weak_password_returns_422(self, client, bad_password):
        resp = await client.post(
            _RESET_EP,
            json={"token": "any-token", "new_password": bad_password},
        )

        assert resp.status_code == 422

    async def test_weak_password_does_not_reach_service(self, client):
        with patch(
            "app.api.v1.endpoints.auth.reset_password", new=AsyncMock()
        ) as mock_reset:
            resp = await client.post(
                _RESET_EP,
                json={"token": "any-token", "new_password": "weakpassword"},
            )

        assert resp.status_code == 422
        mock_reset.assert_not_awaited()
