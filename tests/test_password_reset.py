"""
Tests for:
  POST /api/v1/auth/forgot-password
  POST /api/v1/auth/reset-password
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.security import hash_password, verify_password
from app.models.enums import UserProvider
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.services import auth as auth_service

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RESET_EP = "/api/v1/auth/reset-password"
_FORGOT_EP = "/api/v1/auth/forgot-password"


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


def _make_token(
    user: User,
    *,
    used_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> tuple[str, PasswordResetToken]:
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    record = PasswordResetToken(
        id=uuid.uuid4(),
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at or datetime.now(UTC) + timedelta(hours=1),
        used_at=used_at,
        created_at=datetime.now(UTC),
    )
    return raw, record


def _db_with_results(*scalars):
    """Return a mock db whose execute calls return scalars in sequence.
    Uses MagicMock as base so db.add() stays synchronous (matching SQLAlchemy's API).
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


# ---------------------------------------------------------------------------
# Case 1: forgot_password_existing_email — 200 + token row created in DB
# ---------------------------------------------------------------------------


class TestForgotPasswordExistingEmail:
    async def test_endpoint_returns_200(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.create_password_reset_token",
                new=AsyncMock(return_value="raw-reset-token"),
            ),
            patch(
                "app.api.v1.endpoints.auth.send_password_reset_email",
                new=AsyncMock(),
            ),
        ):
            resp = await client.post(_FORGOT_EP, json={"email": "alice@example.com"})

        assert resp.status_code == 200
        assert resp.json() == {
            "message": "If this email exists, a reset link has been sent."
        }

    async def test_service_creates_token_row_in_db(self):
        user = _make_user()
        # 2 execute calls: SELECT user, UPDATE old tokens
        db = _db_with_results(user, MagicMock())

        raw = await auth_service.create_password_reset_token(db, user.email)

        assert raw is not None
        db.add.assert_called_once()
        added = db.add.call_args[0][0]
        assert isinstance(added, PasswordResetToken)
        assert added.user_id == user.id
        assert len(added.token_hash) == 64
        db.commit.assert_awaited_once()

    async def test_endpoint_sends_email_with_correct_url(self, client):
        mock_send = AsyncMock()
        with (
            patch(
                "app.api.v1.endpoints.auth.create_password_reset_token",
                new=AsyncMock(return_value="raw-reset-token"),
            ),
            patch("app.api.v1.endpoints.auth.send_password_reset_email", new=mock_send),
        ):
            resp = await client.post(_FORGOT_EP, json={"email": "alice@example.com"})

        assert resp.status_code == 200
        mock_send.assert_awaited_once()
        called_email, called_url = mock_send.call_args.args
        assert called_email == "alice@example.com"
        assert "raw-reset-token" in called_url

    async def test_endpoint_returns_200_when_mailer_raises(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.create_password_reset_token",
                new=AsyncMock(return_value="raw-reset-token"),
            ),
            patch(
                "app.api.v1.endpoints.auth.send_password_reset_email",
                new=AsyncMock(side_effect=Exception("SMTP timeout")),
            ),
        ):
            resp = await client.post(_FORGOT_EP, json={"email": "alice@example.com"})

        assert resp.status_code == 200
        assert "reset link has been sent" in resp.json()["message"]


# ---------------------------------------------------------------------------
# Case 2: forgot_password_nonexistent_email — 200, no DB row created
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

    async def test_service_returns_none_and_no_db_add(self):
        db = _db_with_results(None)

        result = await auth_service.create_password_reset_token(db, "ghost@example.com")

        assert result is None
        db.add.assert_not_called()


# ---------------------------------------------------------------------------
# Case 3: forgot_password_oauth_user — provider=google, 200, no token
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
# Case 4: reset_password_valid_token — password updated, used_at set, old rejected
# ---------------------------------------------------------------------------


class TestResetPasswordValidToken:
    async def test_password_updated_used_at_set_old_rejected(self):
        user = _make_user()
        old_password = "OldPass123"
        user.password_hash = hash_password(old_password)

        raw, token = _make_token(user)
        # 3 execute calls: SELECT token FOR UPDATE, SELECT user, UPDATE refresh_tokens
        db = _db_with_results(token, user, MagicMock())

        success = await auth_service.reset_password(db, raw, "NewPass456")

        assert success is True
        assert token.used_at is not None
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
# Case 5: reset_password_used_token — second use returns 400
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

    async def test_service_returns_false_for_used_token(self):
        user = _make_user()
        raw, token = _make_token(user, used_at=datetime.now(UTC) - timedelta(minutes=5))
        db = _db_with_results(token)

        result = await auth_service.reset_password(db, raw, "NewPass456")

        assert result is False
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 6: reset_password_expired_token — expires_at in past returns 400
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

    async def test_service_returns_false_for_expired_token(self):
        user = _make_user()
        raw, token = _make_token(
            user, expires_at=datetime.now(UTC) - timedelta(hours=2)
        )
        db = _db_with_results(token)

        result = await auth_service.reset_password(db, raw, "NewPass456")

        assert result is False
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 7: reset_password_invalid_token — random string returns 400
# ---------------------------------------------------------------------------


class TestResetPasswordInvalidToken:
    async def test_endpoint_returns_400(self, client):
        with patch(
            "app.api.v1.endpoints.auth.reset_password",
            new=AsyncMock(return_value=False),
        ):
            resp = await client.post(
                _RESET_EP,
                json={"token": "totally-random-garbage", "new_password": "NewPass456"},
            )

        assert resp.status_code == 400

    async def test_service_returns_false_for_unknown_hash(self):
        db = _db_with_results(None)

        result = await auth_service.reset_password(db, "bad-token", "NewPass456")

        assert result is False
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 8: reset_password_weak_password — validation fails before DB
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

    async def test_weak_password_does_not_call_db(self, client):
        with patch(
            "app.api.v1.endpoints.auth.reset_password",
            new=AsyncMock(),
        ) as mock_reset:
            resp = await client.post(
                _RESET_EP,
                json={"token": "any-token", "new_password": "weakpassword"},
            )

        assert resp.status_code == 422
        mock_reset.assert_not_awaited()
