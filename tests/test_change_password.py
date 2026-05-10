"""
Tests for POST /api/v1/auth/change-password
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.deps import get_current_user
from app.core.security import hash_password, verify_password
from app.main import app
from app.models.enums import UserProvider
from app.models.user import User
from app.services import auth as auth_service

_CHANGE_EP = "/api/v1/auth/change-password"


def _make_user(
    *,
    email: str = "alice@example.com",
    provider: UserProvider = UserProvider.EMAIL,
    email_verified: bool = True,
    password: str | None = "OldPass123",
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        provider=provider,
        email_verified=email_verified,
        is_active=True,
    )
    if password is not None:
        user.password_hash = hash_password(password)
    return user


def _db_with_execute() -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(return_value=MagicMock())
    db.commit = AsyncMock()
    return db


@pytest.fixture
def auth_user():
    """Override CurrentUser with a pre-built email user; restore after test."""
    user = _make_user()
    app.dependency_overrides[get_current_user] = lambda: user
    yield user
    app.dependency_overrides.clear()


@pytest.fixture
def auth_google_user():
    """Override CurrentUser with a Google-provider user."""
    user = _make_user(provider=UserProvider.GOOGLE, password=None)
    app.dependency_overrides[get_current_user] = lambda: user
    yield user
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Case 1: correct current password — password updated, sessions revoked
# ---------------------------------------------------------------------------


class TestChangePasswordSuccess:
    async def test_endpoint_returns_200(self, client, auth_user):
        with patch(
            "app.api.v1.endpoints.auth.change_password",
            new=AsyncMock(return_value=True),
        ):
            resp = await client.post(
                _CHANGE_EP,
                json={"current_password": "OldPass123", "new_password": "NewPass456"},
            )

        assert resp.status_code == 200
        assert resp.json() == {"message": "Password changed successfully."}

    async def test_service_updates_hash_and_revokes_sessions(self):
        user = _make_user()
        db = _db_with_execute()

        success = await auth_service.change_password(
            db, user, "OldPass123", "NewPass456"
        )

        assert success is True
        assert verify_password("NewPass456", user.password_hash)
        assert not verify_password("OldPass123", user.password_hash)
        db.execute.assert_awaited_once()
        db.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# Case 2: wrong current password — 400
# ---------------------------------------------------------------------------


class TestChangePasswordWrongCurrent:
    async def test_endpoint_returns_400(self, client, auth_user):
        with patch(
            "app.api.v1.endpoints.auth.change_password",
            new=AsyncMock(return_value=False),
        ):
            resp = await client.post(
                _CHANGE_EP,
                json={"current_password": "WrongPass1", "new_password": "NewPass456"},
            )

        assert resp.status_code == 400
        assert "incorrect" in resp.json()["detail"]

    async def test_service_returns_false_for_wrong_password(self):
        user = _make_user()
        db = _db_with_execute()

        result = await auth_service.change_password(
            db, user, "WrongPass1", "NewPass456"
        )

        assert result is False
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 3: unauthenticated request — 401 before reaching the service
# ---------------------------------------------------------------------------


class TestChangePasswordUnauthenticated:
    async def test_no_token_returns_401(self, client):
        resp = await client.post(
            _CHANGE_EP,
            json={"current_password": "OldPass123", "new_password": "NewPass456"},
        )

        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Case 4: Google/OAuth user — no password to verify against
# ---------------------------------------------------------------------------


class TestChangePasswordOAuthUser:
    async def test_endpoint_returns_400_for_google_user(self, client, auth_google_user):
        with patch(
            "app.api.v1.endpoints.auth.change_password",
            new=AsyncMock(return_value=False),
        ):
            resp = await client.post(
                _CHANGE_EP,
                json={"current_password": "anything1A", "new_password": "NewPass456"},
            )

        assert resp.status_code == 400

    async def test_service_returns_false_for_google_user(self):
        user = _make_user(provider=UserProvider.GOOGLE, password=None)
        db = _db_with_execute()

        result = await auth_service.change_password(
            db, user, "anything1A", "NewPass456"
        )

        assert result is False
        db.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# Case 5: weak new password — schema validation rejects before service
# ---------------------------------------------------------------------------


class TestChangePasswordWeakNewPassword:
    @pytest.mark.parametrize(
        "bad_password",
        [
            "short1A",       # too short (7 chars)
            "alllowercase1", # no uppercase
            "AllUpperNoDigit", # no digit
        ],
    )
    async def test_weak_password_returns_422(self, client, auth_user, bad_password):
        resp = await client.post(
            _CHANGE_EP,
            json={"current_password": "OldPass123", "new_password": bad_password},
        )

        assert resp.status_code == 422

    async def test_weak_password_does_not_reach_service(self, client, auth_user):
        with patch(
            "app.api.v1.endpoints.auth.change_password", new=AsyncMock()
        ) as mock_change:
            resp = await client.post(
                _CHANGE_EP,
                json={"current_password": "OldPass123", "new_password": "weakpassword"},
            )

        assert resp.status_code == 422
        mock_change.assert_not_awaited()
