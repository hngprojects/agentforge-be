"""
Tests for POST /api/v1/auth/resend-verification
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.enums import UserProvider
from app.models.user import User
from app.services import auth as auth_service

_RESEND_EP = "/api/v1/auth/resend-verification"


def _make_user(
    *,
    email: str = "alice@example.com",
    provider: UserProvider = UserProvider.EMAIL,
    email_verified: bool = False,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        provider=provider,
        email_verified=email_verified,
        is_active=True,
    )
    return user


def _db_with_user(user: User | None) -> MagicMock:
    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = user
    db.execute = AsyncMock(return_value=result)
    return db


# ---------------------------------------------------------------------------
# Case 1: eligible unverified EMAIL user — email is sent
# ---------------------------------------------------------------------------


class TestResendVerificationEligibleUser:
    async def test_endpoint_returns_200(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.get_verification_resend_target",
                new=AsyncMock(return_value="alice@example.com"),
            ),
            patch("app.api.v1.endpoints.auth.send_verification_email"),
        ):
            resp = await client.post(_RESEND_EP, json={"email": "alice@example.com"})

        assert resp.status_code == 200
        assert "new link has been sent" in resp.json()["message"]

    async def test_endpoint_sends_email_with_token(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.get_verification_resend_target",
                new=AsyncMock(return_value="alice@example.com"),
            ),
            patch(
                "app.api.v1.endpoints.auth.send_verification_email"
            ) as mock_send,
            patch(
                "app.api.v1.endpoints.auth.create_verification_token",
                return_value="new-verify-token",
            ),
        ):
            resp = await client.post(_RESEND_EP, json={"email": "alice@example.com"})

        assert resp.status_code == 200
        mock_send.assert_called_once_with("alice@example.com", "new-verify-token")

    async def test_service_returns_email_for_unverified_user(self):
        user = _make_user(email_verified=False)
        db = _db_with_user(user)

        result = await auth_service.get_verification_resend_target(db, user.email)

        assert result == user.email

    async def test_service_normalises_email_to_lowercase(self):
        user = _make_user(email="alice@example.com", email_verified=False)
        db = _db_with_user(user)

        result = await auth_service.get_verification_resend_target(
            db, "ALICE@EXAMPLE.COM"
        )

        assert result == "alice@example.com"


# ---------------------------------------------------------------------------
# Case 2: already verified user — no email sent
# ---------------------------------------------------------------------------


class TestResendVerificationAlreadyVerified:
    async def test_endpoint_returns_200(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.get_verification_resend_target",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "app.api.v1.endpoints.auth.send_verification_email"
            ) as mock_send,
        ):
            resp = await client.post(_RESEND_EP, json={"email": "alice@example.com"})

        assert resp.status_code == 200
        mock_send.assert_not_called()

    async def test_service_returns_none_for_verified_user(self):
        user = _make_user(email_verified=True)
        db = _db_with_user(user)

        result = await auth_service.get_verification_resend_target(db, user.email)

        assert result is None


# ---------------------------------------------------------------------------
# Case 3: unknown email — no email sent, still 200
# ---------------------------------------------------------------------------


class TestResendVerificationUnknownEmail:
    async def test_endpoint_returns_200(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.get_verification_resend_target",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "app.api.v1.endpoints.auth.send_verification_email"
            ) as mock_send,
        ):
            resp = await client.post(_RESEND_EP, json={"email": "ghost@example.com"})

        assert resp.status_code == 200
        mock_send.assert_not_called()

    async def test_service_returns_none_for_unknown_email(self):
        db = _db_with_user(None)

        result = await auth_service.get_verification_resend_target(
            db, "ghost@example.com"
        )

        assert result is None


# ---------------------------------------------------------------------------
# Case 4: Google/OAuth user — no password, no resend
# ---------------------------------------------------------------------------


class TestResendVerificationOAuthUser:
    async def test_endpoint_returns_200(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.get_verification_resend_target",
                new=AsyncMock(return_value=None),
            ),
            patch(
                "app.api.v1.endpoints.auth.send_verification_email"
            ) as mock_send,
        ):
            resp = await client.post(_RESEND_EP, json={"email": "oauth@example.com"})

        assert resp.status_code == 200
        mock_send.assert_not_called()

    async def test_service_returns_none_for_google_user(self):
        user = _make_user(provider=UserProvider.GOOGLE, email_verified=False)
        db = _db_with_user(user)

        result = await auth_service.get_verification_resend_target(db, user.email)

        assert result is None


# ---------------------------------------------------------------------------
# Case 5: invalid email format — schema validation rejects early
# ---------------------------------------------------------------------------


class TestResendVerificationInvalidInput:
    @pytest.mark.parametrize("bad_email", ["not-an-email", "", "missing@"])
    async def test_invalid_email_returns_422(self, client, bad_email):
        resp = await client.post(_RESEND_EP, json={"email": bad_email})

        assert resp.status_code == 422

    async def test_invalid_email_does_not_reach_service(self, client):
        with patch(
            "app.api.v1.endpoints.auth.get_verification_resend_target",
            new=AsyncMock(),
        ) as mock_service:
            resp = await client.post(_RESEND_EP, json={"email": "bad-email"})

        assert resp.status_code == 422
        mock_service.assert_not_awaited()
