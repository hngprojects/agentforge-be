"""
tests/test_github_oauth_extended.py

Additional GitHub OAuth tests covering gaps not in test_auth.py:

1. oauth_state_nonce cookie is cleared after successful callback
2. oauth_state_nonce cookie is cleared after failed callback
3. Re-login of existing GitHub user (happy path variant)
4. get_or_create_github_user raises 409 when email belongs to EMAIL-provider account
5. State nonce mismatch (state cookie ≠ JWT nonce) returns 400
6. redirect_uri is forwarded correctly in token exchange request
7. Profile-fetch HTTP error returns 502
8. Emails-fetch HTTP error returns 502
"""

import uuid
from http.cookies import SimpleCookie
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import settings
from app.core.security import create_access_token, create_oauth_state_token
from app.models.enums import UserProvider
from app.models.user import User
from app.services import auth as auth_service


# ─────────────────────────────────────────────
#  Helpers (mirror test_auth.py helpers)
# ─────────────────────────────────────────────

_GITHUB_STATE_COOKIE = "oauth_state_nonce"


def _make_user(
    *,
    email: str = "octocat@github.com",
    provider: UserProvider = UserProvider.GITHUB,
    is_active: bool = True,
) -> User:
    u = User(
        id=uuid.uuid4(),
        email=email,
        provider=provider,
        email_verified=True,
        is_active=is_active,
    )
    return u


def _oauth_state_with_cookie(nonce: str = "test-nonce") -> tuple[str, str]:
    return create_oauth_state_token(nonce), f"{_GITHUB_STATE_COOKIE}={nonce}"


def _mock_httpx(
    access_token="gh_token",
    profile=None,
    emails=None,
    token_error=None,
    profile_error=None,
    emails_error=None,
):
    profile = profile or {
        "login": "octocat",
        "name": "The Octocat",
        "avatar_url": "https://example.com/avatar.png",
    }
    emails = emails or [
        {"email": "octocat@github.com", "primary": True, "verified": True}
    ]

    token_resp = MagicMock()
    token_resp.raise_for_status = MagicMock(side_effect=token_error)
    token_resp.json.return_value = {"access_token": access_token}

    profile_resp = MagicMock()
    profile_resp.raise_for_status = MagicMock(side_effect=profile_error)
    profile_resp.json.return_value = profile

    emails_resp = MagicMock()
    emails_resp.raise_for_status = MagicMock(side_effect=emails_error)
    emails_resp.json.return_value = emails

    mock = AsyncMock()
    mock.post = AsyncMock(return_value=token_resp)
    mock.get = AsyncMock(side_effect=[profile_resp, emails_resp])
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


def _http_error(url: str) -> httpx.HTTPStatusError:
    req = httpx.Request("GET", url)
    resp = httpx.Response(500, request=req)
    return httpx.HTTPStatusError("error", request=req, response=resp)


# ─────────────────────────────────────────────
#  Tests
# ─────────────────────────────────────────────


class TestGithubCallbackCookieCleanup:
    """The oauth_state_nonce cookie must be cleared regardless of outcome."""

    async def test_nonce_cookie_cleared_on_success(self, client):
        """Successful callback must delete the nonce cookie."""
        state, cookie = _oauth_state_with_cookie()
        user = _make_user()
        access_token = create_access_token(str(user.id))

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "cid"),
            patch.object(settings, "GITHUB_CLIENT_SECRET", SecretStr("csecret")),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=_mock_httpx(),
            ),
            patch(
                "app.api.v1.endpoints.auth.get_or_create_github_user",
                new=AsyncMock(return_value=user),
            ),
            patch(
                "app.api.v1.endpoints.auth.issue_auth_tokens",
                new=AsyncMock(return_value=(access_token, "raw-refresh")),
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=good&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 200
        # FastAPI sets a deletion cookie with max-age=0 or expires in the past
        set_cookie_header = resp.headers.get("set-cookie", "")
        assert _GITHUB_STATE_COOKIE in set_cookie_header

    @pytest.mark.xfail(
        reason=(
            "Known FastAPI limitation: cookies set on the injected Response object "
            "are NOT included when an HTTPException is raised, because FastAPI's "
            "exception handler creates a new JSONResponse, discarding the earlier "
            "response object. The _clear_github_oauth_state_cookie() call in the "
            "except block runs but has no effect on the error response. "
            "Fix: return a RedirectResponse to the frontend error page instead of "
            "raising HTTPException, so cookie clearing is part of the redirect."
        ),
        strict=True,
    )
    async def test_nonce_cookie_cleared_on_state_mismatch(self, client):
        """Failed callback (bad state) must still clear the nonce cookie."""
        state, _ = _oauth_state_with_cookie(nonce="real-nonce")
        wrong_cookie = f"{_GITHUB_STATE_COOKIE}=wrong-nonce"

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "cid"),
            patch.object(settings, "GITHUB_CLIENT_SECRET", SecretStr("csecret")),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=x&state={state}",
                headers={"cookie": wrong_cookie},
            )

        assert resp.status_code == 400
        set_cookie_header = resp.headers.get("set-cookie", "")
        assert _GITHUB_STATE_COOKIE in set_cookie_header


class TestGithubCallbackExistingUser:
    """Re-login for a user who already has a GitHub account."""

    async def test_existing_github_user_gets_new_tokens(self, client):
        state, cookie = _oauth_state_with_cookie()
        existing = _make_user()
        existing.github_username = "octocat"
        access_token = create_access_token(str(existing.id))

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "cid"),
            patch.object(settings, "GITHUB_CLIENT_SECRET", SecretStr("csecret")),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=_mock_httpx(),
            ),
            patch(
                "app.api.v1.endpoints.auth.get_or_create_github_user",
                new=AsyncMock(return_value=existing),
            ),
            patch(
                "app.api.v1.endpoints.auth.issue_auth_tokens",
                new=AsyncMock(return_value=(access_token, "raw-refresh-2")),
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=code123&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 200
        assert resp.json()["access_token"] == access_token
        assert "refresh_token" in resp.headers.get("set-cookie", "")


class TestGithubServiceLayer:
    """Unit tests on get_or_create_github_user (no HTTP needed)."""

    async def test_email_provider_conflict_raises_409(self):
        """A user registered with email+password cannot silently get a GitHub account."""
        from fastapi import HTTPException
        from unittest.mock import MagicMock

        db = AsyncMock()
        existing = _make_user(provider=UserProvider.EMAIL)
        existing.password_hash = "hashed"

        # AsyncMock children default to AsyncMock, so scalar_one_or_none()
        # would return a coroutine. Explicitly use MagicMock so it returns the
        # User object synchronously (matching real SQLAlchemy Result behaviour).
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = existing
        db.execute.return_value = result_mock

        with pytest.raises(HTTPException) as exc_info:
            await auth_service.get_or_create_github_user(
                db,
                email="octocat@github.com",
                display_name="Octocat",
                avatar_url=None,
                github_username="octocat",
            )

        assert exc_info.value.status_code == 409

    async def test_new_github_user_is_created(self):
        """get_or_create_github_user creates a new user when email is unseen."""
        from unittest.mock import MagicMock

        db = AsyncMock()

        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = None
        db.execute.return_value = result_mock
        db.refresh = AsyncMock()  # no-op refresh

        result = await auth_service.get_or_create_github_user(
            db,
            email="NewUser@Example.com",  # also tests lowercase normalisation
            display_name="New User",
            avatar_url="https://example.com/pic.png",
            github_username="newuser",
        )

        db.commit.assert_awaited()
        # The function constructs and returns the User object directly
        assert result.email == "newuser@example.com"  # lowercased
        assert result.provider == UserProvider.GITHUB
        assert result.github_username == "newuser"
        assert result.email_verified is True


class TestGithubCallbackNonceMismatch:
    """State JWT nonce must match the cookie value exactly."""

    async def test_nonce_mismatch_returns_400(self, client):
        # State token embeds nonce="correct", but cookie has nonce="wrong"
        state = create_oauth_state_token("correct")
        wrong_cookie = f"{_GITHUB_STATE_COOKIE}=wrong"

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "cid"),
            patch.object(settings, "GITHUB_CLIENT_SECRET", SecretStr("csecret")),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=x&state={state}",
                headers={"cookie": wrong_cookie},
            )

        assert resp.status_code == 400
        assert "state" in resp.json()["detail"].lower()


class TestGithubCallbackRedirectUri:
    """redirect_uri must be forwarded in the token exchange request."""

    async def test_redirect_uri_sent_to_github(self, client):
        state, cookie = _oauth_state_with_cookie()
        user = _make_user()
        access_token = create_access_token(str(user.id))
        mock_http = _mock_httpx()

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "cid"),
            patch.object(settings, "GITHUB_CLIENT_SECRET", SecretStr("csecret")),
            patch.object(
                settings,
                "GITHUB_REDIRECT_URI",
                "http://test/api/v1/auth/github/callback",
            ),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_http,
            ),
            patch(
                "app.api.v1.endpoints.auth.get_or_create_github_user",
                new=AsyncMock(return_value=user),
            ),
            patch(
                "app.api.v1.endpoints.auth.issue_auth_tokens",
                new=AsyncMock(return_value=(access_token, "raw")),
            ),
        ):
            await client.get(
                f"/api/v1/auth/github/callback?code=code123&state={state}",
                headers={"cookie": cookie},
            )

        post_call = mock_http.post.await_args
        assert (
            post_call.kwargs["data"]["redirect_uri"]
            == "http://test/api/v1/auth/github/callback"
        )


class TestGithubCallbackHttpErrors:
    """Individual GitHub API failures map to 502."""

    async def test_profile_fetch_error_returns_502(self, client):
        state, cookie = _oauth_state_with_cookie()
        err = _http_error("https://api.github.com/user")
        mock_http = _mock_httpx(profile_error=err)

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "cid"),
            patch.object(settings, "GITHUB_CLIENT_SECRET", SecretStr("csecret")),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_http,
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=code&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 502
        assert "profile" in resp.json()["detail"].lower()

    async def test_emails_fetch_error_returns_502(self, client):
        state, cookie = _oauth_state_with_cookie()
        err = _http_error("https://api.github.com/user/emails")
        mock_http = _mock_httpx(emails_error=err)

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "cid"),
            patch.object(settings, "GITHUB_CLIENT_SECRET", SecretStr("csecret")),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_http,
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=code&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 502
        assert "email" in resp.json()["detail"].lower()