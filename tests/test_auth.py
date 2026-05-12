"""
Tests for:
  GET /api/v1/auth/verify-email
  GET /api/v1/auth/github
  GET /api/v1/auth/github/callback
"""

import uuid
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt
import pytest
from fastapi import HTTPException
from pydantic import SecretStr

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_oauth_state_token,
    create_verification_token,
    hash_refresh_token,
)
from app.models.enums import UserProvider
from app.models.user import User
from app.schemas.auth import TokenResponse
from app.services import auth as auth_service
from app.services import email as email_service

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALGO = settings.JWT_ALGORITHM
_SECRET = settings.JWT_SECRET


def _github_http_error() -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.github.com/test")
    response = httpx.Response(500, request=request)
    return httpx.HTTPStatusError(
        "GitHub request failed",
        request=request,
        response=response,
    )


def _github_request_error() -> httpx.RequestError:
    request = httpx.Request("POST", "https://github.com/login/oauth/access_token")
    return httpx.ConnectTimeout("GitHub timed out", request=request)


def _oauth_state_with_cookie(nonce: str = "oauth-nonce") -> tuple[str, str]:
    return create_oauth_state_token(nonce), f"oauth_state_nonce={nonce}"


def _make_user(
    *,
    email: str = "alice@example.com",
    email_verified: bool = False,
    provider: UserProvider = UserProvider.EMAIL,
) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        provider=provider,
        email_verified=email_verified,
        is_active=True,
    )
    return user


def _make_request(headers: dict[str, str] | None = None, host: str | None = "test"):
    request = MagicMock()
    request.headers = headers or {}
    request.client = MagicMock(host=host) if host else None
    return request


# ---------------------------------------------------------------------------
# Email/password auth
# ---------------------------------------------------------------------------


class TestEmailPasswordAuth:
    async def test_login_sets_refresh_cookie_without_returning_it(self, client):
        with patch(
            "app.api.v1.endpoints.auth.login_user",
            new=AsyncMock(return_value=("access-token", "raw-refresh-token")),
        ) as login_user:
            resp = await client.post(
                "/api/v1/auth/login",
                json={"email": "new@example.com", "password": "correct-password"},
            )

        assert resp.status_code == 200
        assert resp.json() == {
            "access_token": "access-token",
            "token_type": "bearer",
        }
        set_cookie = resp.headers["set-cookie"]
        assert "refresh_token=raw-refresh-token" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "samesite=strict" in set_cookie.lower()
        assert "Path=/api/v1/auth" in set_cookie
        login_user.assert_awaited_once()

    async def test_register_sends_verification_without_printing_token(self, client):
        user = _make_user(email="new@example.com")

        with (
            patch(
                "app.api.v1.endpoints.auth.register_user",
                new=AsyncMock(return_value=user),
            ) as register_user,
            patch("app.api.v1.endpoints.auth.send_verification_email") as send_email,
            patch("builtins.print") as print_mock,
        ):
            resp = await client.post(
                "/api/v1/auth/register",
                json={
                    "email": user.email,
                    "password": "CorrectHorse1",
                    "display_name": "New User",
                },
            )

        assert resp.status_code == 201
        register_user.assert_awaited_once()
        send_email.assert_called_once()
        assert send_email.call_args.args[0] == user.email
        print_mock.assert_not_called()

    async def test_refresh_reads_cookie_and_resets_it(self, client):
        with patch(
            "app.api.v1.endpoints.auth.rotate_refresh_token",
            new=AsyncMock(return_value=("new-access-token", "new-refresh-token")),
        ) as rotate_refresh_token:
            resp = await client.post(
                "/api/v1/auth/refresh",
                headers={"cookie": "refresh_token=old-refresh-token"},
            )

        assert resp.status_code == 200
        assert resp.json() == {
            "access_token": "new-access-token",
            "token_type": "bearer",
        }
        assert "refresh_token=new-refresh-token" in resp.headers["set-cookie"]
        assert rotate_refresh_token.await_args.args[1] == "old-refresh-token"

    async def test_logout_revokes_refresh_token_cookie_without_access_token(
        self, client
    ):
        with patch(
            "app.api.v1.endpoints.auth.logout_user",
            new=AsyncMock(),
        ) as logout_user:
            resp = await client.post(
                "/api/v1/auth/logout",
                headers={"cookie": "refresh_token=raw-refresh-token"},
            )

        assert resp.status_code == 200
        assert "refresh_token=" in resp.headers["set-cookie"]
        assert "Max-Age=0" in resp.headers["set-cookie"]
        assert logout_user.await_args.args[1] == "raw-refresh-token"

    async def test_refresh_requires_refresh_cookie(self, client):
        resp = await client.post("/api/v1/auth/refresh")

        assert resp.status_code == 401

    def test_token_response_refresh_token_is_optional(self):
        response = TokenResponse(access_token="access")

        assert response.refresh_token is None

    async def test_login_unknown_user_returns_401(self):
        with (
            patch(
                "app.services.auth.get_user_by_email",
                new=AsyncMock(return_value=None),
            ),
            pytest.raises(HTTPException) as exc_info,
        ):
            await auth_service.login_user(
                MagicMock(),
                "missing@example.com",
                "wrong-password",
                request=_make_request(),
            )

        assert exc_info.value.status_code == 401

    async def test_create_refresh_token_uses_uuid_and_request_metadata(self):
        db = MagicMock()
        user = _make_user(email="refresh@example.com")

        raw, record = await auth_service._create_refresh_token(
            db,
            user,
            user_agent="pytest",
            ip_address="203.0.113.10",
        )

        assert raw
        assert record.token_hash == hash_refresh_token(raw)
        assert record.token_hash != raw
        assert record.user_id == user.id
        assert record.user_agent == "pytest"
        assert record.ip_address == "203.0.113.10"
        db.add.assert_called_once_with(record)

    def test_refresh_token_context_uses_forwarded_for_from_trusted_proxy(self):
        with patch.object(settings, "TRUSTED_PROXIES", "127.0.0.1"):
            user_agent, ip_address = auth_service._refresh_token_context(
                _make_request(
                    headers={
                        "x-forwarded-for": "203.0.113.10, 198.51.100.10",
                        "user-agent": "pytest",
                    },
                    host="127.0.0.1",
                )
            )

        assert user_agent == "pytest"
        assert ip_address == "203.0.113.10"

    def test_refresh_token_context_ignores_untrusted_forwarded_for(self):
        with patch.object(settings, "TRUSTED_PROXIES", ""):
            _, ip_address = auth_service._refresh_token_context(
                _make_request(
                    headers={"x-forwarded-for": "203.0.113.10"},
                    host="127.0.0.1",
                )
            )

        assert ip_address == "127.0.0.1"

    def test_refresh_token_context_caps_user_agent_and_rejects_invalid_ip(self):
        user_agent, ip_address = auth_service._refresh_token_context(
            _make_request(
                headers={"user-agent": "x" * 600},
                host="not-an-ip-address",
            )
        )

        assert user_agent == "x" * 512
        assert ip_address is None

    def test_verification_email_log_omits_email_and_token(self):
        brevo_client = MagicMock()

        with (
            patch.object(
                email_service.sib_api_v3_sdk,
                "TransactionalEmailsApi",
                return_value=brevo_client,
            ),
            patch.object(email_service.sib_api_v3_sdk, "ApiClient"),
            patch.object(email_service.logger, "info") as logger_info,
        ):
            email_service.send_verification_email("secret@example.com", "token-value")

        brevo_client.send_transac_email.assert_called_once()
        logger_info.assert_called_once_with("Verification email sent via Brevo")
        logged = str(logger_info.call_args)
        assert "secret@example.com" not in logged
        assert "token-value" not in logged

    async def test_github_user_does_not_silently_link_password_account(self):
        user = _make_user(email="octocat@github.com", provider=UserProvider.EMAIL)
        user.password_hash = "existing-password-hash"
        user.email_verified = False

        with (
            patch(
                "app.services.auth.get_user_by_email",
                new=AsyncMock(return_value=user),
            ),
            pytest.raises(HTTPException) as exc_info,
        ):
            await auth_service.get_or_create_github_user(
                MagicMock(),
                email=user.email,
                display_name="Octo Cat",
                avatar_url="https://example.com/avatar.png",
                github_username="octocat",
            )

        assert exc_info.value.status_code == 409
        assert user.email_verified is False
        assert user.github_username is None


class TestGoogleOAuth:
    async def test_google_start_sets_state_cookie_and_redirects(self, client):
        with (
            patch(
                "app.api.v1.endpoints.auth.create_oauth_state_token",
                return_value="state-token",
            ),
            patch(
                "app.api.v1.endpoints.auth.build_google_auth_url",
                return_value="https://accounts.google.com/o/oauth2/v2/auth",
            ),
        ):
            resp = await client.get("/api/v1/auth/google")

        assert resp.status_code == 307
        assert (
            resp.headers["location"] == "https://accounts.google.com/o/oauth2/v2/auth"
        )
        set_cookie = resp.headers["set-cookie"]
        assert "oauth_state=state-token" in set_cookie

    async def test_google_callback_returns_token_and_sets_refresh_cookie(self, client):
        user = _make_user(email="google@example.com", email_verified=True)

        with (
            patch(
                "app.api.v1.endpoints.auth.decode_token",
                return_value={"purpose": "oauth_state"},
            ),
            patch(
                "app.api.v1.endpoints.auth.exchange_google_code",
                new=AsyncMock(return_value={"access_token": "google-access"}),
            ),
            patch(
                "app.api.v1.endpoints.auth.fetch_google_userinfo",
                new=AsyncMock(
                    return_value={
                        "sub": "google-subject",
                        "email": user.email,
                        "email_verified": True,
                        "name": "Google User",
                    }
                ),
            ),
            patch(
                "app.api.v1.endpoints.auth.login_or_register_google_user",
                new=AsyncMock(return_value=("access-token", "refresh-token", user)),
            ),
        ):
            resp = await client.get(
                "/api/v1/auth/google/callback?code=abc&state=state-token",
                headers={"cookie": "oauth_state=state-token"},
            )

        assert resp.status_code == 200
        assert resp.json() == {"access_token": "access-token", "token_type": "bearer"}
        set_cookies = resp.headers.get_list("set-cookie")
        assert any("refresh_token=refresh-token" in value for value in set_cookies)
        assert any(
            "oauth_state=" in value and "Max-Age=0" in value for value in set_cookies
        )

    async def test_google_callback_rejects_state_mismatch(self, client):
        resp = await client.get(
            "/api/v1/auth/google/callback?code=abc&state=state-token",
            headers={"cookie": "oauth_state=other-state"},
        )

        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------


class TestVerifyEmail:
    async def test_happy_path(self, client):
        """Valid verification token marks user as verified."""
        user = _make_user(email="bob@example.com")
        token = create_verification_token(user.email)

        with (
            patch(
                "app.api.v1.endpoints.auth.get_user_by_email",
                new=AsyncMock(return_value=user),
            ),
            patch("app.api.v1.endpoints.auth.DBSession", None),
        ):
            resp = await client.get(
                f"/api/v1/auth/verify-email?token={token}",
            )

        assert resp.status_code == 200
        assert resp.json()["message"] == "Email verified successfully"
        assert user.email_verified is True

    async def test_already_verified(self, client):
        user = _make_user(email="already@example.com", email_verified=True)
        token = create_verification_token(user.email)

        with patch(
            "app.api.v1.endpoints.auth.get_user_by_email",
            new=AsyncMock(return_value=user),
        ):
            resp = await client.get(f"/api/v1/auth/verify-email?token={token}")

        assert resp.status_code == 200
        assert resp.json()["message"] == "Email already verified"

    async def test_expired_token(self, client):
        expired_payload = {
            "sub": "expired@example.com",
            "purpose": "email_verify",
            "iat": datetime.now(UTC) - timedelta(hours=48),
            "exp": datetime.now(UTC) - timedelta(hours=24),
        }
        expired_token = jwt.encode(expired_payload, _SECRET, algorithm=_ALGO)
        resp = await client.get(f"/api/v1/auth/verify-email?token={expired_token}")
        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower()

    async def test_invalid_token(self, client):
        resp = await client.get("/api/v1/auth/verify-email?token=not.a.valid.jwt")
        assert resp.status_code == 401

    async def test_wrong_purpose_token(self, client):
        """Access token must not work as a verification token."""
        fake_user = _make_user()
        access_token = create_access_token(str(fake_user.id))
        resp = await client.get(f"/api/v1/auth/verify-email?token={access_token}")
        assert resp.status_code == 400

    async def test_user_not_found(self, client):
        token = create_verification_token("ghost@example.com")
        with patch(
            "app.api.v1.endpoints.auth.get_user_by_email",
            new=AsyncMock(return_value=None),
        ):
            resp = await client.get(f"/api/v1/auth/verify-email?token={token}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GitHub OAuth
# ---------------------------------------------------------------------------


class TestGithubLogin:
    async def test_redirects_to_github(self, client):
        """With a configured client_id, should redirect to GitHub."""
        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(settings, "COOKIE_SECURE", True),
        ):
            resp = await client.get("/api/v1/auth/github", follow_redirects=False)

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "github.com/login/oauth/authorize" in location
        assert "client_id=test-client-id" in location
        assert "scope=user%3Aemail" in location or "scope=user:email" in location
        # state must be a valid JWT
        from urllib.parse import parse_qs, urlparse

        qs = parse_qs(urlparse(location).query)
        state_token = qs["state"][0]
        from app.core.security import decode_token

        payload = decode_token(state_token)
        assert payload["purpose"] == "oauth_state"
        cookies = SimpleCookie(resp.headers["set-cookie"])
        nonce = cookies["oauth_state_nonce"].value
        assert payload["nonce"] == nonce
        assert cookies["oauth_state_nonce"]["httponly"]
        assert cookies["oauth_state_nonce"]["secure"]
        assert cookies["oauth_state_nonce"]["samesite"].lower() == "lax"

    async def test_returns_501_when_not_configured(self, client):
        with patch.object(settings, "GITHUB_CLIENT_ID", ""):
            resp = await client.get("/api/v1/auth/github", follow_redirects=False)
        assert resp.status_code == 501


class TestGithubCallback:
    def _mock_httpx(
        self,
        access_token="gh_token",
        profile=None,
        emails=None,
        token_data=None,
        token_error=None,
        profile_error=None,
        emails_error=None,
    ):
        if profile is None:
            profile = {
                "login": "octocat",
                "name": "The Octocat",
                "avatar_url": "https://example.com/avatar.png",
            }
        if emails is None:
            emails = [
                {"email": "octocat@github.com", "primary": True, "verified": True}
            ]

        token_response = MagicMock()
        token_response.raise_for_status = MagicMock(side_effect=token_error)
        token_response.json.return_value = (
            {"access_token": access_token} if token_data is None else token_data
        )

        profile_response = MagicMock()
        profile_response.raise_for_status = MagicMock(side_effect=profile_error)
        profile_response.json.return_value = profile

        emails_response = MagicMock()
        emails_response.raise_for_status = MagicMock(side_effect=emails_error)
        emails_response.json.return_value = emails

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=token_response)
        mock_client.get = AsyncMock(side_effect=[profile_response, emails_response])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        return mock_client

    async def test_happy_path_new_user(self, client):
        state, cookie = _oauth_state_with_cookie()
        mock_http = self._mock_httpx()
        new_user = _make_user(email="octocat@github.com", provider=UserProvider.GITHUB)
        new_user.id = uuid.uuid4()
        access_token = create_access_token(str(new_user.id))

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(settings, "COOKIE_SECURE", True),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient", return_value=mock_http
            ),
            patch(
                "app.api.v1.endpoints.auth.get_or_create_github_user",
                new=AsyncMock(return_value=new_user),
            ),
            patch(
                "app.api.v1.endpoints.auth.issue_auth_tokens",
                new=AsyncMock(return_value=(access_token, "raw-refresh-token")),
            ) as issue_auth_tokens,
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=code123&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body == {
            "access_token": access_token,
            "token_type": "bearer",
        }
        assert body["token_type"] == "bearer"
        assert "refresh_token=raw-refresh-token" in resp.headers["set-cookie"]
        assert "HttpOnly" in resp.headers["set-cookie"]
        assert "Secure" in resp.headers["set-cookie"]
        from app.core.security import decode_token

        payload = decode_token(body["access_token"])
        assert payload["purpose"] == "access"
        assert payload["sub"] == str(new_user.id)
        mock_http.post.assert_awaited_once()
        assert mock_http.post.await_args.kwargs["data"]["code"] == "code123"
        issue_auth_tokens.assert_awaited_once()

    async def test_returns_501_when_callback_not_configured(self, client):
        state, cookie = _oauth_state_with_cookie()
        with (
            patch.object(settings, "GITHUB_CLIENT_ID", ""),
            patch.object(settings, "GITHUB_CLIENT_SECRET", SecretStr("")),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=x&state={state}",
                headers={"cookie": cookie},
            )
        assert resp.status_code == 501

    async def test_invalid_state(self, client):
        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
        ):
            resp = await client.get(
                "/api/v1/auth/github/callback?code=x&state=bad.state"
            )
        assert resp.status_code == 401

    async def test_wrong_state_purpose(self, client):
        """An access token used as state should be rejected."""
        fake_user = _make_user()
        fake_user.id = uuid.uuid4()
        bad_state = create_access_token(str(fake_user.id))
        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=x&state={bad_state}"
            )
        assert resp.status_code == 400

    async def test_missing_oauth_nonce_cookie(self, client):
        state = create_oauth_state_token("nonce")
        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=x&state={state}"
            )
        assert resp.status_code == 400

    async def test_no_verified_primary_email(self, client):
        state, cookie = _oauth_state_with_cookie()
        mock_http = self._mock_httpx(
            emails=[
                {
                    "email": "noreply@users.noreply.github.com",
                    "primary": True,
                    "verified": False,
                }
            ]
        )
        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_http,
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=code123&state={state}",
                headers={"cookie": cookie},
            )
        assert resp.status_code == 400
        assert "email" in resp.json()["detail"].lower()

    async def test_github_token_exchange_error(self, client):
        state, cookie = _oauth_state_with_cookie()

        token_response = MagicMock()
        token_response.raise_for_status = MagicMock()
        token_response.json.return_value = {
            "error": "bad_verification_code",
            "error_description": "Code expired",
        }

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=token_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_client,
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=bad&state={state}",
                headers={"cookie": cookie},
            )
        assert resp.status_code == 400
        assert "Code expired" in resp.json()["detail"]

    async def test_github_token_http_error(self, client):
        state, cookie = _oauth_state_with_cookie()
        mock_http = self._mock_httpx(token_error=_github_http_error())

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_http,
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=bad&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 502

    async def test_github_request_error(self, client):
        state, cookie = _oauth_state_with_cookie()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=_github_request_error())
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_client,
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=bad&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 502

    async def test_missing_access_token_from_github(self, client):
        state, cookie = _oauth_state_with_cookie()
        mock_http = self._mock_httpx(token_data={})

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_http,
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=bad&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 502

    async def test_malformed_github_emails_payload(self, client):
        state, cookie = _oauth_state_with_cookie()
        mock_http = self._mock_httpx(emails={"email": "octocat@github.com"})

        with (
            patch.object(settings, "GITHUB_CLIENT_ID", "test-client-id"),
            patch.object(
                settings, "GITHUB_CLIENT_SECRET", SecretStr("test-client-secret")
            ),
            patch(
                "app.api.v1.endpoints.auth.httpx.AsyncClient",
                return_value=mock_http,
            ),
        ):
            resp = await client.get(
                f"/api/v1/auth/github/callback?code=code123&state={state}",
                headers={"cookie": cookie},
            )

        assert resp.status_code == 400
