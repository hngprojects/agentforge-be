import secrets
from urllib.parse import urlencode

import httpx
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Cookie,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import RedirectResponse

from app.api.deps import CurrentUser, DBSession
from app.core.config import settings
from app.core.security import (
    create_oauth_state_token,
    create_verification_token,
    decode_token,
)
from app.schemas.auth import (
    ForgotPasswordRequest,
    GoogleAuthResponse,
    GoogleCallbackRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth import (
    REFRESH_TOKEN_COOKIE,
    build_google_auth_url,
    clear_refresh_token_cookie,
    create_password_reset_token,
    exchange_google_code,
    fetch_google_userinfo,
    get_or_create_github_user,
    get_user_by_email,
    issue_auth_tokens,
    login_or_register_google_user,
    login_user,
    logout_user,
    register_user,
    reset_password,
    rotate_refresh_token,
    set_refresh_token_cookie,
)
from app.services.email import send_password_reset_email, send_verification_email

router = APIRouter()
_GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_USER_URL = "https://api.github.com/user"
_GITHUB_EMAILS_URL = "https://api.github.com/user/emails"
_GITHUB_OAUTH_STATE_COOKIE = "oauth_state_nonce"
_GITHUB_OAUTH_STATE_COOKIE_MAX_AGE = 10 * 60
_GITHUB_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def _set_github_oauth_state_cookie(response: Response, nonce: str) -> None:
    response.set_cookie(
        key=_GITHUB_OAUTH_STATE_COOKIE,
        value=nonce,
        max_age=_GITHUB_OAUTH_STATE_COOKIE_MAX_AGE,
        path=f"{settings.API_V1_PREFIX}/auth",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )


def _clear_github_oauth_state_cookie(response: Response) -> None:
    response.delete_cookie(
        key=_GITHUB_OAUTH_STATE_COOKIE,
        path=f"{settings.API_V1_PREFIX}/auth",
        secure=settings.COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new account (email + password)",
)
async def register(
    body: RegisterRequest, db: DBSession, background_tasks: BackgroundTasks
) -> MessageResponse:
    user = await register_user(
        db,
        email=body.email,
        password=body.password,
        display_name=body.display_name,
    )

    verification_token = create_verification_token(user.email)
    background_tasks.add_task(send_verification_email, user.email, verification_token)

    return MessageResponse(
        message="Account created. Check your email to verify your address."
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    response_model_exclude_none=True,
    summary="Log in and receive an access token plus refresh cookie",
)
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
    db: DBSession,
) -> TokenResponse:
    access_token, raw_refresh = await login_user(
        db,
        email=body.email,
        password=body.password,
        request=request,
    )
    set_refresh_token_cookie(response, raw_refresh)
    return TokenResponse(access_token=access_token)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    response_model_exclude_none=True,
    summary="Rotate the refresh cookie and receive a new access token",
)
async def refresh(
    request: Request,
    response: Response,
    db: DBSession,
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_TOKEN_COOKIE),
) -> TokenResponse:
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )
    access_token, new_raw_refresh = await rotate_refresh_token(
        db, refresh_token, request
    )
    set_refresh_token_cookie(response, new_raw_refresh)
    return TokenResponse(access_token=access_token)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Revoke the refresh token cookie",
)
async def logout(
    response: Response,
    db: DBSession,
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_TOKEN_COOKIE),
) -> MessageResponse:
    if refresh_token is not None:
        await logout_user(db, refresh_token)
    clear_refresh_token_cookie(response)
    return MessageResponse(message="Logged out successfully")


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser):
    return current_user


@router.get(
    "/verify-email",
    response_model=MessageResponse,
    summary="Verify email address via signed token",
)
async def verify_email(
    db: DBSession,
    token: str = Query(..., description="Signed JWT from the verification email"),
) -> MessageResponse:
    payload = decode_token(token)
    if payload.get("purpose") != "email_verify":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token purpose",
        )
    email: str | None = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token missing subject",
        )
    user = await get_user_by_email(db, email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    if user.email_verified:
        return MessageResponse(message="Email already verified")

    user.email_verified = True
    await db.commit()
    return MessageResponse(message="Email verified successfully")


@router.get(
    "/google",
    response_model=GoogleAuthResponse,
    summary="Start Google OAuth flow — returns auth URL and state for the frontend",
)
async def google_start() -> GoogleAuthResponse:
    state = create_oauth_state_token()
    auth_url = build_google_auth_url(state)
    return GoogleAuthResponse(auth_url=auth_url, state=state)


@router.post(
    "/google/callback",
    response_model=TokenResponse,
    response_model_exclude_none=True,
    summary="Complete Google OAuth — frontend forwards code and state",
)
async def google_callback(
    request: Request,
    response: Response,
    db: DBSession,
    body: GoogleCallbackRequest,
) -> TokenResponse:
    payload = decode_token(body.state)
    if payload.get("purpose") != "oauth_state":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OAuth state",
        )

    token_payload = await exchange_google_code(body.code)
    google_access = token_payload.get("access_token")
    if not google_access:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Google token response missing access_token",
        )

    profile = await fetch_google_userinfo(google_access)
    access_token, raw_refresh, _ = await login_or_register_google_user(
        db,
        profile,
        request,
    )
    set_refresh_token_cookie(response, raw_refresh)
    return TokenResponse(access_token=access_token)


# GitHub OAuth
# ---------------------------------------------------------------------------


@router.get(
    "/github",
    summary="Initiate GitHub OAuth flow",
    response_class=RedirectResponse,
    status_code=status.HTTP_302_FOUND,
)
async def github_login() -> RedirectResponse:
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth is not configured",
        )
    nonce = secrets.token_urlsafe(32)
    state = create_oauth_state_token(nonce)
    query = urlencode(
        {
            "client_id": settings.GITHUB_CLIENT_ID,
            "redirect_uri": settings.GITHUB_REDIRECT_URI,
            "scope": "user:email",
            "state": state,
        }
    )
    redirect_url = f"{_GITHUB_AUTHORIZE_URL}?{query}"
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)
    _set_github_oauth_state_cookie(response, nonce)
    return response


@router.get(
    "/github/callback",
    response_model=TokenResponse,
    response_model_exclude_none=True,
    summary="GitHub OAuth callback: exchange code for access token and refresh cookie",
)
async def github_callback(
    request: Request,
    response: Response,
    db: DBSession,
    code: str = Query(...),
    state: str = Query(...),
    oauth_state_nonce: str | None = Cookie(
        default=None,
        alias=_GITHUB_OAUTH_STATE_COOKIE,
    ),
) -> TokenResponse:
    github_client_secret = settings.GITHUB_CLIENT_SECRET.get_secret_value()
    if not settings.GITHUB_CLIENT_ID or not github_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth is not configured",
        )

    try:
        state_payload = decode_token(state)
        if state_payload.get("purpose") != "oauth_state":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OAuth state",
            )
        state_nonce = state_payload.get("nonce")
        if (
            not isinstance(state_nonce, str)
            or oauth_state_nonce is None
            or not secrets.compare_digest(state_nonce, oauth_state_nonce)
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OAuth state",
            )

        async with httpx.AsyncClient(timeout=_GITHUB_TIMEOUT) as client:
            token_resp = await client.post(
                _GITHUB_TOKEN_URL,
                data={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": github_client_secret,
                    "code": code,
                    "redirect_uri": settings.GITHUB_REDIRECT_URI,
                },
                headers={"Accept": "application/json"},
            )
            token_resp.raise_for_status()
            token_data = token_resp.json()

            if "error" in token_data:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=token_data.get(
                        "error_description", "GitHub token exchange failed"
                    ),
                )
            github_access_token: str | None = token_data.get("access_token")
            if not github_access_token:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="GitHub token exchange did not return an access token",
                )

            auth_headers = {
                "Authorization": f"Bearer {github_access_token}",
                "Accept": "application/vnd.github+json",
            }
            profile_resp = await client.get(_GITHUB_USER_URL, headers=auth_headers)
            profile_resp.raise_for_status()
            profile = profile_resp.json()

            emails_resp = await client.get(_GITHUB_EMAILS_URL, headers=auth_headers)
            emails_resp.raise_for_status()
            emails_data = emails_resp.json()
            emails = emails_data if isinstance(emails_data, list) else []

        primary_email: str | None = None
        for entry in emails:
            if not isinstance(entry, dict):
                continue
            if entry.get("primary") and entry.get("verified"):
                primary_email = entry["email"]
                break

        if not primary_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No verified primary email on GitHub account",
            )

        user = await get_or_create_github_user(
            db,
            email=primary_email,
            display_name=profile.get("name") or profile.get("login"),
            avatar_url=profile.get("avatar_url"),
            github_username=profile.get("login"),
        )

        access_token, raw_refresh = await issue_auth_tokens(db, user, request)
        set_refresh_token_cookie(response, raw_refresh)
        _clear_github_oauth_state_cookie(response)
        return TokenResponse(access_token=access_token)
    except httpx.HTTPStatusError as exc:
        detail = "GitHub token exchange failed"
        if exc.response.request.url == httpx.URL(_GITHUB_USER_URL):
            detail = "Unable to fetch GitHub user profile"
        elif exc.response.request.url == httpx.URL(_GITHUB_EMAILS_URL):
            detail = "Unable to fetch GitHub user email"
        _clear_github_oauth_state_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=detail,
        ) from exc
    except httpx.RequestError as exc:
        _clear_github_oauth_state_cookie(response)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to reach GitHub OAuth service",
        ) from exc
    except HTTPException:
        _clear_github_oauth_state_cookie(response)
        raise


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request a password reset link",
)
async def forgot_password(
    body: ForgotPasswordRequest, db: DBSession
) -> MessageResponse:
    raw_token = await create_password_reset_token(db, body.email)
    if raw_token is not None:
        reset_url = f"{settings.FRONTEND_URL}/reset-password#{raw_token}"
        send_password_reset_email(body.email, reset_url)
    return MessageResponse(message="If this email exists, a reset link has been sent.")


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset password using a valid reset token",
)
async def reset_password_endpoint(
    body: ResetPasswordRequest, db: DBSession
) -> MessageResponse:
    success = await reset_password(db, body.token, body.new_password)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )
    return MessageResponse(message="Password updated. Please sign in.")
