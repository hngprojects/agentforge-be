from fastapi import APIRouter, Cookie, HTTPException, Query, Request, Response, status

from app.api.deps import CurrentUser, DBSession
from app.core.security import (
    create_oauth_state_token,
    create_verification_token,
    decode_token,
)
from app.schemas.auth import (
    GoogleAuthResponse,
    GoogleCallbackRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth import (
    REFRESH_TOKEN_COOKIE,
    build_google_auth_url,
    clear_refresh_token_cookie,
    exchange_google_code,
    fetch_google_userinfo,
    get_user_by_email,
    login_or_register_google_user,
    login_user,
    logout_user,
    register_user,
    rotate_refresh_token,
    set_refresh_token_cookie,
)
from app.services.email import send_verification_email

router = APIRouter()


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new account (email + password)",
)
async def register(body: RegisterRequest, db: DBSession) -> MessageResponse:
    user = await register_user(
        db,
        email=body.email,
        password=body.password,
        display_name=body.display_name,
    )

    verification_token = create_verification_token(user.email)
    send_verification_email(user.email, verification_token)

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
