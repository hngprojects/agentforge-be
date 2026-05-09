import logging

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

from app.api.deps import CurrentUser, DBSession
from app.core.config import settings
from app.core.security import create_verification_token, decode_token
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth import (
    create_password_reset_token,
    get_user_by_email,
    login_user,
    logout_user,
    register_user,
    reset_password,
    rotate_refresh_token,
)
from app.services.email import send_password_reset_email, send_verification_email

router = APIRouter()
logger = logging.getLogger(__name__)


async def _deliver_reset_email(email: str, reset_url: str) -> None:
    try:
        await send_password_reset_email(email, reset_url)
    except Exception:
        logger.exception("Background task: failed to deliver password reset email")


_REFRESH_TOKEN_COOKIE = "refresh_token"
_REFRESH_TOKEN_COOKIE_PATH = f"{settings.API_V1_PREFIX}/auth"
_REFRESH_TOKEN_COOKIE_MAX_AGE = settings.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60


def _set_refresh_token_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=_REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        max_age=_REFRESH_TOKEN_COOKIE_MAX_AGE,
        path=_REFRESH_TOKEN_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _clear_refresh_token_cookie(response: Response) -> None:
    response.delete_cookie(
        key=_REFRESH_TOKEN_COOKIE,
        path=_REFRESH_TOKEN_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="strict",
    )


# ---------------------------------------------------------------------------
# POST /register
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# POST /login
# ---------------------------------------------------------------------------


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
    _set_refresh_token_cookie(response, raw_refresh)
    return TokenResponse(access_token=access_token)


# ---------------------------------------------------------------------------
# POST /refresh
# ---------------------------------------------------------------------------


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
    refresh_token: str | None = Cookie(default=None, alias=_REFRESH_TOKEN_COOKIE),
) -> TokenResponse:
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )
    access_token, new_raw_refresh = await rotate_refresh_token(
        db, refresh_token, request
    )
    _set_refresh_token_cookie(response, new_raw_refresh)
    return TokenResponse(access_token=access_token)


# ---------------------------------------------------------------------------
# POST /logout
# ---------------------------------------------------------------------------


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Revoke the refresh token cookie",
)
async def logout(
    response: Response,
    db: DBSession,
    refresh_token: str | None = Cookie(default=None, alias=_REFRESH_TOKEN_COOKIE),
) -> MessageResponse:
    if refresh_token is not None:
        await logout_user(db, refresh_token)
    _clear_refresh_token_cookie(response)
    return MessageResponse(message="Logged out successfully")


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser):
    return current_user


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request a password reset link",
)
async def forgot_password(
    body: ForgotPasswordRequest, db: DBSession, background_tasks: BackgroundTasks
) -> MessageResponse:
    raw_token = await create_password_reset_token(db, body.email)
    if raw_token is not None:
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={raw_token}"
        background_tasks.add_task(_deliver_reset_email, body.email, reset_url)
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
