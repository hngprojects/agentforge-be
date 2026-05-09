import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


def send_verification_email(_to_email: str, _token: str) -> None:
    """
    Stub: in production, dispatch a real email via your provider.
    Keep token delivery behind this boundary so endpoints never log secrets.
    """
    logger.info("Verification email queued")


async def send_password_reset_email(email: str, reset_url: str) -> None:
    if settings.SENDGRID_API_KEY:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.sendgrid.com/v3/mail/send",
                    headers={
                        "Authorization": f"Bearer {settings.SENDGRID_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "personalizations": [{"to": [{"email": email}]}],
                        "from": {"email": settings.SENDGRID_FROM_EMAIL},
                        "subject": "Reset your password",
                        "content": [
                            {
                                "type": "text/plain",
                                "value": f"Click to reset your password: {reset_url}",
                            }
                        ],
                    },
                    timeout=10,
                )
                response.raise_for_status()
        except Exception:
            logger.exception("Failed to send password reset email via SendGrid")
    elif settings.APP_ENV == "development":
        print(f"[DEV] Password reset link: {reset_url}")
    else:
        logger.error(
            "SENDGRID_API_KEY is not configured; password reset email suppressed"
        )
