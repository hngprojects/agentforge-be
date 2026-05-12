import logging

import sib_api_v3_sdk
from sib_api_v3_sdk.configuration import Configuration
from sib_api_v3_sdk.rest import ApiException

from app.core.config import settings

logger = logging.getLogger(__name__)


# def send_verification_email(_to_email: str, _token: str) -> None:
#     """
#     Stub: in production, dispatch a real email via your provider.
#     Keep token delivery behind this boundary so endpoints never log secrets.
#     """
#     logger.info("Verification email queued")


def _build_verification_email(email: str, verification_url: str) -> tuple[str, str]:
    """Return (plain-text body, html body) for the verification email."""
    plain = (
        f"Hi,\n\n"
        f"Thanks for signing up! Please verify your email address by visiting the link below:\n\n"
        f"{verification_url}\n\n"
        f"This link expires in {settings.VERIFICATION_TOKEN_TTL_HOURS} hour(s).\n\n"
        f"If you didn't create an account, you can safely ignore this email.\n\n"
        f"— The Agent Forge Team"
    )
    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Verify your email</title>
</head>
<body style="margin:0;padding:0;background:#f0f4f4;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f4;padding:48px 0;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0"
               style="background:#ffffff;border-radius:12px;overflow:hidden;
                      box-shadow:0 4px 24px rgba(0,95,90,.10);">

          <!-- Header -->
          <tr>
            <td style="background:#005f5a;padding:36px 40px;text-align:center;">
              <!-- Logo mark -->
              <div style="display:inline-block;margin-bottom:16px;">
                <table cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="background:rgba(255,255,255,0.15);border-radius:10px;
                                padding:10px 14px;text-align:center;">
                      <span style="color:#ffffff;font-size:18px;font-weight:800;
                                   letter-spacing:-0.5px;">
                        Agent Forge
                      </span>
                    </td>
                  </tr>
                </table>
              </div>
              <br/>
              <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700;
                         letter-spacing:-0.3px;line-height:1.3;">
                Confirm your email address
              </h1>
            </td>
          </tr>

          <!-- Accent bar -->
          <tr>
            <td style="background:#004744;height:3px;font-size:0;line-height:0;">&nbsp;</td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:40px 40px 32px;">
              <p style="margin:0 0 12px;color:#111827;font-size:15px;
                        font-weight:600;line-height:1.5;">
                Hi there,
              </p>
              <p style="margin:0 0 20px;color:#374151;font-size:15px;line-height:1.7;">
                Thanks for signing up! You're almost there — just click the button
                below to confirm your email address and activate your account.
              </p>

              <!-- Expiry notice -->
              <table cellpadding="0" cellspacing="0" width="100%" style="margin-bottom:28px;">
                <tr>
                  <td style="background:#f0f9f8;border-left:3px solid #005f5a;
                              border-radius:0 6px 6px 0;padding:12px 16px;">
                    <p style="margin:0;color:#005f5a;font-size:13px;line-height:1.5;">
                      ⏱ This link expires in
                      <strong>{settings.VERIFICATION_TOKEN_TTL_HOURS} hour(s)</strong>.
                      Please verify soon.
                    </p>
                  </td>
                </tr>
              </table>

              <!-- CTA button -->
              <table cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td align="center">
                    <a href="{verification_url}"
                       style="display:inline-block;background:#005f5a;color:#ffffff;
                              text-decoration:none;padding:15px 40px;border-radius:8px;
                              font-size:15px;font-weight:700;letter-spacing:0.2px;
                              box-shadow:0 4px 12px rgba(0,95,90,0.3);">
                      Verify Email Address →
                    </a>
                  </td>
                </tr>
              </table>

              <!-- Fallback URL -->
              <p style="margin:28px 0 0;color:#9ca3af;font-size:12px;line-height:1.7;">
                Button not working? Copy and paste this link into your browser:<br/>
                <a href="{verification_url}"
                   style="color:#005f5a;word-break:break-all;font-size:11px;">
                  {verification_url}
                </a>
              </p>
            </td>
          </tr>

          <!-- Divider -->
          <tr>
            <td style="padding:0 40px;">
              <div style="border-top:1px solid #e5e7eb;"></div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:24px 40px 32px;">
              <p style="margin:0 0 8px;color:#9ca3af;font-size:12px;
                        text-align:center;line-height:1.7;">
                If you didn't create an account, you can safely ignore this email.
                No action is required.
              </p>
              <p style="margin:0;color:#9ca3af;font-size:12px;
                        text-align:center;line-height:1.7;">
                This email was sent to
                <strong style="color:#6b7280;">{email}</strong>
              </p>
            </td>
          </tr>

          <!-- Bottom brand bar -->
          <tr>
            <td style="background:#f9fafb;border-top:1px solid #e5e7eb;
                        padding:16px 40px;text-align:center;">
              <p style="margin:0;color:#9ca3af;font-size:11px;letter-spacing:0.3px;">
                © 2025 Agent Forge. All rights reserved.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
    return plain, html


def send_email(
    to_email: str,
    subject: str,
    html_body: str,
    plain_body: str,
    to_name: str = "",
) -> None:
    """Generic reusable email sender via Brevo."""
    configuration = Configuration()
    configuration.api_key["api-key"] = settings.BREVO_API_KEY

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email, "name": to_name}],
        sender={"name": settings.SMTP_FROM_NAME, "email": settings.SMTP_FROM_EMAIL},
        subject=subject,
        html_content=html_body,
        text_content=plain_body,
    )
    try:
        api_instance.send_transac_email(send_smtp_email)
        logger.info("Email sent to %s | subject: %s", to_email, subject)
    except ApiException:
        logger.exception("Failed to send email to %s | subject: %s", to_email, subject)
        raise


def send_contact_admin_notification(
    full_name: str, email: str, phone: str | None, message: str
) -> None:
    """Notify admin when a new contact form is submitted."""
    html_body = f"""
    <h2>New Contact Form Submission</h2>
    <p><strong>Name:</strong> {full_name}</p>
    <p><strong>Email:</strong> {email}</p>
    <p><strong>Phone:</strong> {phone or "—"}</p>
    <hr/>
    <p><strong>Message:</strong></p>
    <p>{message}</p>
    """
    plain_body = (
        f"New Contact Form Submission\n\n"
        f"Name: {full_name}\nEmail: {email}\nPhone: {phone or '—'}\n\nMessage:\n{message}"
    )
    send_email(
        to_email=settings.ADMIN_EMAIL,
        to_name="Admin",
        subject=f"New contact message from {full_name}",
        html_body=html_body,
        plain_body=plain_body,
    )


def send_verification_email(email: str, token: str) -> None:
    verification_url = (
        f"{settings.FRONTEND_URL.rstrip('/')}/confirm-email?token={token}&email={email}"
    )
    plain_body, html_body = _build_verification_email(email, verification_url)

    configuration = Configuration()
    configuration.api_key["api-key"] = settings.BREVO_API_KEY

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": email}],
        sender={"name": settings.SMTP_FROM_NAME, "email": settings.SMTP_FROM_EMAIL},
        subject="Verify your email address",
        html_content=html_body,
        text_content=plain_body,
    )

    try:
        api_instance.send_transac_email(send_smtp_email)
        logger.info("Verification email sent to %s via Brevo", email)
    except ApiException:
        logger.exception("Failed to send verification email to %s", email)
        raise


def send_password_reset_email(_to_email: str, _reset_url: str) -> None:
    """
    Stub: swap this body for a real provider (SendGrid, Resend, SES, etc.) when ready.
    Never log the reset URL here — it contains a bearer token.
    """
    logger.info("Password reset email queued")
