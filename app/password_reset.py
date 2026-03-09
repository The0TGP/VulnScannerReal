import secrets
from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse
from passlib.hash import pbkdf2_sha256

from .database import SessionLocal
from .models import User, PasswordResetToken
from .emailer import send_email

router = APIRouter()


@router.get("/password-reset")
def page(request: Request):
    return request.app.templates.TemplateResponse(
        "password_reset.html",
        {"request": request}
    )


@router.post("/password-reset")
def start_reset(request: Request, username: str = Form(...)):
    db = SessionLocal()
    user = db.query(User).filter(User.username == username).first()

    if user:
        token = secrets.token_urlsafe(32)
        entry = PasswordResetToken(username=username, token=token)
        db.add(entry)
        db.commit()

        link = f"http://localhost:8000/reset/{token}"
        html_email = f"""
<div style="font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5;">
  <div style="max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 10px;">
    <h2 style="color: #ff4d4d;">Reset Your Password</h2>
    <p>You requested a password reset. Click the button below to create a new password:</p>
    <div style="text-align:center; margin: 30px 0;">
      <a href="{link}" style="
        background: #ff4d4d;
        color: white;
        padding: 12px 22px;
        text-decoration: none;
        font-weight: bold;
        border-radius: 6px;
        display: inline-block;">
        Reset Password
      </a>
    </div>
    <p>If this wasn’t you, simply ignore this email.</p>
    <p>Stay secure,<br><strong>VulnScanner Team</strong></p>
  </div>
</div>
"""
send_email(
    username,
    "Reset Your VulnScanner Password",
    f"Reset your password: {link}",
    html_email
)

    return RedirectResponse("/login", status_code=302)


@router.get("/reset/{token}")
def form(request: Request, token: str):
    return request.app.templates.TemplateResponse(
        "reset_form.html",
        {"request": request, "token": token}
    )


@router.post("/reset/{token}")
def apply_reset(token: str, password: str = Form(...)):
    db = SessionLocal()
    entry = db.query(PasswordResetToken).filter_by(token=token).first()

    if entry:
        user = db.query(User).filter_by(username=entry.username).first()
        user.password = pbkdf2_sha256.hash(password)
        db.delete(entry)
        db.commit()

    return RedirectResponse("/login", status_code=302)

