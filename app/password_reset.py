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
        send_email(username, "Password Reset", f"Reset your password:\n{link}")

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
