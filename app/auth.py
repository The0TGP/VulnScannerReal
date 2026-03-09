python


import os
import secrets
from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse
from passlib.hash import pbkdf2_sha256
from .database import SessionLocal
from .models import User, EmailVerification
from .emailer import send_email
router = APIRouter()
# Load BASE_URL from Render environment
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
def get_user(db, username):
    return db.query(User).filter(User.username == username).first()
@router.get("/login")
def login_page(request: Request):
    return request.app.templates.TemplateResponse(
        "login.html",
        {"request": request}
    )
@router.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    user = get_user(db, username)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if not user.is_verified:
        return request.app.templates.TemplateResponse(
            "verify_email.html",
            {"request": request, "message": "Please verify your email before logging in."}
        )
    if pbkdf2_sha256.verify(password, user.password):
        response = RedirectResponse("/dashboard", status_code=302)
        response.set_cookie("user", username)
        return response
    return RedirectResponse("/login", status_code=302)
@router.get("/register")
def register_page(request: Request):
    return request.app.templates.TemplateResponse(
        "register.html",
        {"request": request}
    )
@router.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    # Check if user already exists
    if get_user(db, username):
        return request.app.templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "User already exists."}
        )
    # Create user (not verified yet)
    hashed = pbkdf2_sha256.hash(password)
    new_user = User(username=username, password=hashed, is_verified=False)
    db.add(new_user)
    db.commit()
    # Create verification token
    token = secrets.token_urlsafe(32)
    entry = EmailVerification(username=username, token=token)
    db.add(entry)
    db.commit()
    # Generate verification link
    verification_link = f"{BASE_URL}/verify/{token}"
    # Send email
    html_email = f"""
<div style="font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5;">
  <div style="max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 10px;">
    <h2 style="color: #0078ff;">Verify Your VulnScanner Account</h2>
    <p>Hi there,</p>
    <p>Thanks for creating a VulnScanner account! Please click the button below to verify your email.</p>
    <div style="text-align:center; margin: 30px 0;">
      <a href="{verification_link}" style="
        background: #0078ff;
        color: white;
        padding: 12px 22px;
        text-decoration: none;
        font-weight: bold;
        border-radius: 6px;
        display: inline-block;">
        Verify Email
      </a>
    </div>
    <p>If the button doesn't work, paste this URL into your browser:</p>
    <p style="background:#f0f0f0; padding:10px; border-radius:5px; font-size:14px;">
      {verification_link}
    </p>
    <p>Stay secure,<br><strong>VulnScanner Team</strong></p>
  </div>
</div>
"""
send_email(
    username,
    "Verify Your VulnScanner Account",
    f"Click to verify: {verification_link}",
    html_email
)
    return request.app.templates.TemplateResponse(
        "verify_email.html",
        {"request": request, "message": "Verification email sent. Check your inbox."}
    )
@router.get("/verify/{token}")
def verify_email(request: Request, token: str):
    db = SessionLocal()
    entry = db.query(EmailVerification).filter_by(token=token).first()
    if not entry:
        return request.app.templates.TemplateResponse(
            "verify_email.html",
            {"request": request, "message": "Invalid or expired verification link."}
        )
    # Mark user as verified
    user = get_user(db, entry.username)
    user.is_verified = True
    # Remove token
    db.delete(entry)
    db.commit()
    return request.app.templates.TemplateResponse(
        "login.html",
        {"request": request, "message": "Email verified. You can now log in."}
    )


