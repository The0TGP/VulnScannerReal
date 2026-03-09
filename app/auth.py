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
    send_email(username, "Verify Your Email", f"Click to verify: {verification_link}")
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

