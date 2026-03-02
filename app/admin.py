from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse

from .database import SessionLocal
from .models import User, ScanResult

router = APIRouter()


def is_admin(request: Request):
    user = request.cookies.get("user", None)
    if not user:
        return False
    db = SessionLocal()
    u = db.query(User).filter_by(username=user).first()
    return u and u.is_admin


@router.get("/admin")
def admin_page(request: Request):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=302)

    db = SessionLocal()
    users = db.query(User).all()
    scans = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).all()

    return request.app.templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "users": users,
            "scans": scans
        }
    )


@router.post("/admin/make-admin")
def make_admin(username: str = Form(...)):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    if user:
        user.is_admin = True
        db.commit()
    return RedirectResponse("/admin", status_code=302)


@router.post("/admin/delete-user")
def delete_user(username: str = Form(...)):
    db = SessionLocal()
    user = db.query(User).filter_by(username=username).first()
    if user:
        db.delete(user)
        db.commit()
    return RedirectResponse("/admin", status_code=302)


@router.post("/admin/delete-scan")
def delete_scan(id: int = Form(...)):
    db = SessionLocal()
    scan = db.query(ScanResult).filter_by(id=id).first()
    if scan:
        db.delete(scan)
        db.commit()
    return RedirectResponse("/admin", status_code=302)
