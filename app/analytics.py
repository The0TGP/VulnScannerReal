from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
import json

from .database import SessionLocal
from .models import ScanResult, User

router = APIRouter()


def is_admin(request: Request):
    user = request.cookies.get("user", None)
    if not user:
        return False
    db = SessionLocal()
    u = db.query(User).filter_by(username=user).first()
    return u and u.is_admin


@router.get("/analytics")
def analytics_page(request: Request):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=302)

    db = SessionLocal()

    scans = db.query(ScanResult).all()

    # Stats
    total_scans = len(scans)
    open_port_counts = {}
    xss_count = 0
    sqli_count = 0
    tls_issues = 0

    # Process scan results
    for scan in scans:
        ports = json.loads(scan.ports)
        headers = json.loads(scan.headers)
        tls = json.loads(scan.tls)
        inj = json.loads(scan.injection)

        # Count open ports
        for port, state in ports.items():
            if state == "open":
                open_port_counts[port] = open_port_counts.get(port, 0) + 1

        # Injection stats
        if inj.get("xss") == "potential":
            xss_count += 1
        if inj.get("sqli") == "potential":
            sqli_count += 1

        # TLS stats
        if "error" in tls:
            tls_issues += 1

    return request.app.templates.TemplateResponse(
        "analytics.html",
        {
            "request": request,
            "total_scans": total_scans,
            "open_port_counts": open_port_counts,
            "xss_count": xss_count,
            "sqli_count": sqli_count,
            "tls_issues": tls_issues,
            "scans": scans
        }
    )
