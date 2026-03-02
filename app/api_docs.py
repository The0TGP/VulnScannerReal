from fastapi import APIRouter, Request

router = APIRouter()

# List of API endpoints to display
ENDPOINTS = [
    {"method": "GET", "url": "/", "description": "Home page"},
    {"method": "POST", "url": "/scan", "description": "Start a vulnerability scan"},
    {"method": "GET", "url": "/dashboard", "description": "User dashboard"},
    {"method": "GET", "url": "/login", "description": "Login page"},
    {"method": "POST", "url": "/login", "description": "Log in"},
    {"method": "GET", "url": "/register", "description": "User registration"},
    {"method": "POST", "url": "/register", "description": "Create a new account"},
    {"method": "GET", "url": "/verify/{token}", "description": "Verify email"},
    {"method": "GET", "url": "/password-reset", "description": "Request password reset"},
    {"method": "POST", "url": "/password-reset", "description": "Send password reset email"},
    {"method": "GET", "url": "/reset/{token}", "description": "Password reset form"},
    {"method": "POST", "url": "/reset/{token}", "description": "Save new password"},
    {"method": "GET", "url": "/analytics", "description": "Data analytics dashboard"},
    {"method": "GET", "url": "/admin", "description": "Admin panel"},
    {"method": "POST", "url": "/admin/make-admin", "description": "Promote a user to admin"},
    {"method": "POST", "url": "/admin/delete-user", "description": "Delete a user"},
    {"method": "POST", "url": "/admin/delete-scan", "description": "Delete a scan result"},
]


@router.get("/api-docs")
def docs(request: Request):
    return request.app.templates.TemplateResponse(
        "api_docs.html",
        {"request": request, "endpoints": ENDPOINTS}
    )
