from fastapi import FastAPI, Request, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .database import Base, engine
from .websocket_manager import manager
from . import auth, admin, analytics, api_docs, password_reset
from .scanner import start_scan_background

# Create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Static files + template engine
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# Routers
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(analytics.router)
app.include_router(api_docs.router)
app.include_router(password_reset.router)


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(scan_id, websocket)
    while True:
        try:
            await websocket.receive_text()
        except:
            break


@app.post("/scan")
async def scan(request: Request):
    form = await request.form()
    target = form["target"]

    scan_id = target.replace(".", "_")
    start_scan_background(target, scan_id)

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "scan_id": scan_id}
    )
