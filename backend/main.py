import uvicorn
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from database import get_db, close_db
from config import APP_HOST, APP_PORT

from routers import devices, capture, analysis, flows, panos


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: init DB
    await get_db()
    yield
    # Shutdown: close DB
    await close_db()


app = FastAPI(
    title="IoT Onboarding Tool",
    description="Automate IoT device network onboarding with traffic capture, analysis, and firewall rule generation.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(devices.router)
app.include_router(capture.router)
app.include_router(analysis.router)
app.include_router(flows.router)
app.include_router(panos.router)

# Health check
@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}

# Serve frontend static files (production)
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


if __name__ == "__main__":
    uvicorn.run("main:app", host=APP_HOST, port=APP_PORT, reload=True)
