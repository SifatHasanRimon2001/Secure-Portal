import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .database import db

# Load environment variables once at import time so both the lifespan
# and test scripts get them without needing the full app lifecycle.
load_dotenv()


def _resolve_instance_path() -> Path:
    instance = Path.cwd() / "instance"
    instance.mkdir(parents=True, exist_ok=True)
    return instance


def init_database() -> None:
    """Initialise the database connection, create tables, and seed the admin."""
    database_url = os.getenv(
        "DATABASE_URL",
        "sqlite:///instance/secure_portal.db",
    )
    db.init_app(database_url)
    db.create_all()

    from .services import create_admin_if_missing
    create_admin_if_missing()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Application lifespan – runs once at startup."""
    init_database()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="Secure Portal", lifespan=lifespan)

    # ---- Session middleware (signed cookies) -------------------------------
    secret = os.getenv("SECRET_KEY", os.urandom(32).hex())
    app.add_middleware(SessionMiddleware, secret_key=secret)

    # ---- Static files ------------------------------------------------------
    static_dir = Path(__file__).resolve().parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ---- Templates ---------------------------------------------------------
    template_dir = Path(__file__).resolve().parent / "templates"
    templates = Jinja2Templates(directory=str(template_dir))
    app.state.templates = templates

    # ---- Register routers --------------------------------------------------
    from .routes import router, init_templates
    app.include_router(router)
    init_templates(app)

    return app
