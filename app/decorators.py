from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from .crypto import crypto
from .database import db
from .models import User


# =====================================================
# CURRENT USER EXTRACTION
# =====================================================

async def get_current_user(request: Request) -> User | None:
    """Pull the authenticated user from the session, or return None."""
    user_id = request.session.get("user_id")
    if user_id is None:
        return None
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


def _set_flash(request: Request, message: str, category: str = "info") -> None:
    """Store a flash message in the session (duplicated from routes.py
    to keep dependency redirects self-contained)."""
    flashes = request.session.get("_flashes", [])
    flashes.append({"category": category, "message": message})
    request.session["_flashes"] = flashes


# =====================================================
# DEPENDENCIES
# =====================================================

async def require_user(
    request: Request,
    user: User | None = Depends(get_current_user),
) -> User:
    """FastAPI dependency – require an authenticated user (redirect on failure)."""
    if user is None or not user.is_authenticated:
        _set_flash(request, "Please log in to access this page.", "warning")
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    return user


async def require_admin(
    request: Request,
    user: User = Depends(require_user),
) -> User:
    """FastAPI dependency – require the ADMIN role."""
    try:
        role = crypto.decrypt(user.role_enc)
    except Exception:
        role = "INVALID"
    if role != "ADMIN":
        _set_flash(request, "Administrator access required.", "danger")
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/dashboard"},
        )
    return user
