from functools import wraps
from flask import (
    flash,
    redirect,
    url_for
)
from flask_login import (
    current_user
)
from .crypto import crypto
def get_role(user):
    try:
        return crypto.decrypt(
            user.role_enc
        )
    except Exception:
        return "INVALID"
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(
                url_for("auth.login")
            )
        role = get_role(
            current_user
        )
        if role != "ADMIN":
            flash(
                "Administrator access required.",
                "danger"
            )
            return redirect(
                url_for("auth.dashboard")
            )
        return func(
            *args,
            **kwargs
        )
    return wrapper