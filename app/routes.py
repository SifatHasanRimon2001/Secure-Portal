from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .database import db
from .decorators import get_current_user, require_admin, require_user
from .forms import (
    CredentialCheckForm,
    LoginForm,
    PostForm,
    RegisterForm,
)
from .models import AuditLog, SecurePost, User
from .services import (
    create_audit_log,
    decrypt_post_for_user,
    delete_user,
    encrypt_post_for_user,
    format_timestamp,
    get_all_users,
    get_audit_logs,
    get_created_at,
    get_display_name,
    get_next_post_serial_number,
    get_username,
    get_user_role,
    register_user,
    username_lookup,
    verify_credentials,
    verify_user_integrity,
)

router = APIRouter()

# -- Template helpers ---------------------------------------------------------

_templates: Jinja2Templates | None = None


def _get_templates() -> Jinja2Templates:
    global _templates
    if _templates is None:
        from fastapi import FastAPI
        raise RuntimeError("Templates not initialised – call init_templates(app)")
    return _templates


def init_templates(app: "FastAPI") -> None:
    global _templates
    _templates = app.state.templates


def _flash(request: Request, message: str, category: str = "info") -> None:
    """Store a flash message in the session."""
    flashes = request.session.get("_flashes", [])
    flashes.append({"category": category, "message": message})
    request.session["_flashes"] = flashes


def _build_context(
    request: Request,
    current_user: User | None,
    **extra,
) -> dict:
    """Build the full template context.

    Exposes everything the existing templates expect:
    ``request``, ``url_for``, ``get_flashed_messages``,
    ``current_user``, and ``user_role``.
    """
    # Consume any queued flash messages
    flashes = request.session.pop("_flashes", [])

    def get_flashed_messages(with_categories=False):
        if with_categories:
            return [(f["category"], f["message"]) for f in flashes]
        return [f["message"] for f in flashes]

    def url_for(name: str, **params: str) -> str:
        """Template-friendly URL generator (handles Flask-style ``filename`` for static files)."""
        if name == "static":
            # StaticFiles mounts use ``path`` internally, but templates pass ``filename``
            return f"/static/{params.get('filename', '')}"
        return str(request.url_for(name, **params))

    context = {
        "request": request,
        "url_for": url_for,
        "get_flashed_messages": get_flashed_messages,
        "current_user": current_user,
    }

    if current_user and current_user.is_authenticated:
        try:
            context["user_role"] = get_user_role(current_user)
        except Exception:
            context["user_role"] = "USER"
    else:
        context["user_role"] = None

    context.update(extra)
    return context


def _make_form_from_request(form_class, form_data):
    """Instantiate a WTForms Form from Starlette ``FormData``."""
    # WTForms accepts a dict-like object as the first positional arg (formdata)
    return form_class(formdata=form_data)


# =====================================================
# HOME
# =====================================================
@router.get("/", name="auth.index")
async def index(request: Request):
    user = await get_current_user(request)
    if user and user.is_authenticated:
        return RedirectResponse(url=request.url_for("auth.dashboard"), status_code=302)
    return RedirectResponse(url=request.url_for("auth.login"), status_code=302)


# =====================================================
# REGISTER
# =====================================================
@router.get("/register", name="auth.register")
async def register_get(request: Request):
    user = await get_current_user(request)
    form = RegisterForm()
    templates = _get_templates()
    return templates.TemplateResponse(
        "register.html",
        _build_context(request, user, form=form),
    )


@router.post("/register", name="auth.register_post")
async def register_post(request: Request):
    user = await get_current_user(request)
    form_data = await request.form()
    form = _make_form_from_request(RegisterForm, form_data)
    templates = _get_templates()

    if form.validate():
        username = form.username.data
        display_name = form.display_name.data
        password = form.password.data

        new_user = register_user(username, display_name, password)

        if not new_user:
            _flash(request, "Username already exists.", "danger")
            return templates.TemplateResponse(
                "register.html",
                _build_context(request, user, form=form),
            )

        _flash(request, "Account created successfully! Please log in.", "success")
        return RedirectResponse(
            url=request.url_for("auth.login"), status_code=302
        )

    return templates.TemplateResponse(
        "register.html",
        _build_context(request, user, form=form),
    )


# =====================================================
# LOGIN
# =====================================================
@router.get("/login", name="auth.login")
async def login_get(request: Request):
    user = await get_current_user(request)
    if user and user.is_authenticated:
        return RedirectResponse(url=request.url_for("auth.dashboard"), status_code=302)
    form = LoginForm()
    templates = _get_templates()
    return templates.TemplateResponse(
        "login.html",
        _build_context(request, user, form=form),
    )


@router.post("/login", name="auth.login_post")
async def login_post(request: Request):
    user = await get_current_user(request)
    form_data = await request.form()
    form = _make_form_from_request(LoginForm, form_data)
    templates = _get_templates()

    if form.validate():
        username = form.username.data
        password = form.password.data

        user_obj = User.query.filter_by(
            username_lookup=username_lookup(username)
        ).first()

        if not user_obj:
            _flash(request, "Invalid credentials.", "danger")
            return templates.TemplateResponse(
                "login.html",
                _build_context(request, user, form=form),
            )

        if not verify_user_integrity(user_obj):
            _flash(request, "Account integrity failure.", "danger")
            return templates.TemplateResponse(
                "login.html",
                _build_context(request, user, form=form),
            )

        if not verify_credentials(user_obj, password):
            _flash(request, "Invalid credentials.", "danger")
            return templates.TemplateResponse(
                "login.html",
                _build_context(request, user, form=form),
            )

        # Store user in session
        request.session["user_id"] = str(user_obj.id)

        create_audit_log(
            "LOGIN",
            get_username(user_obj),
            get_username(user_obj),
        )

        _flash(request, "Login successful!", "success")
        return RedirectResponse(
            url=request.url_for("auth.dashboard"), status_code=302
        )

    return templates.TemplateResponse(
        "login.html",
        _build_context(request, user, form=form),
    )


# =====================================================
# LOGOUT
# =====================================================
@router.get("/logout", name="auth.logout")
async def logout(request: Request, current_user: User = Depends(require_user)):
    create_audit_log(
        "LOGOUT",
        get_username(current_user),
        get_username(current_user),
    )
    request.session.pop("user_id", None)
    _flash(request, "You have been logged out.", "info")
    return RedirectResponse(url=request.url_for("auth.login"), status_code=302)


# =====================================================
# DASHBOARD
# =====================================================
@router.get("/dashboard", name="auth.dashboard")
async def dashboard_get(request: Request, current_user: User = Depends(require_user)):
    if not verify_user_integrity(current_user):
        _flash(request, "Integrity check failed.", "danger")
        request.session.pop("user_id", None)
        return RedirectResponse(url=request.url_for("auth.login"), status_code=302)

    form = PostForm()
    templates = _get_templates()

    raw_posts = SecurePost.query.filter_by(
        user_id=current_user.id
    ).order_by(SecurePost.id.asc()).all()

    posts = []
    for post in raw_posts:
        posts.append({
            "id": post.id,
            "serial_number": post.serial_number,
            "created_at": post.created_at,
            "content": decrypt_post_for_user(current_user, post),
        })
    posts.reverse()

    return templates.TemplateResponse(
        "dashboard.html",
        _build_context(request, current_user, **{
            "username": get_username(current_user),
            "display_name": get_display_name(current_user),
            "role": get_user_role(current_user),
            "form": form,
            "posts": posts,
        }),
    )


@router.post("/dashboard", name="auth.dashboard_post")
async def dashboard_post(request: Request, current_user: User = Depends(require_user)):
    if not verify_user_integrity(current_user):
        _flash(request, "Integrity check failed.", "danger")
        request.session.pop("user_id", None)
        return RedirectResponse(url=request.url_for("auth.login"), status_code=302)

    form_data = await request.form()
    form = _make_form_from_request(PostForm, form_data)
    templates = _get_templates()

    if form.validate():
        content = form.content.data.strip()
        ciphertext, mac = encrypt_post_for_user(current_user, content)
        serial_number = get_next_post_serial_number(current_user)

        post = SecurePost(
            user_id=current_user.id,
            serial_number=serial_number,
            created_at=datetime.utcnow(),
            ciphertext=ciphertext,
            mac=mac,
        )
        db.session.add(post)
        db.session.commit()

        create_audit_log(
            "CREATE_POST",
            get_username(current_user),
            str(post.id),
        )

        _flash(request, "Encrypted post saved successfully!", "success")
        return RedirectResponse(
            url=request.url_for("auth.dashboard"), status_code=302
        )

    # Validation failed – re-render with existing posts
    raw_posts = SecurePost.query.filter_by(
        user_id=current_user.id
    ).order_by(SecurePost.id.asc()).all()

    posts = []
    for post in raw_posts:
        posts.append({
            "id": post.id,
            "serial_number": post.serial_number,
            "created_at": post.created_at,
            "content": decrypt_post_for_user(current_user, post),
        })
    posts.reverse()

    return templates.TemplateResponse(
        "dashboard.html",
        _build_context(request, current_user, **{
            "username": get_username(current_user),
            "display_name": get_display_name(current_user),
            "role": get_user_role(current_user),
            "form": form,
            "posts": posts,
        }),
    )


# =====================================================
# CREDENTIAL CHECK
# =====================================================
@router.get("/credentials", name="auth.credentials")
async def credentials_get(request: Request, current_user: User = Depends(require_user)):
    form = CredentialCheckForm()
    templates = _get_templates()
    return templates.TemplateResponse(
        "credentials.html",
        _build_context(request, current_user, **{
            "form": form,
            "verified": False,
            "username": get_username(current_user),
            "display_name": get_display_name(current_user),
            "role": get_user_role(current_user),
            "created_at": format_timestamp(get_created_at(current_user)),
        }),
    )


@router.post("/credentials", name="auth.credentials_post")
async def credentials_post(request: Request, current_user: User = Depends(require_user)):
    form_data = await request.form()
    form = _make_form_from_request(CredentialCheckForm, form_data)
    templates = _get_templates()

    verified = False
    if form.validate():
        verified = verify_credentials(current_user, form.password.data)
        if verified:
            _flash(request, "Verification successful!", "success")
        else:
            _flash(request, "Incorrect password.", "danger")

    return templates.TemplateResponse(
        "credentials.html",
        _build_context(request, current_user, **{
            "form": form,
            "verified": verified,
            "username": get_username(current_user),
            "display_name": get_display_name(current_user),
            "role": get_user_role(current_user),
            "created_at": format_timestamp(get_created_at(current_user)),
        }),
    )


# =====================================================
# DELETE POST
# =====================================================
@router.post("/posts/delete/{post_id}", name="auth.delete_post")
async def delete_post(
    request: Request,
    post_id: int,
    current_user: User = Depends(require_user),
):
    post = db.session.get(SecurePost, post_id)
    if not post or post.user_id != current_user.id:
        _flash(request, "Post not found.", "danger")
        return RedirectResponse(
            url=request.url_for("auth.dashboard"), status_code=302
        )

    db.session.delete(post)
    db.session.commit()

    create_audit_log(
        "DELETE_POST",
        get_username(current_user),
        str(post_id),
    )

    _flash(request, "Post deleted successfully.", "success")
    return RedirectResponse(
        url=request.url_for("auth.dashboard"), status_code=302
    )


# =====================================================
# ADMIN PANEL
# =====================================================
@router.get("/admin", name="auth.admin")
async def admin(request: Request, current_user: User = Depends(require_admin)):
    users = get_all_users()
    templates = _get_templates()
    return templates.TemplateResponse(
        "admin.html",
        _build_context(request, current_user, users=users),
    )


# =====================================================
# DELETE USER
# =====================================================
@router.post("/admin/delete/{user_id}", name="auth.admin_delete_user")
async def admin_delete_user(
    request: Request,
    user_id: int,
    current_user: User = Depends(require_admin),
):
    target = db.session.get(User, user_id)
    if not target:
        _flash(request, "User not found.", "danger")
        return RedirectResponse(
            url=request.url_for("auth.admin"), status_code=302
        )

    if target.id == current_user.id:
        _flash(request, "Cannot delete yourself.", "danger")
        return RedirectResponse(
            url=request.url_for("auth.admin"), status_code=302
        )

    delete_user(current_user, target)
    _flash(request, "User removed successfully.", "success")
    return RedirectResponse(
        url=request.url_for("auth.admin"), status_code=302
    )


# =====================================================
# AUDIT LOGS
# =====================================================
@router.get("/audit-logs", name="auth.audit_logs")
async def audit_logs(request: Request, current_user: User = Depends(require_admin)):
    logs = get_audit_logs()
    templates = _get_templates()
    return templates.TemplateResponse(
        "audit_logs.html",
        _build_context(request, current_user, logs=logs),
    )
