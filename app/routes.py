from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request
)
from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user
)
from datetime import datetime
from . import db
from .models import (
    User,
    SecurePost
)
from .forms import (
    RegisterForm,
    LoginForm,
    PostForm,
    CredentialCheckForm
)
from .decorators import (
    admin_required
)
from .services import (
    register_user,
    verify_credentials,
    verify_user_integrity,
    username_lookup,
    get_username,
    get_display_name,
    get_created_at,
    format_timestamp,
    get_user_role,
    get_next_post_serial_number,
    encrypt_post_for_user,
    decrypt_post_for_user,
    create_audit_log,
    delete_user,
    get_all_users,
    get_audit_logs
)
auth_bp = Blueprint(
    "auth",
    __name__
)
def get_base_context():
    """Get base context for all templates with user role."""
    context = {}
    if current_user.is_authenticated:
        try:
            context['user_role'] = get_user_role(current_user)
        except:
            context['user_role'] = 'USER'
    else:
        context['user_role'] = None
    return context
# =====================================================
# HOME
# =====================================================
@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(
            url_for("auth.dashboard")
        )
    return redirect(
        url_for("auth.login")
    )
# =====================================================
# REGISTER
# =====================================================
@auth_bp.route(
    "/register",
    methods=["GET", "POST"]
)
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        display_name = form.display_name.data
        password = form.password.data
        user = register_user(
            username,
            display_name,
            password
        )
        if not user:
            flash(
                "Username already exists.",
                "danger"
            )
            return render_template(
                "register.html",
                form=form,
                **get_base_context()
            )
        flash(
            "Account created successfully! Please log in.",
            "success"
        )
        return redirect(
            url_for("auth.login")
        )
    return render_template(
        "register.html",
        form=form,
        **get_base_context()
    )
# =====================================================
# LOGIN
# =====================================================
@auth_bp.route(
    "/login",
    methods=["GET", "POST"]
)
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(
            username_lookup=username_lookup(
                username
            )
        ).first()
        if not user:
            flash(
                "Invalid credentials.",
                "danger"
            )
            return render_template(
                "login.html",
                form=form,
                **get_base_context()
            )
        if not verify_user_integrity(
            user
        ):
            flash(
                "Account integrity failure.",
                "danger"
            )
            return render_template(
                "login.html",
                form=form,
                **get_base_context()
            )
        if not verify_credentials(
            user,
            password
        ):
            flash(
                "Invalid credentials.",
                "danger"
            )
            return render_template(
                "login.html",
                form=form,
                **get_base_context()
            )
        login_user(user)
        create_audit_log(
            "LOGIN",
            get_username(user),
            get_username(user)
        )
        flash(
            "Login successful!",
            "success"
        )
        return redirect(
            url_for("auth.dashboard")
        )
    return render_template(
        "login.html",
        form=form,
        **get_base_context()
    )
# =====================================================
# LOGOUT
# =====================================================
@auth_bp.route("/logout")
@login_required
def logout():
    create_audit_log(
        "LOGOUT",
        get_username(current_user),
        get_username(current_user)
    )
    logout_user()
    flash(
        "You have been logged out.",
        "info"
    )
    return redirect(
        url_for("auth.login")
    )
# =====================================================
# DASHBOARD
# =====================================================
@auth_bp.route(
    "/dashboard",
    methods=["GET", "POST"]
)
@login_required
def dashboard():
    if not verify_user_integrity(
        current_user
    ):
        flash(
            "Integrity check failed.",
            "danger"
        )
        logout_user()
        return redirect(
            url_for("auth.login")
        )
    form = PostForm()
    if form.validate_on_submit():
        content = form.content.data.strip()
        ciphertext, mac = encrypt_post_for_user(
            current_user,
            content
        )
        serial_number = get_next_post_serial_number(
            current_user
        )
        post = SecurePost(
            user_id=current_user.id,
            serial_number=serial_number,
            created_at=datetime.utcnow(),
            ciphertext=ciphertext,
            mac=mac
        )
        db.session.add(post)
        db.session.commit()
        create_audit_log(
            "CREATE_POST",
            get_username(current_user),
            str(post.id)
        )
        flash(
            "Encrypted post saved successfully!",
            "success"
        )
        return redirect(
            url_for("auth.dashboard")
        )
    raw_posts = SecurePost.query.filter_by(
        user_id=current_user.id
    ).order_by(SecurePost.id.asc()).all()
    posts = []
    for post in raw_posts:
        posts.append({
            "id": post.id,
            "serial_number": post.serial_number,
            "created_at": post.created_at,
            "content":
                decrypt_post_for_user(
                    current_user,
                    post
                )
        })
    posts.reverse()
    context = get_base_context()
    context.update({
        "username": get_username(current_user),
        "display_name": get_display_name(current_user),
        "role": get_user_role(current_user),
        "form": form,
        "posts": posts
    })
    return render_template(
        "dashboard.html",
        **context
    )
# =====================================================
# CREDENTIAL CHECK
# =====================================================
@auth_bp.route(
    "/credentials",
    methods=["GET", "POST"]
)
@login_required
def credentials():
    form = CredentialCheckForm()
    verified = False
    if form.validate_on_submit():
        verified = verify_credentials(
            current_user,
            form.password.data
        )
        if verified:
            flash(
                "Verification successful!",
                "success"
            )
        else:
            flash(
                "Incorrect password.",
                "danger"
            )
    context = get_base_context()
    context.update({
        "form": form,
        "verified": verified,
        "username": get_username(current_user),
        "display_name": get_display_name(current_user),
        "role": get_user_role(current_user),
        "created_at": format_timestamp(
            get_created_at(current_user)
        )
    })
    return render_template(
        "credentials.html",
        **context
    )
# =====================================================
# DELETE POST
# =====================================================
@auth_bp.route(
    "/posts/delete/<int:post_id>",
    methods=["POST"]
)
@login_required
def delete_post(post_id):
    post = db.session.get(
        SecurePost,
        post_id
    )
    if not post or post.user_id != current_user.id:
        flash(
            "Post not found.",
            "danger"
        )
        return redirect(
            url_for("auth.dashboard")
        )
    db.session.delete(
        post
    )
    db.session.commit()
    create_audit_log(
        "DELETE_POST",
        get_username(current_user),
        str(post_id)
    )
    flash(
        "Post deleted successfully.",
        "success"
    )
    return redirect(
        url_for("auth.dashboard")
    )
# =====================================================
# ADMIN PANEL
# =====================================================
@auth_bp.route("/admin")
@login_required
@admin_required
def admin():
    users = get_all_users()
    context = get_base_context()
    context.update({
        "users": users
    })
    return render_template(
        "admin.html",
        **context
    )
# =====================================================
# DELETE USER
# =====================================================
@auth_bp.route(
    "/admin/delete/<int:user_id>",
    methods=["POST"]
)
@login_required
@admin_required
def admin_delete_user(user_id):
    target = db.session.get(
        User,
        user_id
    )
    if not target:
        flash(
            "User not found.",
            "danger"
        )
        return redirect(
            url_for("auth.admin")
        )
    if target.id == current_user.id:
        flash(
            "Cannot delete yourself.",
            "danger"
        )
        return redirect(
            url_for("auth.admin")
        )
    delete_user(
        current_user,
        target
    )
    flash(
        "User removed successfully.",
        "success"
    )
    return redirect(
        url_for("auth.admin")
    )
# =====================================================
# AUDIT LOGS
# =====================================================
@auth_bp.route("/audit-logs")
@login_required
@admin_required
def audit_logs():
    logs = get_audit_logs()
    context = get_base_context()
    context.update({
        "logs": logs
    })
    return render_template(
        "audit_logs.html",
        **context
    )
