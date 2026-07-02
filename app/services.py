import os
from datetime import datetime
from .database import db
from .models import (
    User,
    SecurePost,
    AuditLog
)
from .crypto import crypto
# =====================================================
# USERNAME NORMALIZATION
# =====================================================
def normalize_username(username):
    return username.strip().lower()
# =====================================================
# TIMESTAMP HELPERS
# =====================================================
def current_timestamp():
    """Return timestamps in one readable pattern for storage and display."""
    return datetime.utcnow().replace(microsecond=0).isoformat(
        sep=" "
    )
def format_timestamp(timestamp):
    """Normalize timestamps to YYYY-MM-DD HH:MM:SS.
    
    Handles multiple formats:
    - ISO 8601 with T separator: 2026-06-20T16:21:22
    - ISO 8601 with space: 2026-06-20 16:21:22
    - ISO with Z timezone: 2026-06-20T16:21:22Z
    """
    if not timestamp:
        return ""
    
    # Handle string timestamps
    if isinstance(timestamp, str):
        try:
            # Try parsing as ISO format
            parsed = datetime.fromisoformat(
                timestamp.replace(
                    "Z",
                    "+00:00"
                )
            )
            return parsed.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except (ValueError, AttributeError):
            # Fallback: replace T with space and truncate
            cleaned = timestamp.replace(
                "T",
                " "
            )[:19]
            return cleaned
    
    # Handle datetime objects
    try:
        return timestamp.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except AttributeError:
        return str(timestamp)[:19]
# =====================================================
# LOOKUP GENERATION
# =====================================================
def username_lookup(username):
    return crypto.username_lookup(
        normalize_username(username)
    )
# =====================================================
# PASSWORD VERIFICATION
# =====================================================
def verify_credentials(user, password):
    if not user:
        return False
    return user.check_password(password)
# =====================================================
# USER MAC
# =====================================================
def generate_user_mac(
    username_enc,
    display_name_enc,
    role_enc,
    created_at_enc
):
    payload = "|".join([
        username_enc,
        display_name_enc,
        role_enc,
        created_at_enc
    ])
    return crypto.generate_mac(
        payload
    )
def verify_user_integrity(user):
    expected = generate_user_mac(
        user.username_enc,
        user.display_name_enc,
        user.role_enc,
        user.created_at_enc
    )
    return expected == user.user_mac
# =====================================================
# ROLE HELPERS
# =====================================================
def get_user_role(user):
    return crypto.decrypt(
        user.role_enc
    )
def is_admin(user):
    return get_user_role(user) == "ADMIN"
# =====================================================
# DECRYPT USER INFO
# =====================================================
def get_username(user):
    return crypto.decrypt(
        user.username_enc
    )
def get_display_name(user):
    return crypto.decrypt(
        user.display_name_enc
    )
def get_created_at(user):
    return crypto.decrypt(
        user.created_at_enc
    )
# =====================================================
# AUDIT LOGGING
# =====================================================
def create_audit_log(
    action,
    actor,
    target
):
    timestamp = current_timestamp()
    action_enc = crypto.encrypt(
        action
    )
    actor_enc = crypto.encrypt(
        actor
    )
    target_enc = crypto.encrypt(
        target
    )
    timestamp_enc = crypto.encrypt(
        timestamp
    )
    payload = "|".join([
        action_enc,
        actor_enc,
        target_enc,
        timestamp_enc
    ])
    mac = crypto.generate_mac(
        payload
    )
    log = AuditLog(
        action_enc=action_enc,
        actor_enc=actor_enc,
        target_enc=target_enc,
        timestamp_enc=timestamp_enc,
        mac=mac
    )
    db.session.add(log)
    db.session.commit()
# =====================================================
# REGISTER USER
# =====================================================
def register_user(
    username,
    display_name,
    password
):
    username = normalize_username(
        username
    )
    lookup = username_lookup(
        username
    )
    existing = User.query.filter_by(
        username_lookup=lookup
    ).first()
    if existing:
        return None
    role = "USER"
    created_at = current_timestamp()
    user_key = crypto.generate_user_key()
    username_enc = crypto.encrypt(
        username
    )
    display_name_enc = crypto.encrypt(
        display_name
    )
    role_enc = crypto.encrypt(
        role
    )
    created_at_enc = crypto.encrypt(
        created_at
    )
    user_key_enc = crypto.encrypt_user_key(
        user_key
    )
    mac = generate_user_mac(
        username_enc,
        display_name_enc,
        role_enc,
        created_at_enc
    )
    user = User(
        username_lookup=lookup,
        username_enc=username_enc,
        display_name_enc=display_name_enc,
        role_enc=role_enc,
        created_at_enc=created_at_enc,
        user_key_enc=user_key_enc,
        user_mac=mac
    )
    user.set_password(
        password
    )
    db.session.add(user)
    db.session.commit()
    create_audit_log(
        "REGISTER",
        username,
        username
    )
    return user
# =====================================================
# ADMIN CREATION
# =====================================================
def create_admin_if_missing():
    admin_username = os.getenv(
        "ADMIN_USERNAME"
    )
    admin_password = os.getenv(
        "ADMIN_PASSWORD"
    )
    admin_display_name = os.getenv(
        "ADMIN_DISPLAY_NAME",
        "Administrator"
    )
    if not admin_username:
        return
    lookup = username_lookup(
        admin_username
    )
    existing = User.query.filter_by(
        username_lookup=lookup
    ).first()
    if existing:
        return
    created_at = current_timestamp()
    role = "ADMIN"
    user_key = crypto.generate_user_key()
    username_enc = crypto.encrypt(
        admin_username
    )
    display_name_enc = crypto.encrypt(
        admin_display_name
    )
    role_enc = crypto.encrypt(
        role
    )
    created_at_enc = crypto.encrypt(
        created_at
    )
    user_key_enc = crypto.encrypt_user_key(
        user_key
    )
    mac = generate_user_mac(
        username_enc,
        display_name_enc,
        role_enc,
        created_at_enc
    )
    admin = User(
        username_lookup=lookup,
        username_enc=username_enc,
        display_name_enc=display_name_enc,
        role_enc=role_enc,
        created_at_enc=created_at_enc,
        user_key_enc=user_key_enc,
        user_mac=mac
    )
    admin.set_password(
        admin_password
    )
    db.session.add(admin)
    db.session.commit()
    create_audit_log(
        "ADMIN_CREATED",
        admin_username,
        admin_username
    )
# =====================================================
# POSTS
# =====================================================
def get_next_post_serial_number(user):
    """
    Get the next serial number for a user's post.

    Serial numbers start at 1 and increment per user,
    maintaining individual sequences for each account.
    """
    max_serial = (
        db.session.query(
            db.func.max(SecurePost.serial_number)
        )
        .filter(
            SecurePost.user_id == user.id
        )
        .scalar()
    )

    return (max_serial or 0) + 1


def encrypt_post_for_user(user, plaintext):
    user_key = crypto.decrypt_user_key(
        user.user_key_enc
    )

    ciphertext = crypto.encrypt_with_user_key(
        plaintext,
        user_key
    )

    mac = crypto.generate_mac(
        ciphertext
    )

    return ciphertext, mac

def decrypt_post_for_user(
    user,
    post
):
    if not crypto.verify_mac(
        post.ciphertext,
        post.mac
    ):
        return "[INTEGRITY FAILURE]"
    user_key = crypto.decrypt_user_key(
        user.user_key_enc
    )
    try:
        return crypto.decrypt_with_user_key(
            post.ciphertext,
            user_key
        )
    except Exception:
        return "[DECRYPTION FAILURE]"
# =====================================================
# DELETE USER
# =====================================================
def delete_user(
    admin_user,
    target_user
):
    actor = get_username(
        admin_user
    )
    target = get_username(
        target_user
    )
    create_audit_log(
        "DELETE_USER",
        actor,
        target
    )
    db.session.delete(
        target_user
    )
    db.session.commit()
# =====================================================
# ALL USERS
# =====================================================
def get_all_users():
    output = []
    users = User.query.all()
    for user in users:
        if not verify_user_integrity(
            user
        ):
            continue
        output.append({
            "id": user.id,
            "username":
                get_username(user),
            "display_name":
                get_display_name(user),
            "role":
                get_user_role(user),
            "created_at":
                format_timestamp(
                    get_created_at(user)
                ),
            "posts":
                len(user.posts)
        })
    return output
# =====================================================
# AUDIT LOGS
# =====================================================
def get_audit_logs():
    logs = AuditLog.query.order_by(
        AuditLog.id.desc()
    ).all()
    result = []
    for log in logs:
        payload = "|".join([
            log.action_enc,
            log.actor_enc,
            log.target_enc,
            log.timestamp_enc
        ])
        if not crypto.verify_mac(
            payload,
            log.mac
        ):
            continue
        result.append({
            "action":
                crypto.decrypt(
                    log.action_enc
                ),
            "actor":
                crypto.decrypt(
                    log.actor_enc
                ),
            "target":
                crypto.decrypt(
                    log.target_enc
                ),
            "timestamp":
                format_timestamp(
                    crypto.decrypt(
                        log.timestamp_enc
                    )
                )
        })
    return result
