from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from .database import db


class UserMixin:
    """Minimal replacement for Flask-Login's UserMixin.

    Provides the boolean properties that the templates check so the
    frontend continues to work without changes.
    """

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username_lookup = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True
    )
    username_enc = db.Column(db.Text, nullable=False)
    display_name_enc = db.Column(db.Text, nullable=False)
    role_enc = db.Column(db.Text, nullable=False)
    created_at_enc = db.Column(db.Text, nullable=False)
    user_key_enc = db.Column(db.Text, nullable=False)
    user_mac = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)

    posts = db.relationship(
        "SecurePost",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(
            password,
            method="scrypt"
        )

    def check_password(self, password):
        return check_password_hash(
            self.password_hash,
            password
        )


class SecurePost(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )
    serial_number = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    mac = db.Column(db.String(64), nullable=False)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    action_enc = db.Column(db.Text, nullable=False)
    actor_enc = db.Column(db.Text, nullable=False)
    target_enc = db.Column(db.Text, nullable=False)
    timestamp_enc = db.Column(db.Text, nullable=False)
    mac = db.Column(db.String(64), nullable=False)
