import uuid
from flask_sqlalchemy import SQLAlchemy
from config import bcrypt, app
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
import re

db = SQLAlchemy()
db.init_app(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        default=lambda: str(uuid.uuid4()),
    )
    name = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    date_created = db.Column(db.String, default=datetime.now())
    password = db.Column(db.String(255), nullable=False)
    failed_attempt = db.Column(db.Integer, default=0, nullable=False)

    def validate_password(self, password: str) -> bool:
        """Check if password meets complexity rules."""
        has_uppercase = any(char.isupper() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password))

        return has_uppercase and has_digit and has_special

    def set_password(self, password: str) -> bool:
        """
        Validates and hashes the password.
        Returns True if successful, False if validation fails.
        """
        if not self.validate_password(password):
            return False
        self.password = bcrypt.generate_password_hash(password).decode("utf-8")
        return True

    def check_pass(self, password: str) -> bool:
        """Check if entered password matches the stored hash."""
        return bcrypt.check_password_hash(self.password, password)


class Admin(db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer,primary_key=True, autoincrement=True)

    # Foreign key references users.user_id (which is a String UUID)
    user_id = db.Column(
        db.String(36),  # match UUID string length
        db.ForeignKey("users.user_id"),
        unique=True,
        nullable=False,
    )

    # Admin-specific fields
    role = db.Column(
        db.String(50), default="system_admin"
    )  # e.g., "superadmin", "moderator"

    permissions = db.Column(db.JSON, nullable=True)  # store granular rights as JSON

    last_login = db.Column(db.DateTime, default=datetime.utcnow)

    created_by = db.Column(
        db.Integer, db.ForeignKey("admins.user_id"), nullable=True
    )  # which admin created this admin

    is_superadmin = db.Column(
        db.Boolean, default=False
    )  # superadmins can manage other admins

    contact_number = db.Column(db.String(20), nullable=True)  # escalation contact

    # Relationship back to user
    user = db.relationship("User", backref=db.backref("admin_profile", uselist=False))
