from flask_sqlalchemy import SQLAlchemy
from config import bcrypt, app
from datetime import datetime
import re

db = SQLAlchemy()
db.init_app(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
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
