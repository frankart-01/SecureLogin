from flask_sqlalchemy import SQLAlchemy
from config import bcrypt, app
from datetime import datetime

db = SQLAlchemy()
db.init_app(app)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    date_created = db.Column(db.String, default=datetime.now())
    password = db.Column(db.String(255), nullable=False)
    failed_attempt = db.Column(db.Integer, default = 0, nullable=False)

    def hash_pass(self, password):
        """Hashes and stores the user's password securely."""
        self.password = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_pass(self, password):
        """Checks if the entered password matches the stored hash."""
        return bcrypt.check_password_hash(self.password, password)
