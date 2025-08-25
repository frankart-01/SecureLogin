import os
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from datetime import timedelta

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql://postgres:****@localhost:5432/login_db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# JWT configs
app.config["JWT_SECRET_KEY"] = ""
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=7)

jwt = JWTManager(app)
