from flask import Flask
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql://***:***@localhost:5432/login_db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
