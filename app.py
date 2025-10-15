# app.py
from datetime import timedelta
from flask import Flask, jsonify, request
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
)
from config import app, login_manager  # assumes app is created in config
from models import Admin, User, db

# -------------------- CONFIG --------------------
MAX_FAILED = 5  # account lock threshold

# JWT setup
app.config["JWT_SECRET_KEY"] = "change-me"  # use an ENV var in production
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=6)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=14)

# CORS: allow your Vite dev server
CORS(
    app,
    origins=["http://localhost:5173"],
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "X-CSRF-TOKEN"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)

jwt = JWTManager(app)
migrate = Migrate(app, db)


# -------------------- FLASK-LOGIN (optional) --------------------
@login_manager.user_loader
def load_user(user_id: str):
    """
    If you still use Flask-Login somewhere else, return a user by primary key.
    If your PK is 'id' (int) and you also have 'user_id' (UUID str), adjust accordingly.
    """
    try:
        return User.query.filter_by(user_id=user_id).first()
    except Exception:
        return None


# -------------------- HELPERS --------------------
def json_body() -> dict:
    if request.is_json:
        return request.get_json(silent=True) or {}
    # Fallback for non-JSON requests
    return {}


def norm(s: str) -> str:
    return (s or "").strip()


def error(msg: str, code: int):
    return jsonify({"message": msg}), code


# -------------------- AUTH ROUTES --------------------
@app.post("/auth/signup")
def signup():
    data = json_body()
    username = norm(data.get("name"))
    email = norm(data.get("email")).lower()
    password = data.get("password") or ""

    if not username or not email or not password:
        return error("Username, email, and password are required.", 400)

    if len(password) < 8:
        return error("Password length must be at least 8 characters.", 400)

    # Uniqueness
    if User.query.filter_by(name=username).first():
        return error("Username already exists.", 409)
    if User.query.filter_by(email=email).first():
        return error("Email already exists.", 409)

    # Create user
    user = User(name=username, email=email)
    if not user.set_password(password):  # your model’s complexity check
        return error(
            "Password doesn't meet complexity rules: include upper, lower, number, and special character.",
            400,
        )

    db.session.add(user)
    db.session.commit()

    # Tokens (use user.user_id as identity)
    access_token = create_access_token(identity=str(user.user_id))
    refresh_token = create_refresh_token(identity=str(user.user_id))

    return (
        jsonify(
            {
                "message": f"{user.name} added to database",
                "user": {
                    "name": user.name,
                    "email": user.email,
                    "user_id": str(user.user_id),
                },
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        ),
        201,
    )


@app.post("/auth/signin")
def signin():
    data = json_body()
    username = norm(data.get("username"))
    email = norm(data.get("email")).lower()
    password = data.get("password") or ""

    # allow login by username OR email
    if not (username or email) or not password:
        return error("Provide username or email, and password.", 400)

    q = None
    if username:
        q = User.query.filter_by(name=username).first()
    elif email:
        q = User.query.filter_by(email=email).first()

    user = q
    if not user:
        return error("No user with provided credentials.", 401)

    # locked?
    if getattr(user, "failed_attempt", 0) >= MAX_FAILED:
        return error(
            "Your account has been temporarily disabled due to too many failed attempts. Contact support.",
            403,
        )

    if user.check_pass(password):
        user.failed_attempt = 0
        db.session.commit()

        access_token = create_access_token(identity=str(user.user_id))
        refresh_token = create_refresh_token(identity=str(user.user_id))
        return (
            jsonify(
                {
                    "message": f"Welcome {user.name}",
                    "user": {
                        "name": user.name,
                        "email": user.email,
                        "user_id": str(user.user_id),
                    },
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                }
            ),
            200,
        )

    # wrong password path
    user.failed_attempt = getattr(user, "failed_attempt", 0) + 1
    db.session.commit()

    remaining = max(0, MAX_FAILED - user.failed_attempt)
    if user.failed_attempt >= MAX_FAILED:
        return error(
            "Too many failed attempts. Your account has been temporarily disabled.",
            403,
        )
    return error(f"Wrong password. You have {remaining} attempts left.", 401)


@app.post("/auth/refresh")
@jwt_required(refresh=True)
def refresh():
    # For refresh tokens if you decide to rotate/renew access tokens
    uid = get_jwt_identity()
    new_access = create_access_token(identity=uid)
    return jsonify({"access_token": new_access}), 200


@app.get("/me")
@jwt_required()
def me():
    uid = get_jwt_identity()
    user = User.query.filter_by(user_id=uid).first()
    if not user:
        return error("User not found.", 404)
    return (
        jsonify(
            {
                "user": {
                    "name": user.name,
                    "email": user.email,
                    "user_id": str(user.user_id),
                }
            }
        ),
        200,
    )


@app.post("/reset_password")
@jwt_required()
def reset_password():
    """
    Example of an admin-only endpoint (adjust to your actual logic).
    Suppose Admin.user_id references User.user_id; if a row exists, caller is admin.
    """
    uid = get_jwt_identity()

    is_admin = Admin.query.filter_by(user_id=uid).first() is not None
    if not is_admin:
        return error("You are not authorised to perform this action.", 403)

    # Example payload: {"target_user_id": "...", "new_password": "..."}
    data = json_body()
    target_id = norm(data.get("target_user_id"))
    new_pw = data.get("new_password") or ""

    if not target_id or not new_pw:
        return error("target_user_id and new_password required.", 400)

    target = User.query.filter_by(user_id=target_id).first()
    if not target:
        return error("Target user not found.", 404)

    if not target.set_password(new_pw):
        return error("New password does not meet complexity rules.", 400)

    db.session.commit()
    return jsonify({"message": f"Password reset for {target.name}"}), 200


# Optional health check
@app.get("/healthz")
def healthz():
    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    app.run(port=5000, debug=True)
