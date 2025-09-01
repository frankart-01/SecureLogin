from flask import jsonify, request
from config import app, jwt
from models import User, db
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
)

MAX_FAILED = 5  # lock threshold


@app.post("/")
def index():
    data = request.get_json(silent=True) or {}

    # Normalize action key (yours had a space + question mark)
    action = (data.get("Register/login? ") or data.get("action") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    email = (data.get("email") or "").strip()

    if action not in {"login", "register"}:
        return jsonify({"msg": "Invalid action. Use 'login' or 'register'."}), 400

    # ---------- LOGIN ----------
    if action == "login":
        if not username or not password:
            return jsonify({"msg": "Username and password are required."}), 400

        user = User.query.filter_by(name=username).first()
        if not user:
            return jsonify({"msg": "No user with provided credentials"}), 404

        # Locked?
        if getattr(user, "failed_attempt", 0) >= MAX_FAILED:
            return (
                jsonify(
                    {
                        "msg": "Your account has been temporarily disabled. Please try again soon or contact your systems administrator."
                    }
                ),
                403,
            )

        # Password OK
        if user.check_pass(password):
            user.failed_attempt = 0
            db.session.commit()

            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)

            return (
                jsonify(
                    {
                        "msg": f"Welcome {user.name}",
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                    }
                ),
                200,
            )

        # Password wrong
        user.failed_attempt = getattr(user, "failed_attempt", 0) + 1
        db.session.commit()

        remaining = max(0, MAX_FAILED - user.failed_attempt)
        if user.failed_attempt >= MAX_FAILED:
            return (
                jsonify(
                    {
                        "msg": "Too many failed attempts. Your account has been temporarily disabled."
                    }
                ),
                403,
            )

        return (
            jsonify(
                {"msg": f"Wrong password provided. You have {remaining} attempts left."}
            ),
            401,
        )

    # ---------- REGISTER ----------
    # Basic input checks
    if not username or not password or not email:
        return jsonify({"msg": "Username, email, and password are required."}), 400

    # Uniqueness checks
    if User.query.filter_by(name=username).first():
        return jsonify({"msg": "Username already exists."}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email already exists."}), 409
    
    if len(password) < 8:
        return jsonify({"msg": "password length must be at least 8 characters"}), 401

    # Create user
    new_user = User(name=username, email=email)
    if new_user.set_password(password):  # make sure this stores a hash, not plaintext
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": f"{new_user.name} added to database"}), 201
    return jsonify({"msg": "password doesn't meet complexityy rules"}), 401
