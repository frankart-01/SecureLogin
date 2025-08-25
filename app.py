from flask import jsonify, request
from config import app, jwt
from models import User, db
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)


@app.post("/")
def index():
    data = request.get_json()

    login_or_signup = data["Register/login? "]
    username = data["username"]
    password = data["password"]
    user = User.query.filter_by(name=username).first()

    # Login logic
    if login_or_signup == "login":
        if user and user.check_pass(password):
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)
            return (
                jsonify(
                    {
                        "msg": f"welcome {username}",
                        "access token": access_token,
                        "refresh_token": refresh_token,
                    }
                ),
                200,
            )
        return jsonify({"msg": "invalid credentials"}), 400

    # Register Logic
    existing_username = User.query.filter_by(name=username).first()

    if existing_username:
        return jsonify({"msg": "name already taken. use another"}), 400

    new_user = User(name=username)
    new_user.hash_pass(password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": f"{new_user.name} added to database"})
