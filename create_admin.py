
from models import User, Admin, db
from werkzeug.security import generate_password_hash


def create_admin(name, email, password):
    # hash password
    hashed_password = generate_password_hash(password)

    # create base user
    user = User(name=name, email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()  # commit so user.id is available

    # create admin linked to user
    admin = Admin(user_id=user.id)
    db.session.add(admin)
    db.session.commit()

    print(f"Admin account created for {name} ({email}) with id={user.id}")


if __name__ == "__main__":
    # example values
    create_admin(
        name="Super Admin", email="admin@example.com", password="StrongPassword123!"
    )
