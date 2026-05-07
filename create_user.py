from app import db, User
import hashlib


def create_user(username, password, role):
    from app import app
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    with app.app_context():
        user = User(username=username, password=hashed_pw, role=role)
        db.session.add(user)
        db.session.commit()
        print(f"User '{username}' created with role '{role}'.")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 4:
        print("Usage: python create_user.py <username> <password> <role>")
    else:
        create_user(sys.argv[1], sys.argv[2], sys.argv[3])
