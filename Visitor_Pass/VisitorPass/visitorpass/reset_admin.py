import os
import sys
from passlib.hash import argon2

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app  # noqa: E402
from extensions import db  # noqa: E402
from models import User  # noqa: E402


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        admin = User.query.filter_by(email="admin@visitorpass.local").first()
        if not admin:
            print("Admin user not found."
                  " If you deleted it, remove the DB to re-seed or create manually.")
        else:
            admin.password_hash = argon2.hash("Admin@12345")
            admin.is_active = True
            db.session.commit()
            print("Admin password reset to Admin@12345 and activated.")
