import os
import sys

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app  # noqa: E402

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        secret = app.config.get("APP_SECRET")
        print(f"APP_SECRET: {secret}")
        print(f"Fernet key (base64): {app.fernet._signing_key + app.fernet._encryption_key}")
