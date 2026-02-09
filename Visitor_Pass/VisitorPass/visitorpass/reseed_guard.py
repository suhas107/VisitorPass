import os
import sys

# Ensure package import works when invoked as a script
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app, reseed_guard_keystore  # noqa: E402


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        print(reseed_guard_keystore(force=True))
