import os
from dotenv import load_dotenv
from flask import Flask

try:
    from .config import Config
    from .extensions import db, login_manager, csrf
    from .auth import auth_bp
    from .rp import rp_bp
    from .admin import admin_bp
    from .models import User, KeyStore
    from .crypto_utils import derive_fernet, generate_rsa_keypair, encrypt_private_key
except ImportError:  # pragma: no cover
    from config import Config
from extensions import db, login_manager, csrf
from auth import auth_bp
from rp import rp_bp
from admin import admin_bp
from models import User, KeyStore
from crypto_utils import derive_fernet, generate_rsa_keypair, encrypt_private_key


def create_app(test_config=None):
    load_dotenv()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    app.fernet = derive_fernet(app.config["APP_SECRET"])

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    app.register_blueprint(auth_bp)
    app.register_blueprint(rp_bp)
    app.register_blueprint(admin_bp)

    with app.app_context():
        db.create_all()
        seed_admin(app)
        seed_guard_keystore(app)
        ensure_guard_keystore(app)

    return app


def seed_admin(app):
    admin_email = "admin@visitorpass.local"
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        private_pem, public_pem = generate_rsa_keypair()
        admin = User(email=admin_email, name="Administrator", role="ADMIN")
        admin.set_password("Admin@12345")
        admin.rsa_public_key_pem = public_pem
        admin.rsa_private_key_enc = encrypt_private_key(private_pem, app.fernet)
        db.session.add(admin)
        db.session.commit()


def seed_guard_keystore(app):
    exists = KeyStore.query.filter_by(owner_type="SECURITY_DESK").first()
    if not exists:
        private_pem, public_pem = generate_rsa_keypair()
        ks = KeyStore(
            owner_type="SECURITY_DESK",
            owner_id=0,
            rsa_public_key_pem=public_pem,
            rsa_private_key_enc=encrypt_private_key(private_pem, app.fernet),
        )
        db.session.add(ks)
        db.session.commit()


def ensure_guard_keystore(app):
    """Verify guard key decrypts with current APP_SECRET; reseed if not."""
    ks = KeyStore.query.filter_by(owner_type="SECURITY_DESK").first()
    if not ks:
        seed_guard_keystore(app)
        return
    try:
        # sanity check decrypt with current fernet
        from crypto_utils import decrypt_private_key

        decrypt_private_key(ks.rsa_private_key_enc, app.fernet)
    except Exception:
        reseed_guard_keystore(force=True)


def reseed_guard_keystore(force: bool = False):
    """Regenerate the Security Desk guard keypair using the current APP_SECRET."""
    ks = KeyStore.query.filter_by(owner_type="SECURITY_DESK").first()
    if ks and not force:
        return "Guard keystore already exists; use force=True to replace."
    if ks and force:
        db.session.delete(ks)
        db.session.commit()
    private_pem, public_pem = generate_rsa_keypair()
    from flask import current_app

    wrapped_priv = encrypt_private_key(private_pem, current_app.fernet)
    ks = KeyStore(owner_type="SECURITY_DESK", owner_id=0, rsa_public_key_pem=public_pem, rsa_private_key_enc=wrapped_priv)
    db.session.add(ks)
    db.session.commit()
    return "Guard keystore regenerated."


app = create_app()


@app.cli.command("reseed-guard-key")
def reseed_guard_key_cmd():
    """CLI helper to regenerate the Security Desk guard keypair with current APP_SECRET."""
    with app.app_context():
        msg = reseed_guard_keystore(force=True)
        print(msg)


@app.cli.command("show-app-secret")
def show_app_secret_cmd():
    """Print the current APP_SECRET and derived Fernet key (for debugging)."""
    from flask import current_app

    secret = current_app.config.get("APP_SECRET")
    print(f"APP_SECRET: {secret}")
    # Derived Fernet key (base64)
    print(f"Fernet key: {current_app.fernet._signing_key + current_app.fernet._encryption_key}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port)
