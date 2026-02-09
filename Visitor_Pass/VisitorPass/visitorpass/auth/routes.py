import base64
import io
import time
import secrets
from flask import render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, current_user, login_required
import pyotp
import qrcode
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from passlib.hash import argon2

from . import auth_bp
from .forms import RegistrationForm, LoginForm, MFAForm, EnableMFAForm
try:
    from extensions import db
    from models import User, ResidentProfile
    from crypto_utils import generate_rsa_keypair, encrypt_private_key, decrypt_private_key
except ImportError:  # pragma: no cover
    from dormpass.extensions import db
    from dormpass.models import User, ResidentProfile
    from dormpass.crypto_utils import generate_rsa_keypair, encrypt_private_key, decrypt_private_key

# Simple in-memory rate limiting structures
login_attempts_ip = {}
login_attempts_user = {}
ATTEMPT_WINDOW = 300
MAX_ATTEMPTS = 5


def _rate_limited(identifier, store):
    now = time.time()
    attempts = [t for t in store.get(identifier, []) if now - t < ATTEMPT_WINDOW]
    store[identifier] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def _record_attempt(identifier, store):
    store.setdefault(identifier, []).append(time.time())


# Assertion issuance and verification to model Verifier->RP handoff

def issue_assertion(user):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return serializer.dumps({"uid": user.id, "role": user.role})


def verify_assertion(token):
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        data = serializer.loads(token, max_age=3600)
        return data
    except (BadSignature, SignatureExpired):
        return None


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.role.data == "RESIDENT":
            if form.email_code.data != current_app.config.get("RESIDENT_ENROLL_CODE"):
                flash("Resident enroll code failed.", "danger")
                return render_template("register.html", form=form)
        else:  # GUARD
            if form.guard_code.data != current_app.config.get("GUARD_ENROLL_CODE"):
                flash("Guard enroll code invalid.", "danger")
                return render_template("register.html", form=form)
        existing = User.query.filter_by(email=form.email.data.lower()).first()
        if existing:
            flash("Email already registered.", "warning")
            return render_template("register.html", form=form)
        private_pem, public_pem = generate_rsa_keypair()
        user = User(
            email=form.email.data.lower(),
            name=form.name.data,
            role=form.role.data,
            rsa_public_key_pem=public_pem,
            rsa_private_key_enc=encrypt_private_key(private_pem, current_app.fernet),
        )
        user.set_password(form.password.data)
        recovery_code = secrets.token_hex(8)
        user.recovery_code_hash = argon2.hash(recovery_code)
        db.session.add(user)
        db.session.commit()
        if form.role.data == "RESIDENT":
            profile = ResidentProfile(user_id=user.id, room_number=form.room_number.data or "N/A", phone=form.phone.data)
            db.session.add(profile)
            db.session.commit()
        flash(f"Registration successful. Recovery code: {recovery_code}", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        ip = request.remote_addr or "anon"
        if _rate_limited(ip, login_attempts_ip) or _rate_limited(form.email.data.lower(), login_attempts_user):
            flash("Too many attempts, try later.", "danger")
            return render_template("login.html", form=form)
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user or not user.check_password(form.password.data):
            _record_attempt(ip, login_attempts_ip)
            _record_attempt(form.email.data.lower(), login_attempts_user)
            flash("Invalid credentials.", "danger")
            return render_template("login.html", form=form)
        if not user.is_active:
            flash("Account disabled.", "danger")
            return render_template("login.html", form=form)
        session.pop("pending_user", None)
        if user.mfa_enabled:
            session["pending_user"] = user.id
            return redirect(url_for("auth.mfa_challenge"))
        login_user(user)
        session["rp_assertion"] = issue_assertion(user)
        flash("Logged in.", "success")
        return redirect(url_for("rp.dashboard"))
    return render_template("login.html", form=form)


@auth_bp.route("/mfa", methods=["GET", "POST"])
def mfa_challenge():
    pending_id = session.get("pending_user")
    if not pending_id:
        return redirect(url_for("auth.login"))
    user = User.query.get(pending_id)
    if not user:
        return redirect(url_for("auth.login"))
    form = MFAForm()
    if form.validate_on_submit():
        if not user.totp_secret_enc:
            flash("MFA not configured.", "danger")
            return redirect(url_for("auth.login"))
        secret = current_app.fernet.decrypt(user.totp_secret_enc).decode()
        totp = pyotp.TOTP(secret)
        if totp.verify(form.otp.data, valid_window=1):
            login_user(user)
            session.pop("pending_user", None)
            session["rp_assertion"] = issue_assertion(user)
            flash("MFA success.", "success")
            return redirect(url_for("rp.dashboard"))
        flash("Invalid OTP.", "danger")
    return render_template("mfa_setup.html", form=form, challenge_only=True)


@auth_bp.route("/enable-mfa", methods=["GET", "POST"])
@login_required
def enable_mfa():
    # CSP issues MFA secret; RA already validated email at registration.
    secret = session.get("provision_secret") or pyotp.random_base32()
    session["provision_secret"] = secret
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="VisitorPass")
    # Generate QR data URI
    qr = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    # Support both Pillow and pure-PyPNG writers without format kwarg
    qr.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    form = EnableMFAForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(secret)
        if totp.verify(form.otp.data, valid_window=1):
            current_user.totp_secret_enc = current_app.fernet.encrypt(secret.encode())
            current_user.mfa_enabled = True
            session.pop("provision_secret", None)
            db.session.commit()
            flash("MFA enabled.", "success")
            return redirect(url_for("rp.dashboard"))
        flash("OTP incorrect.", "danger")
    return render_template("mfa_setup.html", form=form, qr_b64=qr_b64, provisioning_uri=provisioning_uri, challenge_only=False)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("rp_assertion", None)
    flash("Logged out.", "info")
    return redirect(url_for("rp.home"))
