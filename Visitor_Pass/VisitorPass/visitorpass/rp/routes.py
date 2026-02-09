import base64
import io
from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, session, jsonify, current_app
from flask_login import login_required, current_user, logout_user
import qrcode

from . import rp_bp
from .forms import CreatePassForm, TokenVerifyForm
try:
    from extensions import db
    from models import User, Pass, EntryLog, KeyStore, ResidentProfile
    from acl import require_permission, can
    from crypto_utils import (
        generate_aes_key,
        encrypt_payload,
        decrypt_payload,
        wrap_aes_key,
        unwrap_aes_key,
        sign_bytes,
        verify_signature,
        canonical_signing_bytes,
        base64url_encode_json,
        base64url_decode_json,
        decrypt_private_key,
    )
    from auth.routes import verify_assertion
except ImportError:  # pragma: no cover
    from dormpass.extensions import db
    from dormpass.models import User, Pass, EntryLog, KeyStore, ResidentProfile
    from dormpass.acl import require_permission, can
    from dormpass.crypto_utils import (
        generate_aes_key,
        encrypt_payload,
        decrypt_payload,
        wrap_aes_key,
        unwrap_aes_key,
        sign_bytes,
        verify_signature,
        canonical_signing_bytes,
        base64url_encode_json,
        base64url_decode_json,
        decrypt_private_key,
    )
    from dormpass.auth.routes import verify_assertion


def _ensure_assertion():
    token = session.get("rp_assertion")
    data = verify_assertion(token) if token else None
    if not data or str(data.get("uid")) != current_user.get_id():
        logout_user()
        session.pop("rp_assertion", None)
        flash("Session assertion missing; please login again.", "warning")
        return False
    return True


@rp_bp.route("/")
def home():
    return render_template("home.html")


@rp_bp.route("/dashboard")
@login_required
def dashboard():
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    user_passes = []
    logs = []
    if current_user.role == "RESIDENT":
        user_passes = Pass.query.filter_by(resident_id=current_user.id).order_by(Pass.created_at.desc()).all()
    elif current_user.role == "GUARD":
        logs = EntryLog.query.filter_by(guard_id=current_user.id).order_by(EntryLog.scanned_at.desc()).limit(20).all()
    elif current_user.role == "ADMIN":
        logs = EntryLog.query.order_by(EntryLog.scanned_at.desc()).limit(20).all()
    return render_template("resident_dashboard.html", passes=user_passes, logs=logs)


@rp_bp.route("/passes/create", methods=["GET", "POST"])
@login_required
@require_permission("PASS", "create")
def create_pass():
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    form = CreatePassForm()
    if form.validate_on_submit():
        if form.valid_until.data <= form.valid_from.data:
            flash("End time must be after start.", "danger")
            return render_template("create_pass.html", form=form)
        guard_key = KeyStore.query.filter_by(owner_type="SECURITY_DESK").first()
        if not guard_key:
            flash("No guard key configured.", "danger")
            return render_template("create_pass.html", form=form)
        aes_key = generate_aes_key()
        payload = {
            "visitor_name": form.visitor_name.data,
            "visitor_phone": form.visitor_phone.data,
            "resident": current_user.name,
            "room": current_user.profile.room_number if current_user.profile else "",
            "valid_from": form.valid_from.data.isoformat(),
            "valid_until": form.valid_until.data.isoformat(),
        }
        iv_b64, ciphertext_b64 = encrypt_payload(payload, aes_key)
        wrapped_key_b64 = wrap_aes_key(guard_key.rsa_public_key_pem, aes_key).decode()
        issued_at = datetime.utcnow().isoformat() + "Z"
        signing_bytes = canonical_signing_bytes(wrapped_key_b64, iv_b64.decode(), ciphertext_b64.decode(), "pending", issued_at)
        # final pass id needed; use placeholder then recompute after assign id
        new_pass = Pass(
            resident_id=current_user.id,
            visitor_name=form.visitor_name.data,
            visitor_phone_enc=current_app.fernet.encrypt(form.visitor_phone.data.encode()),
            valid_from=form.valid_from.data,
            valid_until=form.valid_until.data,
            status="ACTIVE",
            guard_key_id=guard_key.id,
            aes_key_wrapped_b64=wrapped_key_b64,
            iv_b64=iv_b64.decode(),
            ciphertext_b64=ciphertext_b64.decode(),
            issued_at=issued_at,
            signature_b64="",
        )
        db.session.add(new_pass)
        db.session.flush()
        signing_bytes = canonical_signing_bytes(wrapped_key_b64, new_pass.iv_b64, new_pass.ciphertext_b64, new_pass.id, issued_at)
        resident_private = decrypt_private_key(current_user.rsa_private_key_enc, current_app.fernet)
        signature_b64 = sign_bytes(resident_private, signing_bytes).decode()
        new_pass.signature_b64 = signature_b64
        db.session.commit()
        flash("Pass created.", "success")
        return redirect(url_for("rp.pass_detail", pass_id=new_pass.id))
    return render_template("create_pass.html", form=form)


def build_token(pass_obj: Pass):
    token = {
        "pass_id": pass_obj.id,
        "resident_id": pass_obj.resident_id,
        "guard_key_id": pass_obj.guard_key_id,
        "wrapped_key": pass_obj.aes_key_wrapped_b64,
        "iv": pass_obj.iv_b64,
        "ciphertext": pass_obj.ciphertext_b64,
        "sig": pass_obj.signature_b64,
        "alg": {"enc": "AES-256-GCM", "wrap": "RSA-OAEP-SHA256", "sig": "RSA-PSS-SHA256"},
        "issued_at": pass_obj.issued_at,
    }
    return base64url_encode_json(token)


def _qr_for_token(token_str: str):
    """
    Build a QR; if data is too large for version 40 at high EC, fall back to lower EC or no QR.
    """
    for ec in [qrcode.constants.ERROR_CORRECT_M, qrcode.constants.ERROR_CORRECT_L]:
        try:
            qr_builder = qrcode.QRCode(
                error_correction=ec,
                box_size=8,
                border=4,
            )
            qr_builder.add_data(token_str)
            qr_builder.make(fit=True)
            qr = qr_builder.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            qr.save(buf)
            return base64.b64encode(buf.getvalue()).decode()
        except ValueError:
            continue
    return None


@rp_bp.route("/passes/<pass_id>")
@login_required
def pass_detail(pass_id):
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    pass_obj = Pass.query.get_or_404(pass_id)
    if current_user.role == "RESIDENT" and pass_obj.resident_id != current_user.id:
        flash("Not authorized", "danger")
        return redirect(url_for("rp.dashboard"))
    token_str = build_token(pass_obj)
    qr_b64 = _qr_for_token(token_str)
    return render_template("pass_detail.html", pass_obj=pass_obj, token_str=token_str, qr_b64=qr_b64)


@rp_bp.route("/passes/<pass_id>/revoke", methods=["POST"])
@login_required
def revoke_pass(pass_id):
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    pass_obj = Pass.query.get_or_404(pass_id)
    if current_user.role == "RESIDENT" and pass_obj.resident_id != current_user.id:
        flash("Not authorized", "danger")
        return redirect(url_for("rp.dashboard"))
    if current_user.role == "ADMIN" or (current_user.role == "RESIDENT" and pass_obj.resident_id == current_user.id):
        pass_obj.status = "REVOKED"
        db.session.commit()
        flash("Pass revoked.", "info")
    return redirect(url_for("rp.dashboard"))


@rp_bp.route("/guard")
@login_required
@require_permission("PASS", "read_minimal")
def guard_dashboard():
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    logs = EntryLog.query.filter_by(guard_id=current_user.id).order_by(EntryLog.scanned_at.desc()).limit(30).all()
    form = TokenVerifyForm()
    return render_template("guard_dashboard.html", logs=logs, form=form)


@rp_bp.route("/guard/scan")
@login_required
@require_permission("PASS", "validate")
def guard_scan():
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    form = TokenVerifyForm()
    return render_template("guard_scan.html", form=form)


@rp_bp.route("/guard/verify", methods=["POST"])
@login_required
@require_permission("PASS", "validate")
def guard_verify():
    if not _ensure_assertion():
        return jsonify({"result": "UNAUTHENTICATED"}), 401
    token_str = request.json.get("token") if request.is_json else request.form.get("token")
    if not token_str:
        return jsonify({"result": "ERROR", "reason": "No token"}), 400
    try:
        token_data = base64url_decode_json(token_str)
    except Exception:
        return jsonify({"result": "ERROR", "reason": "Invalid encoding"}), 400
    pass_obj = Pass.query.get(token_data.get("pass_id"))
    result = "INVALID"
    notes = ""
    details = None
    status_code = 400
    guard_key = KeyStore.query.get(token_data.get("guard_key_id")) if token_data.get("guard_key_id") else None
    if not pass_obj:
        notes = "Pass not found"
        status_code = 400
    elif not guard_key:
        notes = "Guard key missing"
        status_code = 400
    else:
        issued_at = token_data.get("issued_at", "")
        signing_bytes = canonical_signing_bytes(
            token_data["wrapped_key"], token_data["iv"], token_data["ciphertext"], pass_obj.id, issued_at
        )
        resident = pass_obj.resident
        if token_data.get("resident_id") != pass_obj.resident_id or token_data.get("guard_key_id") != pass_obj.guard_key_id:
            result = "INVALID"
            notes = "Token metadata mismatch"
            status_code = 400
        elif not verify_signature(resident.rsa_public_key_pem, signing_bytes, token_data.get("sig", "")):
            result = "SIGNATURE_FAIL"
            notes = "Signature invalid"
            status_code = 400
        else:
            try:
                guard_priv = decrypt_private_key(guard_key.rsa_private_key_enc, current_app.fernet)
            except Exception:
                result = "DECRYPT_FAIL"
                notes = "Cannot decrypt guard key; check APP_SECRET/keystore seed."
                status_code = 400
            else:
                try:
                    aes_key = unwrap_aes_key(guard_priv, token_data["wrapped_key"])
                    payload = decrypt_payload(token_data["iv"], token_data["ciphertext"], aes_key)
                    now = datetime.utcnow()
                    if pass_obj.status in ["REVOKED", "USED"]:
                        result = pass_obj.status
                        notes = f"Pass {pass_obj.status.lower()}"
                        status_code = 400
                    elif now < pass_obj.valid_from or now > pass_obj.valid_until:
                        result = "EXPIRED"
                        notes = "Outside validity window"
                        status_code = 400
                    else:
                        result = "VALID"
                        details = payload
                        pass_obj.status = "USED"
                        db.session.commit()
                        status_code = 200
                except Exception as exc:  # noqa: BLE001
                    result = "DECRYPT_FAIL"
                    notes = str(exc)
                    status_code = 400
    log = EntryLog(
        pass_id=token_data.get("pass_id"),
        guard_id=current_user.id,
        result=result,
        notes=notes,
        client_ip=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({"result": result, "notes": notes, "details": details}), status_code


@rp_bp.route("/logs")
@login_required
def logs():
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    if current_user.role == "ADMIN":
        entries = EntryLog.query.order_by(EntryLog.scanned_at.desc()).all()
    elif current_user.role == "GUARD":
        entries = EntryLog.query.filter_by(guard_id=current_user.id).order_by(EntryLog.scanned_at.desc()).all()
    else:  # Resident
        entries = (
            EntryLog.query.join(Pass)
            .filter(Pass.resident_id == current_user.id)
            .order_by(EntryLog.scanned_at.desc())
            .all()
        )
    return render_template("logs.html", logs=entries)


@rp_bp.route("/directory")
@login_required
def directory():
    if current_user.role == "RESIDENT":
        if not can(current_user.role, "RESIDENT_DIRECTORY", "read_self"):
            flash("Not allowed", "danger")
            return redirect(url_for("rp.dashboard"))
        profiles = ResidentProfile.query.filter_by(user_id=current_user.id).all()
    else:
        if not can(current_user.role, "RESIDENT_DIRECTORY", "read_all"):
            flash("Not allowed", "danger")
            return redirect(url_for("rp.dashboard"))
        profiles = ResidentProfile.query.all()
    return render_template("users.html", profiles=profiles)
