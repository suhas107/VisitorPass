from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user, logout_user

from . import admin_bp
try:
    from extensions import db
    from models import User, EntryLog
    from acl import require_permission
    from auth.routes import verify_assertion
except ImportError:  # pragma: no cover
    from dormpass.extensions import db
    from dormpass.models import User, EntryLog
    from dormpass.acl import require_permission
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


@admin_bp.route("/")
@login_required
@require_permission("USER", "manage")
def dashboard():
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    user_count = User.query.count()
    log_count = EntryLog.query.count()
    return render_template("admin_dashboard.html", user_count=user_count, log_count=log_count)


@admin_bp.route("/users")
@login_required
@require_permission("USER", "manage")
def manage_users():
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    users = User.query.all()
    return render_template("users.html", users=users)


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@require_permission("USER", "manage")
def toggle_user(user_id):
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Cannot deactivate self.", "danger")
    else:
        user.is_active = not user.is_active
        db.session.commit()
        flash("Updated user state.", "success")
    return redirect(url_for("admin.manage_users"))


@admin_bp.route("/logs")
@login_required
@require_permission("ENTRY_LOG", "read_all")
def all_logs():
    if not _ensure_assertion():
        return redirect(url_for("auth.login"))
    logs = EntryLog.query.order_by(EntryLog.scanned_at.desc()).all()
    return render_template("logs.html", logs=logs)
