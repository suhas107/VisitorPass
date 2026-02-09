import uuid
from datetime import datetime
from flask_login import UserMixin
from passlib.hash import argon2
from sqlalchemy.orm import relationship
from sqlalchemy import func

try:
    from extensions import db, login_manager
except ImportError:  # pragma: no cover
    from dormpass.extensions import db, login_manager


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    recovery_code_hash = db.Column(db.String(255))
    mfa_enabled = db.Column(db.Boolean, default=False)
    totp_secret_enc = db.Column(db.LargeBinary)
    rsa_public_key_pem = db.Column(db.LargeBinary)
    rsa_private_key_enc = db.Column(db.LargeBinary)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile = relationship("ResidentProfile", uselist=False, back_populates="user")
    passes = relationship("Pass", back_populates="resident")

    def get_id(self):
        return str(self.id)

    def set_password(self, password):
        self.password_hash = argon2.hash(password)

    def check_password(self, password):
        return argon2.verify(password, self.password_hash)

    @property
    def is_admin(self):
        return self.role == "ADMIN"

    @property
    def is_guard(self):
        return self.role == "GUARD"

    @property
    def is_resident(self):
        return self.role == "RESIDENT"


class ResidentProfile(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    room_number = db.Column(db.String(20), nullable=False)
    phone = db.Column(db.String(30))
    user = relationship("User", back_populates="profile")


class Pass(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    resident_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    visitor_name = db.Column(db.String(255), nullable=False)
    visitor_phone_enc = db.Column(db.LargeBinary, nullable=False)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default="ACTIVE")
    issued_at = db.Column(db.String(40))
    guard_key_id = db.Column(db.Integer, db.ForeignKey("key_store.id"))
    aes_key_wrapped_b64 = db.Column(db.Text, nullable=False)
    iv_b64 = db.Column(db.Text, nullable=False)
    ciphertext_b64 = db.Column(db.Text, nullable=False)
    signature_b64 = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    resident = relationship("User", back_populates="passes")
    guard_key = relationship("KeyStore")
    logs = relationship("EntryLog", back_populates="pass_obj")


class EntryLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pass_id = db.Column(db.String(36), db.ForeignKey("pass.id"))
    guard_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    scanned_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    result = db.Column(db.String(30))
    notes = db.Column(db.Text)
    client_ip = db.Column(db.String(64))

    guard = relationship("User")
    pass_obj = relationship("Pass", back_populates="logs")


class KeyStore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_type = db.Column(db.String(30))
    owner_id = db.Column(db.Integer)
    rsa_public_key_pem = db.Column(db.LargeBinary)
    rsa_private_key_enc = db.Column(db.LargeBinary)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
