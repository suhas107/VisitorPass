import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///dormpass.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    APP_SECRET = os.environ.get("APP_SECRET", "super-secret")
    SECURITY_PASSWORD_SALT = os.environ.get("SECURITY_PASSWORD_SALT", "salt")
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    WTF_CSRF_ENABLED = True
    GUARD_ENROLL_CODE = os.environ.get("GUARD_ENROLL_CODE", "CHANGE-ME-GUARD-CODE")
    RESIDENT_ENROLL_CODE = os.environ.get("RESIDENT_ENROLL_CODE") or os.environ.get("EMAIL_VERIFICATION_CODE", "resident-secret")
    EMAIL_VERIFICATION_CODE = RESIDENT_ENROLL_CODE  # backward compatibility for old env var name
    SESSION_PROTECTION = "strong"

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
