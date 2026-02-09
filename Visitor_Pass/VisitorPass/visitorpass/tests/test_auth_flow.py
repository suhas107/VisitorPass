import pyotp
import pytest
from app import create_app
from extensions import db


def setup_app():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
            "RESIDENT_ENROLL_CODE": "TESTCODE",
            "GUARD_ENROLL_CODE": "GUARD",
            "APP_SECRET": "testsecretkey",
            "SECRET_KEY": "supersecret",
        }
    )
    with app.app_context():
        db.create_all()
    return app


def test_login_and_mfa_flow():
    app = setup_app()
    client = app.test_client()
    # register resident
    resp = client.post(
        "/auth/register",
        data={
            "name": "Test User",
            "email": "test@example.com",
            "password": "Password1!",
            "confirm": "Password1!",
            "role": "RESIDENT",
            "room_number": "101",
            "email_code": "TESTCODE",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    # login (no MFA yet)
    resp = client.post(
        "/auth/login",
        data={"email": "test@example.com", "password": "Password1!"},
        follow_redirects=True,
    )
    assert b"Logged in" in resp.data
    # enable MFA
    client.get("/auth/enable-mfa")
    with client.session_transaction() as sess:
        secret = sess["provision_secret"]
    otp = pyotp.TOTP(secret).now()
    resp = client.post("/auth/enable-mfa", data={"otp": otp}, follow_redirects=True)
    assert b"MFA enabled" in resp.data
    # logout then login to trigger MFA challenge
    client.get("/auth/logout")
    resp = client.post(
        "/auth/login",
        data={"email": "test@example.com", "password": "Password1!"},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    # complete MFA
    with client.session_transaction() as sess:
        pending = sess.get("pending_user")
        assert pending is not None
    otp2 = pyotp.TOTP(secret).now()
    resp = client.post("/auth/mfa", data={"otp": otp2}, follow_redirects=True)
    assert b"MFA success" in resp.data
