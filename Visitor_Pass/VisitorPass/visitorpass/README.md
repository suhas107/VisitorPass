# VisitorPass
Secure apartment visitor pass demo showcasing MFA, ACL/RBAC, encryption, signatures, and QR validation. Built with Flask, SQLAlchemy, and open-source crypto primitives.

## Quickstart
1. `cd dormpass && python3 -m venv .venv && source .venv/bin/activate` (or `Scripts\activate` on Windows)
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and adjust secrets. Default admin: `admin@visitorpass.local / Admin@12345` (change after first login). Demo codes: `resident-secret` (resident enroll) and `guard-secret` (guard enroll).
4. `python app.py` and open http://localhost:5000
5. Run tests: `pytest`

Codes you need (from `.env`):
- `GUARD_ENROLL_CODE`: shared secret to allow guard self-enrollment (default `guard-secret`).
- `RESIDENT_ENROLL_CODE` (alias `EMAIL_VERIFICATION_CODE`): resident enroll code required on registration (default `resident-secret`).

## Feature-to-Rubric Checklist
- **Authentication (single + MFA)**: `auth/routes.py` login + `/auth/mfa`, `pyotp` TOTP, QR provisioning on `/auth/enable-mfa`.
- **Authorization (ACL)**: Matrix in `acl.py`, decorator `require_permission`, enforced on guard/admin routes; README table below.
- **Hashing (salted)**: Argon2 via passlib for passwords and recovery codes (`models.User.password_hash`, `recovery_code_hash`).
- **Encryption (key transport + encrypt/decrypt)**: RSA-OAEP wrapping AES-256-GCM keys in `rp/routes.py` (pass creation/verify) and `crypto_utils.py`; guard private key encrypted at rest.
- **Digital Signature (hash-based)**: Resident RSA key signs canonical hash of encrypted packet (RSA-PSS SHA-256) in `rp/routes.py`; verified on guard validate.
- **Encoding (Base64 + QR)**: Pass token base64url encoded (`crypto_utils.base64url_encode_json`) and rendered as QR (`pass_detail.html`, `guard_scan.html` uses html5-qrcode CDN).
- **Access Control Subjects/Objects**: Subjects RESIDENT/GUARD/ADMIN; Objects PASS/ENTRY_LOG/RESIDENT_DIRECTORY/USER. Matrix enforced, table below.
- **NIST SP 800-63-2 mapping**: Documented below; verifier assertion implemented with `itsdangerous` signed token stored in session (`auth.routes.issue_assertion` -> RP check).
- **Rate limiting/lockout**: In-memory limiters in `auth/routes.py` protect login.
- **Seed data**: Admin account + Security Desk guard keypair auto-created on startup (`app.py`).


Here’s how the current VisitorPass repo satisfies each rubric item for full credit:

Authentication: single + MFA: Password login via Flask-Login/Argon2 (routes.py (lines 75-135)), TOTP MFA flow with QR provisioning and OTP verification (routes.py (lines 139-189), mfa_setup.html). Sessions carry a signed assertion for RP checks (itsdangerous).
Authorization (Access Control Matrix/ACL): Explicit matrix and decorator in acl.py; enforced on resident/guard/admin routes (routes.py, routes.py). README includes the ACL table and justification.
Encryption (key exchange + encrypt/decrypt): Per-pass AES-256-GCM payloads, RSA-OAEP wrapping of the AES key with guard public key, guard unwraps and decrypts on validation (routes.py (lines 69-232), crypto_utils.py). Guard private key and user private keys are Fernet-encrypted at rest.
Hashing with salt: Argon2 password hashing and recovery-code hashing (models.py, routes.py registration). No plaintext secrets stored.
Digital Signature (hash-based): Resident RSA-PSS signatures over canonical SHA-256 hash of wrapped_key+iv+ciphertext+pass_id+issued_at; verified on guard validation (crypto_utils.py, routes.py guard_verify).
Encoding (Base64 + QR): Pass token JSON is base64url-encoded (crypto_utils.base64url_encode_json) and rendered as QR for residents; guards scan via html5-qrcode CDN or paste token (pass_detail.html, guard_scan.html).
NIST SP 800-63-2 mapping: Documented in README (role mapping) and implemented separation of RA/CSP/Verifier in auth blueprint and RP in rp blueprint with signed assertion (routes.py issue_assertion, _ensure_assertion in routes.py and routes.py).
Access Control subjects/objects: Subjects: RESIDENT/GUARD/ADMIN; Objects: PASS, ENTRY_LOG, RESIDENT_DIRECTORY, USER. Matrix and enforcement present (acl.py, README table).
Rate limiting / lockout: In-memory attempt tracking on login (routes.py).
Seed data: Admin account and Security Desk guard keypair auto-created on startup (app.py).
Tests: test_auth_flow.py (login + MFA), test_crypto.py (encrypt/decrypt + signature), test_acl.py (permissions). Run via pytest.
UI/UX: Premium theme, clear QR/token display, guard scanner, resident/admin dashboards (templates + main.css).
Theory & attacks: README covers Security Levels/Risks, Possible Attacks, Countermeasures sections.
Demo guide: README has step-by-step demo, one-minute talk track, and screenshot checklist.

## NIST SP 800-63-2 Role Mapping
- **Claimant**: Any user (resident/guard/admin) submitting credentials during `/auth/login` and `/auth/mfa`.
- **Registration Authority (RA)**: `/auth/register` validates identity attributes and requires `RESIDENT_ENROLL_CODE` (free out-of-band check) and guard enroll code for guards.
- **Credential Service Provider (CSP)**: Same auth blueprint issues/verifies credentials—stores Argon2 password verifiers and encrypted TOTP secrets; generates resident RSA signing keys.
- **Verifier**: `/auth/login` + `/auth/mfa` validate password + OTP and issue a signed assertion via `issue_assertion` (itsdangerous) after successful proofing.
- **Relying Party (RP)**: RP blueprint routes (e.g., `/dashboard`, `/passes/create`) consume the assertion (`_ensure_assertion`) to authorize access and drive application logic.

## Access Control Matrix (enforced in `acl.py`)
| Subject   | PASS                          | ENTRY_LOG              | RESIDENT_DIRECTORY        | USER |
|-----------|------------------------------|------------------------|---------------------------|------|
| RESIDENT  | create, read_own, revoke_own | read_own               | read_self                 | -    |
| GUARD     | validate, read_minimal       | create, read_own       | read_all                  | -    |
| ADMIN     | read_all, revoke_all         | read_all               | read_all                  | manage |
Decorator `require_permission` plus ownership checks guard routes (`rp/routes.py`, `admin/routes.py`).

## Pass Crypto Pipeline
1. Resident creates a pass (`/passes/create`):
   - AES-256 key generated per pass; payload (visitor/resident/time window) encrypted with AES-GCM.
   - Security Desk guard RSA public key wraps the AES key via RSA-OAEP-SHA256.
   - Canonical signing bytes: `sha256(wrapped_key + iv + ciphertext + pass_id + issued_at)`; signed with resident RSA private key using RSA-PSS-SHA256.
   - Token JSON → base64url string → QR.
2. Guard validation (`/guard/verify`):
   - Base64url decode JSON, verify resident signature, unwrap AES key with guard private key (encrypted at rest with Fernet derived from `APP_SECRET`), decrypt payload.
   - Check status/time window; mark pass `USED` to prevent replay; log every attempt in `EntryLog`.

Token format (Base64URL of JSON):
```json
{
  "pass_id": "...",
  "resident_id": 1,
  "guard_key_id": 1,
  "wrapped_key": "...",
  "iv": "...",
  "ciphertext": "...",
  "sig": "...",
  "alg": {"enc": "AES-256-GCM", "wrap": "RSA-OAEP-SHA256", "sig": "RSA-PSS-SHA256"},
  "issued_at": "2024-...Z"
}
```

## Security Design Choices
- **AES-GCM** for confidentiality + integrity with nonces per pass; fast and AEAD.
- **RSA-OAEP** for secure key transport of the per-pass AES key to the guard station.
- **RSA-PSS** signatures over hashed canonical bytes to detect tampering and tie passes to residents.
- **Argon2** for salted password and recovery-code hashing; memory-hard vs. brute force.
- **TOTP MFA** (pyotp) avoids paid SMS/email, works offline; QR provisioning provided.
- **Fernet-wrapped private keys/TOTP secrets** derived from `APP_SECRET` via PBKDF2 to protect keys at rest.
- **Replay prevention** by marking passes `USED` after successful validation and enforcing validity windows.
- **CSRF** via Flask-WTF on all forms and AJAX tokens; HTTPOnly session cookies (set `Secure` in production with HTTPS).
- **Rate limiting** on login per IP and per account to deter guessing; accounts can be disabled by admin.

## Theory: Security Levels & Risks
- Assurance rises from password-only to password+TOTP; still at risk from device theft or token leakage.
- QR/base64 tokens are bearer artifacts; theft enables replay unless invalidated quickly (short windows + `USED` flag).
- Private key compromise (resident or guard) undermines authenticity/decryption; protect `APP_SECRET` and filesystem permissions.

### Possible Attacks
- Phishing/credential stuffing; OTP brute force; MITM on HTTP; QR token theft; replay before `USED`; SQLi/XSS/CSRF; key theft from disk.

### Countermeasures
- Argon2 hashing, MFA, rate limiting, account disable, and recovery codes.
- HTTPS (out-of-scope locally), HTTPOnly/SameSite cookies, CSRF tokens, input validation via WTForms.
- RSA-PSS signature verification, AES-GCM integrity, short validity windows, `USED` marking, and full audit logs per scan.
- Keys/TOTP secrets encrypted with Fernet; guard RSA private key never leaves server.

## Demo Guide
Use these steps to demo live to others (projector or shared screen works great):
1. Start the app: `python app.py` and open http://localhost:5000.
2. Show the landing page and register a **Resident** using the `RESIDENT_ENROLL_CODE` from `.env`.
3. As the resident, create a visitor pass and open the pass detail to show the QR + token.
4. In a new private window (or log out), register a **Guard** using the `GUARD_ENROLL_CODE`.
5. As the guard, open **Scan Pass**, scan the QR or paste the token, and show the VALID result + log entry.
6. Log in as **Admin** (`admin@visitorpass.local / Admin@12345`), open **Logs** and **Users**, and show role-based access.

Short version:
- **Resident**: Register → create pass → show QR/token → revoke optional.
- **Guard**: Register → scan/pass token → see VALID/INVALID + logs.
- **Admin**: Login → manage users → view logs + resident directory.

One‑Minute Demo (talk track):
1. “This is VisitorPass — encrypted visitor passes with MFA and signed QR tokens.”
2. “Resident creates a pass; here’s the QR and token.”
3. “Guard scans it — signature verified, key unwrapped, payload decrypted.”
4. “Entry log is auto‑recorded; admin can audit everything.”

Screenshot Checklist (optional):
- Landing page (hero + feature cards)
- Resident dashboard (passes list)
- Pass detail (QR + token)
- Guard scanner result (VALID)
- Admin logs and users

## Tests
- `tests/test_crypto.py`: AES-GCM roundtrip + RSA-PSS signature validity checks.
- `tests/test_acl.py`: ACL expectations for roles.
- `tests/test_auth_flow.py`: Registration, login, MFA enable, MFA challenge success using pyotp.

## Notes
- SQLite file auto-created; times are naive UTC (`datetime.utcnow()`); adjust for timezone as needed.
- Guard Security Desk keypair auto-seeded in `KeyStore` with private key encrypted using Fernet derived from `APP_SECRET`.
- All dependencies are free/open-source; MFA uses offline TOTP (no paid services).

## Troubleshooting
- If guard scans return `DECRYPT_FAIL`: your `.env` `APP_SECRET` likely changed after the DB/keystore was created. Regenerate the guard keypair (invalidates old passes) with: `python reseed_guard.py` from the `dormpass` folder, then restart and create new passes.
