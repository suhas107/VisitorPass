# VisitorPass Viva Brief

## Project Intro (what/why)
VisitorPass is a secure apartment visitor management system. Residents issue time-bound, encrypted QR passes for guests; guards validate passes on arrival; admins manage users/logs. It fits the cyber security lab because it demonstrates end-to-end application security: authentication (1FA+MFA), authorization via ACL, encryption/signatures, hashing, encoding, NIST-aligned auth architecture, and full audit logging—all runnable locally with open-source tools.

## Real-world usage
- Resident creates a pass with validity window; system encrypts payload, signs it, and encodes as QR/token.
- Guard scans/pastes token; system verifies signature, unwraps key, decrypts payload, checks status/time, marks USED, and logs the event.
- Admin oversees users/roles/logs and can deactivate accounts/passes.

## Evaluation Components → What/How/Where

### 1) Authentication (3m)
- **Single-factor (password login)**: Flask-Login sessions with Argon2 password verifier. *Where*: `auth/routes.py` (`login`), `models.User.check_password`, `passlib[argon2]`.
- **Multi-factor (password + TOTP)**: `pyotp` TOTP; enable flow shows provisioning QR; login challenge verifies OTP. *Where*: `auth/routes.py` (`enable_mfa`, `mfa_challenge`), `templates/mfa_setup.html`; secrets encrypted with Fernet.
- **NIST SP 800-63-2 alignment**: Claimant (user), RA (register verifies enroll codes), CSP (stores hashed password, issues TOTP secret), Verifier (password+OTP check, issues signed assertion), RP (consumes assertion). *Where*: `README.md` (NIST section), `auth/routes.py` (`issue_assertion`), `rp/routes.py` (`_ensure_assertion`), blueprints split (`auth`=RA/CSP/Verifier, `rp`=RP).

### 2) Authorization / Access Control (3m)
- **Access Control Model (ACL)**: Subjects RESIDENT/GUARD/ADMIN; Objects PASS/ENTRY_LOG/RESIDENT_DIRECTORY/USER; permissions table. *Where*: `acl.py`, `README.md` (ACL table).
- **Policy definition & justification**: Documented in README ACL section; enforced checks include ownership (read_own/revoke_own) and role gates.
- **Programmatic enforcement**: `@require_permission` decorator on guard/admin/resident routes; ownership filters in `rp/routes.py`, `admin/routes.py`.

### 3) Encryption (3m)
- **Key exchange/transport**: RSA-OAEP wraps per-pass AES-256 key using Security Desk guard public key. *Where*: `rp/routes.py` (pass creation/verify), `crypto_utils.wrap_aes_key/unwrap_aes_key`; guard keypair seeded in `app.py` (`KeyStore`).
- **Encrypt/Decrypt**: AES-256-GCM encrypts pass payload with random IV; guard decrypts after unwrapping AES key. *Where*: `crypto_utils.encrypt_payload/decrypt_payload`, used in `rp/routes.py` (create/guard_verify). Private keys encrypted at rest with Fernet derived from `APP_SECRET`.

### 4) Hashing & Digital Signature (3m)
- **Hashing with salt**: Argon2 for passwords and recovery code hashing. *Where*: `models.User.set_password/check_password`, `auth/routes.py` (registration), `requirements.txt` (`passlib[argon2]`).
- **Digital signature (hash-based)**: Resident RSA-PSS over canonical SHA-256 bytes of wrapped_key+iv+ciphertext+pass_id+issued_at; guard verifies with resident public key. *Where*: `crypto_utils.canonical_signing_bytes/sign_bytes/verify_signature`, used in `rp/routes.py` (create/guard_verify).

### 5) Encoding Techniques (3m total: 1 for encoding/decoding + 2 theory)
- **Encoding/Decoding implementation**: Pass token JSON → base64url string → QR (qrcode); decoding in guard verify via `base64url_decode_json`; QR scan via html5-qrcode/jsQR. *Where*: `crypto_utils.base64url_encode_json/decode`, `rp/routes.py` (build_token/guard_verify), `templates/pass_detail.html`, `templates/guard_scan.html`.
- **Security Levels & Risks (theory)**: *Where*: `README.md` (Theory: Security Levels & Risks).
- **Possible Attacks (theory)**: *Where*: `README.md` (Theory: Possible Attacks, Countermeasures).

### Viva / Conceptual Clarity (2m) & Participation (3m) / Complete Viva (5m)
- **Design choices documented**: README covers why AES-GCM, RSA-OAEP, RSA-PSS, Argon2, TOTP; ACL rationale; replay prevention (`USED` state). *Where*: `README.md` (Security Design Choices, Theory, Demo Guide).
- **Awareness of attacks/countermeasures**: Listed and mapped to mitigations (rate limiting, CSRF, Argon2, signatures, key wrapping, audit logs). *Where*: `README.md` (Theory sections).

## File/Module Map (quick reference)
- App setup/seeding: `app.py` (admin + guard keypair seed; Fernet derivation; CLI reseed/show secret).
- Config/env: `config.py`, `.env.example`, `.env` (APP_SECRET, enroll codes, DB).
- Extensions: `extensions.py` (db, login, csrf).
- Models: `models.py` (User, ResidentProfile, Pass, EntryLog, KeyStore).
- ACL: `acl.py` (permissions + decorator).
- Crypto helpers: `crypto_utils.py` (Fernet derivation, RSA keygen, OAEP wrap/unwrap, AES-GCM, RSA-PSS, base64url, canonical hash).
- Auth (RA/CSP/Verifier): `auth/routes.py`, `auth/forms.py`, templates `login.html`, `register.html`, `mfa_setup.html`.
- RP (Resident/Guard): `rp/routes.py`, `rp/forms.py`, templates `resident_dashboard.html`, `create_pass.html`, `pass_detail.html`, `guard_scan.html`.
- Admin: `admin/routes.py`, templates `admin_dashboard.html`, `users.html`.
- UI assets: `static/main.css`, `static/main.js`.
- Tests: `tests/test_auth_flow.py`, `tests/test_crypto.py`, `tests/test_acl.py`.
- Utilities: `reseed_guard.py` (regenerate guard key), `reset_admin.py` (reset admin password), `show_secret.py` (debug APP_SECRET/Fernet).
- Docs: `README.md`, `VIVA.md` (this brief).

## How it satisfies the rubric (concise mapping)
- **Single-factor Auth**: Password login via Flask-Login + Argon2. (auth/routes.py, models.py)
- **MFA**: TOTP with pyotp, QR provisioning, OTP verify. (auth/routes.py, mfa_setup.html)
- **Access Control Matrix**: 3 subjects x 3+ objects; ACL in code + README. (acl.py, README)
- **Enforced ACL**: Decorator + ownership checks. (rp/routes.py, admin/routes.py)
- **Key Exchange/Transport**: RSA-OAEP wrapping AES key. (crypto_utils.py, rp/routes.py)
- **Encrypt/Decrypt**: AES-256-GCM payloads. (crypto_utils.py, rp/routes.py)
- **Hashing with Salt**: Argon2 for passwords and recovery code. (models.py, auth/routes.py)
- **Digital Signature**: RSA-PSS over canonical SHA-256 hash. (crypto_utils.py, rp/routes.py)
- **Encoding**: Base64url + QR; decoding in guard verify; scan/upload. (crypto_utils.py, guard_scan.html)
- **Theory (Security levels/risks, attacks, countermeasures)**: README Theory sections.
- **NIST SP 800-63-2 alignment**: Roles mapped in README + code separation (auth vs rp), assertion issuance/consumption.

## Demo script (2–3 minutes)
1. Show landing page: “VisitorPass for apartment visitors.”
2. Register resident with `RESIDENT_ENROLL_CODE` (resident-secret), enable MFA (optional), create a pass, view QR/token.
3. Register guard with `GUARD_ENROLL_CODE` (guard-secret), open scan page, scan QR/paste token → show VALID result card and note pass marked USED.
4. Show guard logs updated.
5. Log in as admin (`admin@visitorpass.local / Admin@12345`), show user management and logs.

## Why this fits the lab
- Realistic application (apartment visitor control) with cohesive security: MFA, ACL, crypto for confidentiality/integrity, encoding, hashing, NIST-aligned auth flow, and audit logs—all implemented with open-source tools and runnable locally.

## Oral Examination Prep (concepts & talking points)
- **Authentication**: Explain password + TOTP (pyotp), why Argon2, session assertions, CSRF protection, rate limiting.
- **Authorization**: Walk through ACL subjects/objects, decorator enforcement, and ownership checks; justify least-privilege choices.
- **Crypto design**: Why AES-GCM (AEAD), RSA-OAEP for key transport, RSA-PSS for signatures, Fernet for private key/TOTP secret at rest; canonical signing bytes; replay prevention via `USED`.
- **NIST mapping**: Identify Claimant/RA/CSP/Verifier/RP roles in code and data flow.
- **Attacks & mitigations**: Phishing/credential stuffing (MFA, Argon2, rate limits), replay/token theft (time windows, USED), tampering (signatures), key theft (Fernet + APP_SECRET), CSRF/XSS (Flask-WTF, templating), MITM (HTTPS in prod).
- **Encoding/QR**: Base64url token structure, QR size/error correction trade-offs, scan/upload paths.
- **Data model & audit**: Pass status transitions, EntryLog on every verification, admin deactivate users/passes.
- **Operational**: ENV secrets (APP_SECRET, enroll codes), guard keystore reseed, admin reset, test coverage (pytest).
- **MFA UX**: Google Authenticator (and any TOTP app) ready—provision via QR in “Enable MFA,” then enter 6-digit codes at login.

## Conceptual clarity & security reasoning (quick answers)
- **Why Argon2?** Memory-hard password hashing to resist GPU/ASIC brute force; salted automatically. Recovery codes also hashed.
- **Why TOTP (pyotp)?** Free, offline second factor; avoids paid SMS/email; QR provisioning simplifies enrollment.
- **Why RSA-OAEP + AES-GCM?** Hybrid crypto: OAEP securely transports a fresh AES-256 key; GCM provides confidentiality + integrity with nonces.
- **Why RSA-PSS signatures?** Modern padding for RSA signatures; combined with canonical hashing to prevent tampering/replay.
- **Why Fernet for key-at-rest?** Protects private keys/TOTP secrets using APP_SECRET-derived key via PBKDF2; keeps DB secrets unusable if exfiltrated without env.
- **Replay prevention?** Passes marked `USED` after valid scan; validity window enforced; status check blocks REVOKED/EXPIRED/USED.
- **ACL rationale?** Least privilege: residents manage own passes; guards validate/log; admins manage users/logs. Decorators + ownership checks enforce it.
- **Assertion model?** Verifier issues signed session assertion (itsdangerous); RP consumes it to ensure authenticated, MFA-verified sessions.
- **CSRF/session safety?** Flask-WTF CSRF tokens; HTTPOnly cookies; recommend Secure/SameSite in production.
- **Error handling/UX?** Clear status on scan/paste; fallback decoder; warnings for oversized QR; admin reset/reseed scripts for recovery.

## Attacks & countermeasures (ready-made points)
- **Phishing/credential stuffing**: MFA + Argon2 + rate limiting.
- **Replay/token theft**: Short validity, `USED` flag, signatures binding token to resident/guard keys.
- **Tampering**: RSA-PSS over canonical SHA-256 bytes; signature fail rejects.
- **Key theft**: Private keys/TOTP secrets encrypted with Fernet using APP_SECRET; guard keystore reseed if secret changes.
- **CSRF/XSS/SQLi**: CSRF tokens on forms/AJAX; Jinja auto-escape; SQLAlchemy ORM for queries.
- **MITM**: Use HTTPS in deployment; HTTPOnly/SameSite cookies.
- **Brute-forcing OTP**: 6-digit TOTP with drift window=1; rate limiting on login.
- **Why TOTP (pyotp)?** Free, offline second factor; avoids paid SMS/email; QR provisioning simplifies enrollment; works with Google Authenticator/1Password/Authy.
