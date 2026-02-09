import base64
import json
import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_fernet(app_secret: str, salt: bytes = b"dormpass-salt") -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(app_secret.encode()))
    return Fernet(key)


def generate_rsa_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def encrypt_private_key(private_pem: bytes, fernet: Fernet) -> bytes:
    return fernet.encrypt(private_pem)


def decrypt_private_key(enc_private: bytes, fernet: Fernet) -> bytes:
    return fernet.decrypt(enc_private)


def wrap_aes_key(public_pem: bytes, aes_key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_pem)
    wrapped = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return base64.urlsafe_b64encode(wrapped)


def unwrap_aes_key(private_pem: bytes, wrapped_key_b64: str) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    wrapped = base64.urlsafe_b64decode(wrapped_key_b64)
    return private_key.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def encrypt_payload(payload: dict, key: bytes):
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    data = json.dumps(payload).encode()
    ciphertext = aesgcm.encrypt(iv, data, None)
    return base64.urlsafe_b64encode(iv), base64.urlsafe_b64encode(ciphertext)


def decrypt_payload(iv_b64: str, ciphertext_b64: str, key: bytes):
    aesgcm = AESGCM(key)
    iv = base64.urlsafe_b64decode(iv_b64)
    ciphertext = base64.urlsafe_b64decode(ciphertext_b64)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode())


def sign_bytes(private_pem: bytes, data: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.urlsafe_b64encode(signature)


def verify_signature(public_pem: bytes, data: bytes, signature_b64: str) -> bool:
    public_key = serialization.load_pem_public_key(public_pem)
    try:
        pad_len = (-len(signature_b64)) % 4
        signature = base64.b64decode(signature_b64 + ("=" * pad_len), altchars=b"-_", validate=True)
    except Exception:
        return False
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def canonical_signing_bytes(wrapped_key_b64: str, iv_b64: str, ciphertext_b64: str, pass_id: str, issued_at: str) -> bytes:
    combined = (
        base64.urlsafe_b64decode(wrapped_key_b64)
        + base64.urlsafe_b64decode(iv_b64)
        + base64.urlsafe_b64decode(ciphertext_b64)
        + pass_id.encode()
        + issued_at.encode()
    )
    return hashlib.sha256(combined).digest()


def generate_aes_key() -> bytes:
    return os.urandom(32)


def base64url_encode_json(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode()


def base64url_decode_json(data: str) -> dict:
    raw = base64.urlsafe_b64decode(data.encode())
    return json.loads(raw)
