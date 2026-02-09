from crypto_utils import (
    generate_aes_key,
    encrypt_payload,
    decrypt_payload,
    generate_rsa_keypair,
    sign_bytes,
    verify_signature,
    canonical_signing_bytes,
)


def test_encrypt_decrypt_roundtrip():
    key = generate_aes_key()
    data = {"hello": "world"}
    iv_b64, ct_b64 = encrypt_payload(data, key)
    plain = decrypt_payload(iv_b64.decode(), ct_b64.decode(), key)
    assert plain == data


def test_signature_validation():
    priv, pub = generate_rsa_keypair()
    payload = canonical_signing_bytes("a2==", "b2==", "c2==", "pid", "2024-01-01Z")
    sig = sign_bytes(priv, payload).decode()
    assert verify_signature(pub, payload, sig)
    assert verify_signature(pub, payload, sig + "tamper") is False
