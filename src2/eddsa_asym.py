# eddsa_asym.py
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from typing import Tuple


def generate_ed25519() -> Tuple[bytes, bytes]:
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.Raw,
                                  format=serialization.PrivateFormat.Raw,
                                  encryption_algorithm=serialization.NoEncryption())
    pub_bytes = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return priv_pem, pub_bytes


def sign_ed25519(priv_bytes: bytes, message: bytes) -> bytes:
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.sign(message)


def verify_ed25519(pub_bytes: bytes, message: bytes, signature: bytes) -> bool:
    pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
    try:
        pub.verify(signature, message)
        return True
    except Exception:
        return False
