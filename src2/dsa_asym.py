# dsa_asym.py
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from typing import Tuple


def generate_dsa(key_size: int = 2048) -> Tuple[bytes, bytes]:
    priv = dsa.generate_private_key(key_size=key_size)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def sign_dsa(priv_pem: bytes, message: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(message, hashes.SHA256())
    return sig


def verify_dsa(pub_pem: bytes, message: bytes, signature: bytes) -> bool:
    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(signature, message, hashes.SHA256())
        return True
    except Exception:
        return False
