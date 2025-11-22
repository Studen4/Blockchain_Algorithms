# rsa_asym.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from typing import Tuple


def generate_rsa(key_size: int = 2048) -> Tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def encrypt_rsa(pub_pem: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(pub_pem)
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return ct


def decrypt_rsa(priv_pem: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    pt = priv.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return pt


def sign_rsa(priv_pem: bytes, message: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return sig


def verify_rsa(pub_pem: bytes, message: bytes, signature: bytes) -> bool:
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
