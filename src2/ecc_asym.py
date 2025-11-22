# ecc_asym.py (ECDSA + ECDH)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from typing import Tuple


def generate_ecc(curve=ec.SECP256R1()) -> Tuple[bytes, bytes]:
    priv = ec.generate_private_key(curve)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.PKCS8,
                                  encryption_algorithm=serialization.NoEncryption())
    pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def ecdh_shared_secret(priv_pem: bytes, peer_pub_pem: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    peer_pub = serialization.load_pem_public_key(peer_pub_pem)
    shared = priv.exchange(ec.ECDH(), peer_pub)
    # Derive a key (render as bytes)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"handshake data").derive(shared)
    return derived


def sign_ecdsa(priv_pem: bytes, message: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    return sig


def verify_ecdsa(pub_pem: bytes, message: bytes, signature: bytes) -> bool:
    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
