# dh_asym.py
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


def generate_dh_parameters(key_size: int = 2048):
    return dh.generate_parameters(generator=2, key_size=key_size)


def generate_dh_keypair(parameters):
    priv = parameters.generate_private_key()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.PKCS8,
                                  encryption_algorithm=serialization.NoEncryption())
    pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def dh_shared_secret(priv_pem: bytes, peer_pub_pem: bytes) -> bytes:
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    peer_pub = serialization.load_pem_public_key(peer_pub_pem)
    shared = priv.exchange(peer_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dh handshake").derive(shared)
    return key
