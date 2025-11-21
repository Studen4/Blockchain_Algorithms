# aes.py — AES-GCM unified interface
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def encrypt_aes_gcm(plaintext: bytes, aad: bytes | None = None):
    key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return (key, nonce, ct)


def decrypt_aes_gcm(encrypted_tuple, aad: bytes | None = None):
    key, nonce, ct = encrypted_tuple
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, aad)
    return pt


if __name__ == "__main__":
    key, n, ct = encrypt_aes_gcm(b"hello aes")
    print(decrypt_aes_gcm((key, n, ct)))
