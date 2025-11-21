# chacha20.py — ChaCha20-Poly1305 unified interface (AEAD)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os


def generate_key() -> bytes:
    return ChaCha20Poly1305.generate_key()


def chacha20_encrypt(plaintext: bytes, aad: bytes | None = None):
    key = generate_key()
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return (key, nonce, ct)


def chacha20_decrypt(encrypted_tuple, aad: bytes | None = None):
    key, nonce, ct = encrypted_tuple
    aead = ChaCha20Poly1305(key)
    pt = aead.decrypt(nonce, ct, aad)
    return pt


if __name__ == "__main__":
    t = chacha20_encrypt(b"hello chacha")
    print(chacha20_decrypt(t))
