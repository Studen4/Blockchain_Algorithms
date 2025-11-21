# blowfish.py — Blowfish unified interface (CBC + PKCS7)
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = Blowfish.block_size


def generate_key(length: int = 16) -> bytes:
    return get_random_bytes(length)


def encrypt_blowfish(plaintext: bytes):
    key = generate_key()
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return (key, iv, ct)


def decrypt_blowfish(encrypted_tuple):
    key, iv, ct = encrypted_tuple
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt


if __name__ == "__main__":
    t = encrypt_blowfish(b"hello blowfish")
    print(decrypt_blowfish(t))
