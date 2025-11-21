# cast128.py — CAST-128 (CBC + PKCS7)
try:
    from Crypto.Cipher import CAST
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except Exception:
    CAST = None

BLOCK_SIZE = 8


def generate_key(length: int = 16) -> bytes:
    from Crypto.Random import get_random_bytes
    return get_random_bytes(length)


def encrypt_cast128(plaintext: bytes):
    if CAST is None:
        raise RuntimeError("CAST-128 not available in this environment")
    key = generate_key(16)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = CAST.new(key, CAST.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return (key, iv, ct)


def decrypt_cast128(encrypted_tuple):
    if CAST is None:
        raise RuntimeError("CAST-128 not available in this environment")
    key, iv, ct = encrypted_tuple
    cipher = CAST.new(key, CAST.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt
