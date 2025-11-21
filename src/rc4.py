# rc4.py — RC4 (stream) unified interface
from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes


def rc4_encrypt(plaintext: bytes):
    key = get_random_bytes(16)
    cipher = ARC4.new(key)
    ct = cipher.encrypt(plaintext)
    return (key, ct)


def rc4_decrypt(encrypted_tuple):
    key, ct = encrypted_tuple
    cipher = ARC4.new(key)
    pt = cipher.decrypt(ct)
    return pt


if __name__ == "__main__":
    t = rc4_encrypt(b"hello rc4")
    print(rc4_decrypt(t))
