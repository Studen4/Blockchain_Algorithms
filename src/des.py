# des.py — DES unified interface (CBC + PKCS7)
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 8


def encrypt_des(plaintext: bytes):
    key = get_random_bytes(8)  # DES key 8 bytes
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    # return (key, iv, ciphertext)
    return (key, iv, ct)


def decrypt_des(encrypted_tuple):
    key, iv, ct = encrypted_tuple
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt


if __name__ == "__main__":
    tup = encrypt_des(b"hello des")
    print(decrypt_des(tup))
