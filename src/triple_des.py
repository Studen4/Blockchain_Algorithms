# triple_des.py — 3DES unified interface (CBC + PKCS7)
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def _generate_3des_key():
    key = DES3.adjust_key_parity(get_random_bytes(24))
    return key


def encrypt_3des(plaintext: bytes):
    key = _generate_3des_key()
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, DES3.block_size))
    return (key, iv, ct)


def decrypt_3des(encrypted_tuple):
    key, iv, ct = encrypted_tuple
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), DES3.block_size)
    return pt


if __name__ == "__main__":
    t = encrypt_3des(b"hello 3des")
    print(decrypt_3des(t))
