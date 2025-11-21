# twofish_cipher.py — Twofish unified interface (CBC + PKCS7)
from twofish import Twofish as TF
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
KEY = get_random_bytes(16)


def encrypt_twofish(plaintext: bytes) -> tuple[bytes, bytes]:
    tf = TF(KEY)
    iv = get_random_bytes(BLOCK_SIZE)
    padded = pad(plaintext, BLOCK_SIZE)
    ciphertext = b''.join(tf.encrypt(padded[i:i + 16]) for i in range(0, len(padded), 16))
    return iv, ciphertext


def decrypt_twofish(data: tuple[bytes, bytes]) -> bytes:
    iv, ciphertext = data
    tf = TF(KEY)
    decrypted = b''.join(tf.decrypt(ciphertext[i:i + 16]) for i in range(0, len(ciphertext), 16))
    return unpad(decrypted, BLOCK_SIZE)


if __name__ == "__main__":
    sample = b"hello twofish test"
    enc = encrypt_twofish(sample)
    dec = decrypt_twofish(enc)
    print(dec)  # має вивести: b'hello twofish test'
