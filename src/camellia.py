# camellia.py — Camellia unified interface (Camellia-128)
from Crypto.Util.Padding import pad, unpad
import os
import camellia

BLOCK_SIZE = 16


def encrypt_camellia(plaintext: bytes):
    key = os.urandom(16)
    iv = os.urandom(BLOCK_SIZE)
    cipher = camellia.CamelliaCipher(key=key, IV=iv, mode=camellia.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return key, iv, ct


def decrypt_camellia(data_tuple):
    key, iv, ct = data_tuple
    cipher = camellia.CamelliaCipher(key=key, IV=iv, mode=camellia.MODE_CBC)
    pt_padded = cipher.decrypt(ct)
    pt = unpad(pt_padded, BLOCK_SIZE)
    return pt
