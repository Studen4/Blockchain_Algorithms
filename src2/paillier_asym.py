# paillier_asym.py (PHE realization)
from phe import paillier
from typing import Tuple


def generate_paillier(key_size: int = 2048) -> Tuple[paillier.PaillierPublicKey, paillier.PaillierPrivateKey]:
    pub, priv = paillier.generate_paillier_keypair(n_length=key_size)
    return pub, priv


def encrypt_paillier(pub, plaintext: bytes) -> bytes:
    m = int.from_bytes(plaintext, byteorder="big")
    ct = pub.encrypt(m)
    return str(ct.ciphertext()).encode()


def decrypt_paillier(priv, ciphertext_bytes: bytes) -> bytes:
    ctext = int(ciphertext_bytes.decode())
    dec = priv.decrypt(ctext)
    return int(dec).to_bytes((dec.bit_length() + 7) // 8, byteorder="big")
