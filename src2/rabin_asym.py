from typing import Tuple
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


def available() -> bool:
    return True


def generate_rabin(key_size: int = 512) -> Tuple[int, Tuple[int, int]]:
    p = getPrime(key_size // 2)
    while p % 4 != 3:
        p = getPrime(key_size // 2)
    q = getPrime(key_size // 2)
    while q % 4 != 3:
        q = getPrime(key_size // 2)
    n = p * q
    return n, (p, q)


def encrypt_rabin(pub: int, plaintext: bytes) -> int:
    n = pub
    marker = b'@@'
    m = bytes_to_long(marker + plaintext)
    c = pow(m, 2, n)
    return c


def decrypt_rabin(priv: Tuple[int, int], ciphertext: int) -> tuple[list[bytes], list[int | bytes]]:
    p, q = priv
    n = p * q

    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    yp = pow(q, -1, p)
    yq = pow(p, -1, q)

    r1 = (mp * q * yq + mq * p * yp) % n
    r2 = n - r1
    r3 = (mp * q * yq - mq * p * yp) % n
    r4 = n - r3

    candidates = [r1, r2, r3, r4]
    messages = [long_to_bytes(r) for r in candidates]

    correct_messages = [msg[2:] for msg in messages if msg.startswith(b'@@')]
    return messages, correct_messages
