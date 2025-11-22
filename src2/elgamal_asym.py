import random
import secrets
from typing import Tuple

PRIME_BITS = 512


def available() -> bool:
    return True


def generate_prime(bits: int) -> int:
    while True:
        n = secrets.randbits(bits) | 1
        if is_prime(n):
            return n


def is_prime(n: int, k: int = 5) -> bool:
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_elgamal(key_size: int = PRIME_BITS) -> Tuple[dict, dict]:
    p = generate_prime(key_size)
    g = random.randrange(2, p - 1)
    x = random.randrange(1, p - 2)
    y = pow(g, x, p)
    priv = {'p': p, 'g': g, 'x': x}
    pub = {'p': p, 'g': g, 'y': y}
    return priv, pub


def encrypt_elgamal(pub: dict, plaintext: bytes) -> Tuple[int, int]:
    m = int.from_bytes(plaintext, 'big')
    p, g, y = pub['p'], pub['g'], pub['y']
    k = random.randrange(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2


def decrypt_elgamal(priv: dict, ciphertext: Tuple[int, int]) -> bytes:
    c1, c2 = ciphertext
    p, x = priv['p'], priv['x']
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, 'big')
