# ntru_asym.py - Example theoretical realization
from typing import Tuple, List
from Crypto.Util.number import bytes_to_long, long_to_bytes
import random


def available():
    return True


def poly_add(a, b, q):
    return [(x + y) % q for x, y in zip(a, b)]


def poly_mul(a, b, q):
    n = len(a)
    res = [0] * n
    for i in range(n):
        for j in range(n):
            res[(i + j) % n] = (res[(i + j) % n] + a[i] * b[j]) % q
    return res


def poly_inv_mod_prime(f, p):
    n = len(f)
    inv = [0] * n
    inv[0] = pow(f[0], -1, p)
    return inv


def generate_ntru(mode: str = "demo") -> Tuple[Tuple[List[int], int, int], List[int]]:
    N = 11
    p = 3
    q = 128

    f = [random.randint(1, p - 1) for _ in range(N)]
    g = [random.randint(0, p - 1) for _ in range(N)]
    f_inv_p = poly_inv_mod_prime(f, p)
    fg = poly_mul(f_inv_p, g, q)
    h = [(p * x) % q for x in fg]

    priv = (f, p, q)
    pub = h
    return priv, pub


def encrypt_ntru(pub: List[int], plaintext: bytes) -> List[int]:
    h = pub
    N = len(h)
    q = 128
    m_num = bytes_to_long(plaintext)
    m = [(m_num >> (8 * i)) & 0xFF for i in range(N)]
    m = [x % q for x in m]

    r = [random.randint(0, 3) for _ in range(N)]
    rh = poly_mul(r, h, q)
    e = poly_add(rh, m, q)
    return e


def decrypt_ntru(priv: Tuple[List[int], int, int], ciphertext: List[int]) -> bytes:
    f, p, q = priv
    N = len(f)
    a = poly_mul(f, ciphertext, q)

    m_mod_p = [x % p for x in a]
    m_num = 0
    for i in range(N - 1, -1, -1):
        m_num = (m_num << 8) | m_mod_p[i]

    return long_to_bytes(m_num)
