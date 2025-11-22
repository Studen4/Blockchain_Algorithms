def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def modexp(base, exp, mod):
    return pow(base, exp, mod)
