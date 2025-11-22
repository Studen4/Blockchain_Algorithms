from src3.rsa_math_ds import modexp


def rsa_sign(private_d, n, m):
    return modexp(m, private_d, n)


def rsa_verify(public, m, s):
    return m == modexp(s, public.e, public.n)
