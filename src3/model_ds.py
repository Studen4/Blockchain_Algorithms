class PublicKey:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e


class PrivateKey:
    def __init__(self, n: int, d: int):
        self.n = n
        self.d = d


class SignedMessage:
    def __init__(self, m: int, s: int):
        self.m = m
        self.s = s
