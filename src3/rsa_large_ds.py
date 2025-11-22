from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class PublicKey:
    def __init__(self, rsa_key: RSA.RsaKey):
        self._rsa_key = rsa_key

    @property
    def n(self):
        return self._rsa_key.n

    @property
    def e(self):
        return self._rsa_key.e

    @property
    def rsa_key(self):
        return self._rsa_key


class PrivateKey:
    def __init__(self, rsa_key: RSA.RsaKey):
        self._rsa_key = rsa_key

    @property
    def n(self):
        return self._rsa_key.n

    @property
    def d(self):
        return self._rsa_key.d

    @property
    def rsa_key(self):
        return self._rsa_key


def generate_large_rsa(key_size: int = 2048):
    key = RSA.generate(key_size)
    priv = PrivateKey(key)
    pub = PublicKey(key.publickey())
    return pub, priv


def sign_large(priv: PrivateKey, message: bytes) -> bytes:
    h = SHA256.new(message)
    signature = pkcs1_15.new(priv.rsa_key).sign(h)
    return signature


def verify_large(pub: PublicKey, message: bytes, signature: bytes) -> bool:
    h = SHA256.new(message)
    try:
        pkcs1_15.new(pub.rsa_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
