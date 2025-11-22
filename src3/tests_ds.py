from .rsa_sign_ds import rsa_verify
from .model_ds import PublicKey
from .utils_ds import make_signed

public = PublicKey(n=187, e=77)

tests = [
    make_signed(139, 90),
    make_signed(62, 163),
    make_signed(95, 57),
]


def run_tests():
    print("=== RSA DS TESTS ===")
    for t in tests:
        valid = rsa_verify(public, t.m, t.s)
        print(f"m={t.m} | s={t.s} | valid={valid}")
