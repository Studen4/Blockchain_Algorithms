from src3 import PublicKey, rsa_verify, make_signed
from src3.rsa_large_ds import generate_large_rsa, sign_large, verify_large


def main():
    public = PublicKey(187, 77)
    pairs = [
        make_signed(139, 90),
        make_signed(62, 163),
        make_signed(95, 57),
    ]

    print("=== RSA Digital Signature Verification ===")
    print(f"Public key: n={public.n}, e={public.e}")

    for p in pairs:
        ok = rsa_verify(public, p.m, p.s)
        print(f"m={p.m:3d} | s={p.s:3d} | verified={ok}")

    print("=== RSA Large Signature Test ===")
    pub, priv = generate_large_rsa(2048)

    messages = [
        b"Hello, blockchain! 1",
        b"This is a very very long message to sign."
    ]

    for msg in messages:
        sig = sign_large(priv, msg)
        ok = verify_large(pub, msg, sig)
        print(f"Message: {msg!r}")
        print(f"Signature (hex): {sig.hex()[:80]}...")
        print(f"Verified: {ok}\n")


if __name__ == "__main__":
    main()
