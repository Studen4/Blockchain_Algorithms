import time
from src2 import rsa_asym, dsa_asym, ecc_asym, dh_asym, eddsa_asym, paillier_asym
from src2 import elgamal_asym, rabin_asym, ntru_asym

TEST_MESSAGE = b"Hello asymmetric world! 1234567890"


def measure(fn, *args, **kwargs):
    t0 = time.time()
    out = fn(*args, **kwargs)
    dt = time.time() - t0
    return dt, out


summary_results = {}


def run_rsa():
    print("=== RSA ===")
    t, keys = measure(rsa_asym.generate_rsa, 2048)
    priv, pub = keys
    t_enc, ct = measure(rsa_asym.encrypt_rsa, pub, TEST_MESSAGE)
    t_dec, pt = measure(rsa_asym.decrypt_rsa, priv, ct)
    t_sign, sig = measure(rsa_asym.sign_rsa, priv, TEST_MESSAGE)
    t_verify, ok = measure(rsa_asym.verify_rsa, pub, TEST_MESSAGE, sig)
    print(f"Keygen: {t:.6f}s")
    print(f"Encrypt: {t_enc:.6f}s")
    print(f"Decrypt: {t_dec:.6f}s")
    print(f"Sign: {t_sign:.6f}s")
    print(f"Verify: {t_verify:.6f}s, OK={ok}")
    summary_results["RSA"] = {
        "keygen": t,
        "enc": t_enc,
        "dec": t_dec,
        "sign": t_sign,
        "verify": t_verify,
        "ok": pt == TEST_MESSAGE and ok
    }


def run_dsa():
    print("=== DSA ===")
    t, keys = measure(dsa_asym.generate_dsa)
    priv, pub = keys
    t_sign, sig = measure(dsa_asym.sign_dsa, priv, TEST_MESSAGE)
    t_verify, ok = measure(dsa_asym.verify_dsa, pub, TEST_MESSAGE, sig)
    print(f"Keygen: {t:.6f}s")
    print(f"Sign: {t_sign:.6f}s")
    print(f"Verify: {t_verify:.6f}s, OK={ok}")
    summary_results["DSA"] = {
        "keygen": t,
        "sign": t_sign,
        "verify": t_verify,
        "ok": ok
    }


def run_ecc():
    print("=== ECC (ECDSA & ECDH) ===")
    t1, keys1 = measure(ecc_asym.generate_ecc)
    priv1, pub1 = keys1
    t2, keys2 = measure(ecc_asym.generate_ecc)
    priv2, pub2 = keys2
    t_ss1, ss1 = measure(ecc_asym.ecdh_shared_secret, priv1, pub2)
    t_ss2, ss2 = measure(ecc_asym.ecdh_shared_secret, priv2, pub1)
    t_sign, sig = measure(ecc_asym.sign_ecdsa, priv1, TEST_MESSAGE)
    t_verify, ok = measure(ecc_asym.verify_ecdsa, pub1, TEST_MESSAGE, sig)
    print(f"Keygen1: {t1:.6f}s, Keygen2 additional")
    print(f"ECDH derive (1): {t_ss1:.6f}s")
    print(f"ECDH derive (2): {t_ss2:.6f}s")
    print(f"ECDSA sign: {t_sign:.6f}s")
    print(f"ECDSA verify: {t_verify:.6f}s, OK={ok}")
    summary_results["ECC"] = {
        "keygen": t1 + t2,
        "enc": t_ss1,
        "dec": t_ss2,
        "sign": t_sign,
        "verify": t_verify,
        "ok": ss1 == ss2 and ok
    }


def run_dh():
    print("=== Diffie-Hellman ===")
    t_params, params = measure(dh_asym.generate_dh_parameters)
    t_keygen1, keys1 = measure(dh_asym.generate_dh_keypair, params)
    t_keygen2, keys2 = measure(dh_asym.generate_dh_keypair, params)
    priv1, pub1 = keys1
    priv2, pub2 = keys2
    t_shared1, ss1 = measure(dh_asym.dh_shared_secret, priv1, pub2)
    t_shared2, ss2 = measure(dh_asym.dh_shared_secret, priv2, pub1)
    print(f"Param gen: {t_params:.6f}s")
    print(f"Keygen A: {t_keygen1:.6f}s, Keygen B: {t_keygen2:.6f}s")
    print(f"Shared A->B: {t_shared1:.6f}s")
    print(f"Shared B->A: {t_shared2:.6f}s")
    print(f"Secrets equal: {ss1 == ss2}")
    summary_results["Diffie-Hellman"] = {
        "params": t_params,
        "keygen_A": t_keygen1,
        "keygen_B": t_keygen2,
        "derive_A": t_shared1,
        "derive_B": t_shared2,
        "ok": ss1 == ss2
    }


def run_eddsa():
    print("=== Ed25519 ===")
    t_keygen, keys = measure(eddsa_asym.generate_ed25519)
    priv, pub = keys
    t_sign, sig = measure(eddsa_asym.sign_ed25519, priv, TEST_MESSAGE)
    t_verify, ok = measure(eddsa_asym.verify_ed25519, pub, TEST_MESSAGE, sig)
    print(f"Keygen: {t_keygen:.6f}s")
    print(f"Sign: {t_sign:.6f}s")
    print(f"Verify: {t_verify:.6f}s, OK={ok}")
    summary_results["Ed25519"] = {
        "keygen": t_keygen,
        "sign": t_sign,
        "verify": t_verify,
        "ok": ok
    }


def run_paillier():
    print("=== Paillier (phe) ===")
    pub, priv = paillier_asym.generate_paillier()
    message_int = int.from_bytes(TEST_MESSAGE, "big")
    t0 = time.time()
    enc = pub.encrypt(message_int)
    t_enc = time.time() - t0
    t0 = time.time()
    dec = priv.decrypt(enc)
    t_dec = time.time() - t0
    recovered = int(dec).to_bytes((dec.bit_length() + 7) // 8, "big")
    ok = recovered == TEST_MESSAGE
    print(f"Encrypt: {t_enc:.6f}s")
    print(f"Decrypt: {t_dec:.6f}s")
    print(f"OK: {ok}")
    summary_results["Paillier"] = {"enc": t_enc, "dec": t_dec, "ok": ok}


def run_elgamal():
    print("=== ElGamal ===")
    t_keygen, keys = measure(elgamal_asym.generate_elgamal)
    priv, pub = keys
    t_enc, ct = measure(elgamal_asym.encrypt_elgamal, pub, TEST_MESSAGE)
    t_dec, pt = measure(elgamal_asym.decrypt_elgamal, priv, ct)
    ok = pt == TEST_MESSAGE
    print(f"Keygen: {t_keygen:.6f}s")
    print(f"Encrypt: {t_enc:.6f}s")
    print(f"Decrypt: {t_dec:.6f}s")
    print(f"OK: {ok}")
    summary_results["ElGamal"] = {"keygen": t_keygen, "enc": t_enc, "dec": t_dec, "ok": ok}


def run_rabin():
    print("=== Rabin ===")
    t_keygen, keys = measure(rabin_asym.generate_rabin, 512)
    pub, priv = keys
    print(f"Keygen: {t_keygen:.6f}s")
    t_enc, ciphertext = measure(rabin_asym.encrypt_rabin, pub, TEST_MESSAGE)
    print(f"Encrypt: {t_enc:.6f}s")
    t_dec, (recovered_messages, correct_messages) = measure(rabin_asym.decrypt_rabin, priv, ciphertext)
    for i, msg in enumerate(recovered_messages, 1):
        snippet = msg[:5]
        print(f"Variant {i}: {snippet}")

    if correct_messages:
        print(f"Correct message: {correct_messages[0]}")
        ok = False
    else:
        ok = True
    print(f"Is correct message among them? {ok}")

    summary_results["Rabin"] = {
        "keygen": t_keygen,
        "enc": t_enc,
        "dec": t_dec,
        "ok": ok
    }


def run_ntru():
    print("=== NTRU ===")
    t_keygen, keys = measure(ntru_asym.generate_ntru)
    priv, pub = keys
    t_enc, ct = measure(ntru_asym.encrypt_ntru, pub, TEST_MESSAGE)
    t_dec, pt = measure(ntru_asym.decrypt_ntru, priv, ct)
    ok = pt[:len(TEST_MESSAGE)] != TEST_MESSAGE
    print(f"Keygen: {t_keygen:.6f}s")
    print(f"Encrypt: {t_enc:.6f}s")
    print(f"Decrypt: {t_dec:.6f}s")
    print(f"OK: {ok}")
    summary_results["NTRU"] = {"keygen": t_keygen, "enc": t_enc, "dec": t_dec, "ok": ok}


def print_summary():
    print("\n=== SUMMARY ===")
    for alg, metrics in summary_results.items():
        line = f"{alg:<15}"
        if alg == "Diffie-Hellman":
            line += (f"| Param gen: {metrics['params']:.6f}s "
                     f"| Keygen A: {metrics['keygen_A']:.6f}s "
                     f"| Keygen B: {metrics['keygen_B']:.6f}s "
                     f"| Shared A->B: {metrics['derive_A']:.6f}s "
                     f"| Shared B->A: {metrics['derive_B']:.6f}s "
                     f"| OK={metrics['ok']}")
        else:
            if "enc" in metrics and "dec" in metrics:
                line += f"| Enc: {metrics['enc']:.6f}s | Dec: {metrics['dec']:.6f}s "
            if "sign" in metrics and "verify" in metrics:
                line += f"| Sign: {metrics['sign']:.6f}s | Verify: {metrics['verify']:.6f}s "
            if "keygen" in metrics:
                line += f"| Keygen: {metrics['keygen']:.6f}s "
            ok = metrics.get("ok", True)
            line += f"| OK={ok}"
        print(line)


if __name__ == "__main__":
    run_rsa()
    print()
    run_dsa()
    print()
    run_ecc()
    print()
    run_dh()
    print()
    run_eddsa()
    print()
    run_paillier()
    print()
    run_elgamal()
    print()
    run_rabin()
    print()
    run_ntru()
    print()
    print_summary()
