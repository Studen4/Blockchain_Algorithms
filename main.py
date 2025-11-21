import time

# AES (GCM)
from src.aes import encrypt_aes_gcm, decrypt_aes_gcm
# DES
from src.des import encrypt_des, decrypt_des
# 3DES
from src.triple_des import encrypt_3des, decrypt_3des
# Blowfish
from src.blowfish import encrypt_blowfish, decrypt_blowfish
# Twofish
from src.twofish_cipher import encrypt_twofish, decrypt_twofish
# RC4
from src.rc4 import rc4_encrypt, rc4_decrypt
# ChaCha20
from src.chacha20 import chacha20_encrypt, chacha20_decrypt
# Serpent
from src.serpent_cipher import encrypt_serpent, decrypt_serpent
# CAST-128
from src.cast128 import encrypt_cast128, decrypt_cast128
# Camellia
from src.camellia import encrypt_camellia, decrypt_camellia


TEST_DATA = b"Hello blockchain world! 1234567890"


def test_algorithm(name, encrypt_func, decrypt_func):
    print(f"\n===== Testing {name} =====")

    # Encrypt
    start = time.time()
    encrypted = encrypt_func(TEST_DATA)
    enc_time = time.time() - start

    # Decrypt
    start = time.time()
    decrypted = decrypt_func(encrypted)
    dec_time = time.time() - start

    success = (decrypted == TEST_DATA)

    print(f"Encrypted sample: {str(encrypted)[:60]}...")
    print(f"Decryption OK:   {success}")
    print(f"Encrypt time:    {enc_time:.6f} sec")
    print(f"Decrypt time:    {dec_time:.6f} sec")

    return {
        "algorithm": name,
        "encrypt_time": enc_time,
        "decrypt_time": dec_time,
        "status": success,
    }


def main():
    print("=== Running Symmetric Cipher Benchmark ===")

    results = [test_algorithm("AES-GCM", encrypt_aes_gcm, decrypt_aes_gcm),
               test_algorithm("DES", encrypt_des, decrypt_des), test_algorithm("3DES", encrypt_3des, decrypt_3des),
               test_algorithm("Blowfish", encrypt_blowfish, decrypt_blowfish),
               test_algorithm("Twofish", encrypt_twofish, decrypt_twofish),
               test_algorithm("RC4", rc4_encrypt, rc4_decrypt),
               test_algorithm("ChaCha20", chacha20_encrypt, chacha20_decrypt),
               test_algorithm("Serpent", encrypt_serpent, decrypt_serpent),
               test_algorithm("CAST-128", encrypt_cast128, decrypt_cast128),
               test_algorithm("Camellia", encrypt_camellia, decrypt_camellia)]

    print("\n=== SUMMARY ===")
    for r in results:
        print(
            f"{r['algorithm']:<12} | "
            f"Enc: {r['encrypt_time']:.6f}s | "
            f"Dec: {r['decrypt_time']:.6f}s | "
            f"{'OK' if r['status'] else 'FAIL'}"
        )


if __name__ == "__main__":
    main()
