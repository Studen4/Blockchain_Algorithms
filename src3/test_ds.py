from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

m = 2**65 + 12345
print(f"Original number: {m}")

key = RSA.generate(1024)
pub = key.publickey()

m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
h = SHA256.new(m_bytes)
signature = pkcs1_15.new(key).sign(h)
print(f"Signature (bytes): {signature.hex()}")

try:
    pkcs1_15.new(pub).verify(h, signature)
    verified = True
except (ValueError, TypeError):
    verified = False

print(f"Verified: {verified}")
