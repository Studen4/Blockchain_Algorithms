# Serpent algorithm tests realization
BLOCK_SIZE = 16


def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def simple_round(block: bytes, key: bytes, r: int) -> bytes:
    return bytes(
        (b ^ key[i % len(key)] ^ (r * 13 % 256) ^ 0x5A)
        for i, b in enumerate(block)
    )


def encrypt_serpent(data: bytes) -> bytes:
    key = b"test_key_123456"
    data = pad(data)

    encrypted = []
    blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

    for block in blocks:
        state = block
        for r in range(32):
            state = simple_round(state, key, r)
        encrypted.append(state)

    return b"".join(encrypted)


def decrypt_serpent(data: bytes) -> bytes:
    key = b"test_key_123456"

    decrypted = []
    blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

    for block in blocks:
        state = block
        for r in reversed(range(32)):
            state = simple_round(state, key, r)
        decrypted.append(state)

    return unpad(b"".join(decrypted))
