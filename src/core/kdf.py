import os

from argon2.low_level import Type, hash_secret_raw

# Argon2id cost parameters (reasonable defaults for a single-user local vault)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4

SALT_SIZE = 16   # bytes
KEY_LENGTH = 32  # 32 bytes = 256-bit key, required for AES-256-GCM

DEFAULT_KDF = "argon2id"


def generate_salt(size: int = SALT_SIZE) -> bytes:
    """Generate a new random salt. Call this ONCE, at vault init time only."""
    return os.urandom(size)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from passphrase + salt using Argon2id."""
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=Type.ID,
    )