from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

# Defaults are argon2-cffi's own recommended parameters, adequate for
# hashing user login passphrases (as opposed to the DEK KDF in kdf.py, which
# uses stronger deliberately-slow parameters since it's used far less often).
_ph = PasswordHasher()


def hash_password(passphrase: str) -> str:
    """Return an argon2id hash string (salt + params embedded) to store."""
    return _ph.hash(passphrase)


def verify_password(password_hash: str, passphrase: str) -> bool:
    """True if passphrase matches password_hash, False otherwise.
    Never raises - callers should treat any mismatch/corruption as False."""
    try:
        _ph.verify(password_hash, passphrase)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False
