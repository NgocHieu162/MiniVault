class VaultError(Exception):
    """Base class for all vault-related errors."""


class VaultLockedError(VaultError):
    """Raised when a KV/Transit operation is attempted while the vault is locked."""


class InvalidPassphraseError(VaultError):
    """Raised when the master passphrase fails to decrypt the DEK.
    Message must stay generic - never reveal internal decryption details."""


class VaultAlreadyInitializedError(VaultError):
    """Raised when init_vault() is called but vault metadata already exists on disk."""


class VaultNotInitializedError(VaultError):
    """Raised when unlock() is called before the vault has ever been initialized."""

# ---------------------------------------------------------------------------
# Feature 0.2 — User Identity Authentication
# ---------------------------------------------------------------------------

class AuthError(VaultError):
    """Base class for all authentication/session related errors."""


class EmailAlreadyExistsError(AuthError):
    """Raised at register() when the email is already taken."""


class PassphraseMismatchError(AuthError):
    """Raised at register() when passphrase != confirm_passphrase."""


class WeakPassphraseError(AuthError):
    """Raised at register() when the passphrase does not meet the minimum
    strength policy (see passphrase_policy.py)."""


class AccountNotFoundError(AuthError):
    """Raised at login() when no user exists for the given email."""


class InvalidCredentialsError(AuthError):
    """Raised at login() when the passphrase does not match the stored hash.
    Kept generic on purpose - never reveals *why* the login failed."""


class AccountLockedError(AuthError):
    """Raised at login() when the account is inside its 5-failed-attempt
    lockout window - including when the CORRECT passphrase is supplied
    while locked (Acceptance Criteria, section 0.2)."""

    def __init__(self, remaining_seconds: float):
        self.remaining_seconds = max(0, int(remaining_seconds))
        super().__init__(
            f"Account temporarily locked. Try again in {self.remaining_seconds}s."
        )


class UnauthenticatedError(AuthError):
    """Raised by validate_session() when the token is missing, unknown, or
    expired. Every Feature 1 / Feature 2 endpoint must raise this BEFORE any
    permission or path check is evaluated (see Acceptance Criteria 1.2)."""
