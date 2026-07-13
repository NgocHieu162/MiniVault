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
