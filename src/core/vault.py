import base64
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..auth.exceptions import (
    InvalidPassphraseError,
    VaultAlreadyInitializedError,
    VaultLockedError,
    VaultNotInitializedError,
)
from .kdf import DEFAULT_KDF, derive_key, generate_salt
from ..storage.vault_storage import VaultStorage

NONCE_SIZE = 12  # 96-bit nonce, standard/recommended size for AES-GCM


class VaultManager:
    def __init__(self, storage: Optional[VaultStorage] = None):
        self.storage = storage or VaultStorage()
        self._dek: Optional[bytes] = None  # plaintext DEK lives in RAM only
        self._status: str = "locked"

    @property
    def status(self) -> str:
        return self._status

    def is_initialized(self) -> bool:
        return self.storage.exists()

    def init_vault(self, passphrase: str) -> None:
        """First run only. Fails if a vault already exists on disk."""
        if self.is_initialized():
            raise VaultAlreadyInitializedError("Vault already initialized")

        salt = generate_salt()
        derived_key = derive_key(passphrase, salt)

        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(derived_key).encrypt(nonce, dek, associated_data=None)

        # Store nonce prepended to ciphertext so unlock() can split them back out
        encrypted_dek = nonce + ciphertext

        self.storage.save(
            {
                "kdf": DEFAULT_KDF,
                "kdf_salt_b64": base64.b64encode(salt).decode("ascii"),
                "encrypted_dek_b64": base64.b64encode(encrypted_dek).decode("ascii"),
                "status": "locked",
            }
        )

        # Per acceptance criteria: after init, vault stays locked.
        # Caller must still call unlock() explicitly.
        self._dek = None
        self._status = "locked"

    def unlock(self, passphrase: str) -> None:
        """Re-derive the key from passphrase + stored salt, decrypt the DEK.
        Raises InvalidPassphraseError (generic) on any decryption failure."""
        if not self.is_initialized():
            raise VaultNotInitializedError("Vault has not been initialized yet")

        data = self.storage.load()
        salt = base64.b64decode(data["kdf_salt_b64"])
        encrypted_dek = base64.b64decode(data["encrypted_dek_b64"])
        nonce, ciphertext = encrypted_dek[:NONCE_SIZE], encrypted_dek[NONCE_SIZE:]

        derived_key = derive_key(passphrase, salt)

        try:
            dek = AESGCM(derived_key).decrypt(nonce, ciphertext, associated_data=None)
        except InvalidTag:
            # GCM tag mismatch == wrong passphrase. Never expose more detail than this.
            raise InvalidPassphraseError("Invalid master passphrase")

        self._dek = dek
        self._status = "unlocked"

    def lock(self) -> None:
        """Explicitly re-lock the vault and wipe the DEK from memory."""
        self._dek = None
        self._status = "locked"

    def get_dek(self) -> bytes:
        """Used internally by Feature 1 (KV) / Feature 2 (Transit) to get
        the plaintext DEK for their own encryption operations."""
        if self._status != "unlocked" or self._dek is None:
            raise VaultLockedError("VAULT_LOCKED")
        return self._dek
