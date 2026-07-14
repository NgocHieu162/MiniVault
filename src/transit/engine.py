import base64
import json
import os
from typing import Any, Dict, List, Optional

from src.auth.exceptions import VaultLockedError
from src.auth.vault import VaultManager

from .exceptions import (
    InvalidKeyUsageException,
    KeyAlreadyExistsError,
    KeyNotFoundError,
    KeyRevokedError,
    PermissionDeniedError,
)
from .models import KeyRecord, SigningKeyRecord


class TransitEngine:
    """The core engine responsible for cryptographic operations on named keys.
    
    This includes creating/listing/revoking keys, encrypting/decrypting data,
    and signing/verifying messages.
    """

    def __init__(self, vault_manager: VaultManager, storage_path: str = "data/transit_keys.json"):
        self.vault_manager = vault_manager
        self.storage_path = storage_path

    def _load_storage(self) -> Dict[str, Any]:
        """Loads the raw metadata dictionary from the storage file."""
        if not os.path.exists(self.storage_path):
            return {"keys": {}, "signing_keys": {}}
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"keys": {}, "signing_keys": {}}

    def _save_storage(self, data: Dict[str, Any]) -> None:
        """Saves the metadata dictionary atomically to the storage file."""
        directory = os.path.dirname(self.storage_path) or "."
        os.makedirs(directory, exist_ok=True)
        tmp_path = self.storage_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, self.storage_path)

    # --- Feature 2.1: Named Key Management ---

    def create_key(self, key_name: str, owner_email: str) -> None:
        """Generates a new AES-256 key, encrypts it with the Vault DEK, and stores it.
        
        Args:
            key_name: The unique identifier for the key.
            owner_email: The email of the user creating and owning the key.
            
        Raises:
            VaultLockedError: If the vault is locked.
            KeyAlreadyExistsError: If a key with this name already exists.
        """
        # Ensure vault is unlocked (calling get_dek will raise VaultLockedError if locked)
        _ = self.vault_manager.get_dek()

        # TODO: Implement key generation (AES-256), encryption with DEK,
        # storage update, and saving to disk.
        raise NotImplementedError("create_key is not implemented yet")

    def list_keys(self, owner_email: str) -> List[Dict[str, Any]]:
        """Lists metadata of all keys owned by the specified email.
        
        Args:
            owner_email: The email of the key owner.
            
        Returns:
            A list of dictionaries containing key metadata (strictly NO plaintext key material).
        """
        # TODO: Filter and return key metadata.
        raise NotImplementedError("list_keys is not implemented yet")

    def revoke_key(self, key_name: str, owner_email: str) -> None:
        """Revokes a key, making it unusable for further cryptographic operations.
        
        Args:
            key_name: The name of the key to revoke.
            owner_email: The email of the caller (must match the key owner).
            
        Raises:
            KeyNotFoundError: If the key does not exist.
            PermissionDeniedError: If the caller is not the owner of the key.
        """
        # TODO: Mark the key as revoked in storage.
        raise NotImplementedError("revoke_key is not implemented yet")

    # --- Feature 2.2: Encrypt/Decrypt as a Service ---

    def encrypt(self, key_name: str, plaintext: bytes, owner_email: str) -> str:
        """Encrypts plaintext bytes using the named symmetric key.
        
        Args:
            key_name: The name of the key to encrypt with.
            plaintext: The raw bytes to encrypt.
            owner_email: The email of the caller (must match the key owner).
            
        Returns:
            A ciphertext string formatted as 'vault:<key_name>:<base64_payload>'
            
        Raises:
            VaultLockedError: If the vault is locked.
            KeyNotFoundError: If the key does not exist.
            KeyRevokedError: If the key is revoked.
            PermissionDeniedError: If the caller is not the owner (Access Control).
        """
        # Ensure vault is unlocked
        _ = self.vault_manager.get_dek()

        # TODO: Retrieve key, decrypt key with DEK, encrypt plaintext with AESGCM,
        # and format/return the final ciphertext string.
        raise NotImplementedError("encrypt is not implemented yet")

    def decrypt(self, key_name: str, ciphertext: str, owner_email: str) -> bytes:
        """Decrypts a 'vault' formatted ciphertext string using the named symmetric key.
        
        Args:
            key_name: The name of the key to decrypt with.
            ciphertext: The ciphertext string.
            owner_email: The email of the caller (must match the key owner).
            
        Returns:
            The decrypted plaintext bytes.
            
        Raises:
            VaultLockedError: If the vault is locked.
            KeyNotFoundError: If the key does not exist.
            KeyRevokedError: If the key is revoked.
            PermissionDeniedError: If the caller is not the owner.
            InvalidTag: If decryption fails (corrupted data or tag mismatch).
        """
        # Ensure vault is unlocked
        _ = self.vault_manager.get_dek()

        # TODO: Parse ciphertext, retrieve key, decrypt key with DEK,
        # decrypt ciphertext with AESGCM, and return plaintext.
        raise NotImplementedError("decrypt is not implemented yet")

    # --- Feature 2.4: Sign & Verify as a Service ---

    def create_signing_key(self, key_name: str, owner_email: str, algorithm: str = "Ed25519") -> None:
        """Generates an asymmetric key pair, encrypts the private key with DEK, and stores both.
        
        Args:
            key_name: The unique identifier for the signing key.
            owner_email: The email of the user creating and owning the key.
            algorithm: The asymmetric algorithm, either 'RSA-2048' or 'Ed25519'.
            
        Raises:
            VaultLockedError: If the vault is locked.
            KeyAlreadyExistsError: If a key with this name already exists.
            ValueError: If the requested algorithm is unsupported.
        """
        # Ensure vault is unlocked
        _ = self.vault_manager.get_dek()

        if algorithm not in ("RSA-2048", "Ed25519"):
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        # TODO: Generate asymmetric key pair, encrypt private key with DEK,
        # export public key in PEM format, and save to storage.
        raise NotImplementedError("create_signing_key is not implemented yet")

    def sign(self, key_name: str, message: bytes, owner_email: str) -> bytes:
        """Signs a message using the private key of the named asymmetric key.
        
        Args:
            key_name: The name of the signing key.
            message: The message bytes to sign.
            owner_email: The email of the caller (must match the key owner).
            
        Returns:
            The raw signature bytes.
            
        Raises:
            VaultLockedError: If the vault is locked.
            KeyNotFoundError: If the key does not exist.
            KeyRevokedError: If the key is revoked.
            PermissionDeniedError: If the caller is not the owner.
        """
        # Ensure vault is unlocked
        _ = self.vault_manager.get_dek()

        # TODO: Retrieve signing key, decrypt private key with DEK,
        # perform sign operation using the appropriate algorithm, and return signature.
        raise NotImplementedError("sign is not implemented yet")

    def verify(self, key_name: str, message: bytes, signature: bytes, owner_email: str) -> bool:
        """Verifies a signature against a message using the public key of the named asymmetric key.
        
        Args:
            key_name: The name of the signing key.
            message: The message bytes.
            signature: The signature bytes to verify.
            owner_email: The email of the caller (must match the key owner).
            
        Returns:
            True if the signature is valid, False otherwise (safely handles verification failures).
            
        Raises:
            KeyNotFoundError: If the key does not exist.
            PermissionDeniedError: If the caller is not the owner.
        """
        # Note: Verification does NOT require the vault to be unlocked since
        # public keys are stored in plaintext.
        
        # TODO: Retrieve signing key, load public key from PEM,
        # perform verification, return True/False without throwing crash exceptions.
        raise NotImplementedError("verify is not implemented yet")
