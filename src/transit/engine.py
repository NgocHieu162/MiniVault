import base64
import json
import os
from typing import Any, Dict, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.vault import VaultManager

from .exceptions import (
    InvalidKeyUsageError,
    KeyAlreadyExistsError,
    KeyNotFoundError,
    KeyRevokedError,
    PermissionDeniedError,
)
from .models import KeyRecord, SigningKeyRecord

NONCE_SIZE = 12  # 96-bit nonce, standard size for AES-GCM


class TransitEngine:
    """The core engine responsible for cryptographic operations on named keys.

    This includes creating/listing/revoking keys, encrypting/decrypting data,
    and signing/verifying messages.
    """

    def __init__(self, vault_manager: VaultManager, storage_path: str = "data/transit_keys.json"):
        self.vault_manager = vault_manager
        self.storage_path = storage_path

    # --- Internal Helpers ---

    def _load_storage(self) -> Dict[str, Any]:
        """Loads the raw metadata dictionary from the storage file."""
        if not os.path.exists(self.storage_path):
            return {"keys": {}, "signing_keys": {}}
        with open(self.storage_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_storage(self, data: Dict[str, Any]) -> None:
        """Saves the metadata dictionary atomically to the storage file."""
        directory = os.path.dirname(self.storage_path) or "."
        os.makedirs(directory, exist_ok=True)
        tmp_path = self.storage_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, self.storage_path)

    def _get_key_record(self, key_name: str) -> KeyRecord:
        """Retrieves a KeyRecord from storage, raising KeyNotFoundError if missing."""
        data = self._load_storage()
        if key_name not in data["keys"]:
            raise KeyNotFoundError(f"Key '{key_name}' not found")
        return KeyRecord.from_dict(data["keys"][key_name])

    def _get_signing_key_record(self, key_name: str) -> SigningKeyRecord:
        """Retrieves a SigningKeyRecord from storage, raising KeyNotFoundError if missing."""
        data = self._load_storage()
        if key_name not in data["signing_keys"]:
            raise KeyNotFoundError(f"Signing key '{key_name}' not found")
        return SigningKeyRecord.from_dict(data["signing_keys"][key_name])

    def _assert_owner(self, record_email: str, caller_email: str) -> None:
        """Raises PermissionDeniedError if the caller is not the key owner."""
        if record_email != caller_email:
            raise PermissionDeniedError(
                f"Access denied: caller '{caller_email}' is not the owner of this key"
            )

    def _encrypt_bytes_with_dek(self, plaintext: bytes) -> str:
        """Encrypts raw bytes using the Vault DEK and returns a base64-encoded string (nonce + ciphertext)."""
        dek = self.vault_manager.get_dek()
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, associated_data=None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def _decrypt_bytes_with_dek(self, encrypted_b64: str) -> bytes:
        """Decrypts a base64-encoded DEK-encrypted blob and returns the original plaintext bytes."""
        dek = self.vault_manager.get_dek()
        raw = base64.b64decode(encrypted_b64)
        nonce, ciphertext = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
        return AESGCM(dek).decrypt(nonce, ciphertext, associated_data=None)

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
        data = self._load_storage()
        if key_name in data["keys"]:
            raise KeyAlreadyExistsError(f"Key '{key_name}' already exists")

        # Generate AES-256 key (version 1) and protect it with the master DEK
        aes_key = AESGCM.generate_key(bit_length=256)
        encrypted_key_b64 = self._encrypt_bytes_with_dek(aes_key)

        record = KeyRecord(
            key_name=key_name,
            owner_email=owner_email,
            keys_by_version={"1": encrypted_key_b64},
            latest_version=1,
        )
        data["keys"][key_name] = record.to_dict()
        self._save_storage(data)

    def list_keys(self, owner_email: str) -> List[Dict[str, Any]]:
        """Lists metadata of all active keys owned by the specified email.

        Args:
            owner_email: The email of the key owner.

        Returns:
            A list of dicts containing key metadata (NO plaintext key material is ever included).
        """
        data = self._load_storage()
        result = []
        for raw in data["keys"].values():
            if raw["owner_email"] == owner_email:
                # Never expose encrypted or plaintext key material
                result.append({
                    "key_name": raw["key_name"],
                    "owner_email": raw["owner_email"],
                    "created_at": raw["created_at"],
                    "is_revoked": raw["is_revoked"],
                })
        return result

    def revoke_key(self, key_name: str, owner_email: str) -> None:
        """Revokes a key, making it permanently unusable for further operations.

        Args:
            key_name: The name of the key to revoke.
            owner_email: The email of the caller (must match the key owner).

        Raises:
            KeyNotFoundError: If the key does not exist.
            PermissionDeniedError: If the caller is not the owner.
        """
        data = self._load_storage()
        record = self._get_key_record(key_name)
        self._assert_owner(record.owner_email, owner_email)

        data["keys"][key_name]["is_revoked"] = True
        self._save_storage(data)

    def rotate_key(self, key_name: str, owner_email: str) -> int:
        """Rotates a named key by generating a new key version.

        The old key versions are retained so existing ciphertexts can still be decrypted.
        All subsequent encrypt() calls will use the new latest version.

        Args:
            key_name: The name of the key to rotate.
            owner_email: The email of the caller (must match the key owner).

        Returns:
            The new latest version number (integer).

        Raises:
            VaultLockedError: If the vault is locked.
            KeyNotFoundError: If the key does not exist.
            KeyRevokedError: If the key has already been revoked.
            PermissionDeniedError: If the caller is not the owner.
        """
        # Ensure vault is unlocked before generating a new key version
        _ = self.vault_manager.get_dek()

        data = self._load_storage()
        record = self._get_key_record(key_name)
        self._assert_owner(record.owner_email, owner_email)
        if record.is_revoked:
            raise KeyRevokedError(f"Key '{key_name}' has been revoked and cannot be rotated")

        # Generate a brand-new AES-256 key for the next version
        new_aes_key = AESGCM.generate_key(bit_length=256)
        new_encrypted_b64 = self._encrypt_bytes_with_dek(new_aes_key)
        new_version = record.latest_version + 1

        data["keys"][key_name]["keys_by_version"][str(new_version)] = new_encrypted_b64
        data["keys"][key_name]["latest_version"] = new_version
        self._save_storage(data)
        return new_version

    # --- Feature 2.2: Encrypt/Decrypt as a Service ---

    def encrypt(self, key_name: str, plaintext: bytes, owner_email: str) -> str:
        """Encrypts plaintext bytes using the named symmetric key.

        Args:
            key_name: The name of the key to encrypt with.
            plaintext: The raw bytes to encrypt.
            owner_email: The email of the caller (must match the key owner).

        Returns:
            A ciphertext string formatted as 'vault:<key_name>:<base64(nonce + ciphertext)>'.

        Raises:
            VaultLockedError: If the vault is locked.
            KeyNotFoundError: If the key does not exist.
            KeyRevokedError: If the key has been revoked.
            PermissionDeniedError: If the caller is not the owner.
        """
        record = self._get_key_record(key_name)
        self._assert_owner(record.owner_email, owner_email)
        if record.is_revoked:
            raise KeyRevokedError(f"Key '{key_name}' has been revoked")

        # Always encrypt with the latest key version
        version = str(record.latest_version)
        if version not in record.keys_by_version:
            raise KeyNotFoundError(f"Key version '{version}' not found for key '{key_name}'")

        # Decrypt the named AES key using the master DEK
        named_key = self._decrypt_bytes_with_dek(record.keys_by_version[version])

        # Encrypt the plaintext with a fresh nonce using the named AES key
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(named_key).encrypt(nonce, plaintext, associated_data=None)
        payload = base64.b64encode(nonce + ciphertext).decode("ascii")
        # Include the version in the ciphertext tag: vault:<key_name>:<version>:<payload>
        return f"vault:{key_name}:{version}:{payload}"

    def decrypt(self, key_name: str, ciphertext: str, owner_email: str) -> bytes:
        """Decrypts a 'vault' formatted ciphertext string using the named symmetric key.

        Args:
            key_name: The name of the key to decrypt with.
            ciphertext: The ciphertext string in 'vault:<key_name>:<base64>' format.
            owner_email: The email of the caller (must match the key owner).

        Returns:
            The decrypted plaintext bytes.

        Raises:
            VaultLockedError: If the vault is locked.
            KeyNotFoundError: If the key does not exist.
            KeyRevokedError: If the key has been revoked.
            PermissionDeniedError: If the caller is not the owner.
            InvalidTag: If decryption fails due to corrupted data or wrong key.
            ValueError: If the ciphertext format is invalid.
        """
        record = self._get_key_record(key_name)
        self._assert_owner(record.owner_email, owner_email)
        if record.is_revoked:
            raise KeyRevokedError(f"Key '{key_name}' has been revoked")

        # Parse the vault ciphertext format.
        # Supports both old format: vault:<key_name>:<payload>
        # and new versioned format:  vault:<key_name>:<version>:<payload>
        parts = ciphertext.split(":")
        if len(parts) == 3 and parts[0] == "vault" and parts[1] == key_name:
            # Old format (version 1 assumed for backward compatibility)
            version = "1"
            payload_b64 = parts[2]
        elif len(parts) == 4 and parts[0] == "vault" and parts[1] == key_name:
            # New versioned format
            version = parts[2]
            payload_b64 = parts[3]
        else:
            raise ValueError(
                f"Invalid ciphertext format. Expected 'vault:{key_name}:<version>:<base64>'"
            )

        if version not in record.keys_by_version:
            raise KeyNotFoundError(
                f"Key version '{version}' not found for key '{key_name}'. "
                f"Available versions: {list(record.keys_by_version.keys())}"
            )

        payload = base64.b64decode(payload_b64)
        nonce, ct = payload[:NONCE_SIZE], payload[NONCE_SIZE:]

        # Decrypt the specific version of the named AES key using the master DEK
        named_key = self._decrypt_bytes_with_dek(record.keys_by_version[version])
        return AESGCM(named_key).decrypt(nonce, ct, associated_data=None)

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
        if algorithm not in ("RSA-2048", "Ed25519"):
            raise ValueError(f"Unsupported algorithm: '{algorithm}'. Use 'RSA-2048' or 'Ed25519'")

        data = self._load_storage()
        if key_name in data["signing_keys"]:
            raise KeyAlreadyExistsError(f"Signing key '{key_name}' already exists")

        if algorithm == "Ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        else:  # RSA-2048
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

        # Store public key in plaintext PEM format for public verification
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

        # Encrypt the private key with the master DEK before storing
        encrypted_private_key_b64 = self._encrypt_bytes_with_dek(private_bytes)

        record = SigningKeyRecord(
            key_name=key_name,
            owner_email=owner_email,
            algorithm=algorithm,
            encrypted_private_key_b64=encrypted_private_key_b64,
            public_key_pem=public_key_pem,
        )
        data["signing_keys"][key_name] = record.to_dict()
        self._save_storage(data)

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
            KeyRevokedError: If the key has been revoked.
            PermissionDeniedError: If the caller is not the owner.
        """
        record = self._get_signing_key_record(key_name)
        self._assert_owner(record.owner_email, owner_email)
        if record.is_revoked:
            raise KeyRevokedError(f"Signing key '{key_name}' has been revoked")

        # Decrypt the private key using the master DEK
        private_bytes = self._decrypt_bytes_with_dek(record.encrypted_private_key_b64)

        if record.algorithm == "Ed25519":
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            return private_key.sign(message)
        elif record.algorithm == "RSA-2048":
            private_key = serialization.load_pem_private_key(private_bytes, password=None)
            return private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            raise InvalidKeyUsageError(f"Unsupported algorithm for sign: '{record.algorithm}'")

    def verify(self, key_name: str, message: bytes, signature: bytes, owner_email: str) -> bool:
        """Verifies a signature against a message using the public key of the named asymmetric key.

        Args:
            key_name: The name of the signing key.
            message: The message bytes that were originally signed.
            signature: The signature bytes to verify.
            owner_email: The email of the caller (must match the key owner).

        Returns:
            True if the signature is valid, False otherwise.
            Never raises exceptions due to signature mismatch — only returns False.

        Raises:
            KeyNotFoundError: If the key does not exist.
            PermissionDeniedError: If the caller is not the owner.
        """
        record = self._get_signing_key_record(key_name)
        self._assert_owner(record.owner_email, owner_email)
        # Note: verify uses only the public key (plaintext PEM), so the vault does NOT need to be unlocked.

        public_key = serialization.load_pem_public_key(record.public_key_pem.encode("ascii"))

        try:
            if record.algorithm == "Ed25519":
                public_key.verify(signature, message)
            elif record.algorithm == "RSA-2048":
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            else:
                raise InvalidKeyUsageError(f"Unsupported algorithm for verify: '{record.algorithm}'")
            return True
        except (InvalidSignature, Exception):
            return False
