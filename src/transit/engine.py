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
    def __init__(self, vault_manager: VaultManager, storage_path: str = "data/transit_keys.json"):
        self.vault_manager = vault_manager
        self.storage_path = storage_path

    def _load_storage(self) -> Dict[str, Any]:
        if not os.path.exists(self.storage_path):
            return {"keys": {}, "signing_keys": {}}
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"keys": {}, "signing_keys": {}}

    def _save_storage(self, data: Dict[str, Any]) -> None:
        directory = os.path.dirname(self.storage_path) or "."
        os.makedirs(directory, exist_ok=True)
        tmp_path = self.storage_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, self.storage_path)

    def _get_key_record(self, key_name: str) -> KeyRecord:
        data = self._load_storage()
        if key_name not in data["keys"]:
            raise KeyNotFoundError(f"Key '{key_name}' not found")
        return KeyRecord.from_dict(data["keys"][key_name])

    def _assert_owner(self, record_email: str, caller_email: str) -> None:
        if record_email != caller_email:
            raise PermissionDeniedError(
                f"Access denied: caller '{caller_email}' is not the owner of this key"
            )

    def _encrypt_bytes_with_dek(self, plaintext: bytes) -> str:
        dek = self.vault_manager.get_dek()
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, associated_data=None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def _decrypt_bytes_with_dek(self, encrypted_b64: str) -> bytes:
        dek = self.vault_manager.get_dek()
        raw = base64.b64decode(encrypted_b64)
        nonce, ciphertext = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
        return AESGCM(dek).decrypt(nonce, ciphertext, associated_data=None)

    def create_key(self, key_name: str, owner_email: str) -> None:
        # Ensure vault is unlocked
        _ = self.vault_manager.get_dek()
        
        data = self._load_storage()
        if key_name in data["keys"]:
            raise KeyAlreadyExistsError(f"Key '{key_name}' already exists")

        aes_key = AESGCM.generate_key(bit_length=256)
        encrypted_key_b64 = self._encrypt_bytes_with_dek(aes_key)

        record = KeyRecord(
            key_name=key_name,
            owner_email=owner_email,
            encrypted_key_b64=encrypted_key_b64,
        )
        data["keys"][key_name] = record.to_dict()
        self._save_storage(data)

    def list_keys(self, owner_email: str) -> List[Dict[str, Any]]:
        data = self._load_storage()
        result = []
        for raw in data["keys"].values():
            if raw["owner_email"] == owner_email:
                result.append({
                    "key_name": raw["key_name"],
                    "owner_email": raw["owner_email"],
                    "created_at": raw["created_at"],
                    "is_revoked": raw["is_revoked"],
                })
        return result

    def revoke_key(self, key_name: str, owner_email: str) -> None:
        data = self._load_storage()
        record = self._get_key_record(key_name)
        data["keys"][key_name]["is_revoked"] = True
        self._save_storage(data)

    def encrypt(self, key_name: str, plaintext: bytes, owner_email: str) -> str:
        record = self._get_key_record(key_name)
        named_key = self._decrypt_bytes_with_dek(record.encrypted_key_b64)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(named_key).encrypt(nonce, plaintext, associated_data=None)
        payload = base64.b64encode(nonce + ciphertext).decode("ascii")
        return f"vault:{key_name}:{payload}"

    def decrypt(self, key_name: str, ciphertext: str, owner_email: str) -> bytes:
        record = self._get_key_record(key_name)
        parts = ciphertext.split(":")
        if len(parts) != 3 or parts[0] != "vault" or parts[1] != key_name:
            raise ValueError(f"Invalid ciphertext format. Expected 'vault:{key_name}:<base64>'")
        payload = base64.b64decode(parts[2])
        nonce, ct = payload[:NONCE_SIZE], payload[NONCE_SIZE:]
        named_key = self._decrypt_bytes_with_dek(record.encrypted_key_b64)
        return AESGCM(named_key).decrypt(nonce, ct, associated_data=None)

    def create_signing_key(self, key_name: str, owner_email: str, algorithm: str = "Ed25519") -> None:
        raise NotImplementedError("create_signing_key is not implemented yet")

    def sign(self, key_name: str, message: bytes, owner_email: str) -> bytes:
        raise NotImplementedError("sign is not implemented yet")

    def verify(self, key_name: str, message: bytes, signature: bytes, owner_email: str) -> bool:
        raise NotImplementedError("verify is not implemented yet")
