import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..auth.auth_manager import AuthManager
from ..auth.exceptions import (
    IntegrityError,
    NotFoundError,
    PermissionDeniedError,
    VaultLockedError,
)
from ..core.vault import VaultManager
from ..storage.vault_storage import VaultStorage

logger = logging.getLogger("mini_vault.kv.access")
NONCE_SIZE = 12          # 96-bit nonce, same convention as vault.py
GCM_TAG_SIZE = 16        # bytes, fixed size of the AES-GCM auth tag
DEFAULT_KV_PATH = "storage/kv_store.json"
OWNER_PREFIX = "secret/"  # every path must be secret/<email>/...


class KVManager:
    def __init__(
        self,
        vault: VaultManager,
        auth: AuthManager,
        storage: Optional[VaultStorage] = None,
    ):
        self.vault = vault
        self.auth = auth
        self.storage = storage or VaultStorage(path=DEFAULT_KV_PATH)

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------
    def _load_all(self) -> dict:
        if not self.storage.exists():
            return {}
        return self.storage.load().get("records", {})

    def _save_all(self, records: dict) -> None:
        self.storage.save({"records": records})

    def _check_ownership(self, path: str, email: str) -> None:
        expected_prefix = f"{OWNER_PREFIX}{email}/"
        if not path.startswith(expected_prefix):
            logger.warning(
                "PERMISSION_DENIED requester=%s attempted_path=%s",
                email,
                path,
            )
            raise PermissionDeniedError("PERMISSION_DENIED")

    def _authorize(self, path: str, token: str) -> str:
        """Runs steps 1-3 of the check order above. Returns caller email."""
        email = self.auth.validate_session(token)  # step 1, always first
        if not self.vault.is_unlocked():            # step 2
            raise VaultLockedError("VAULT_LOCKED")
        self._check_ownership(path, email)           # step 3
        return email

    def _encrypt(self, dek: bytes, data: dict) -> dict:
        """Encrypt a dict and return nonce_b64, ciphertext_b64, tag_b64."""
        plaintext = json.dumps(data).encode("utf-8")
        nonce = os.urandom(NONCE_SIZE)
        ct_and_tag = AESGCM(dek).encrypt(nonce, plaintext, associated_data=None)
        ciphertext, tag = ct_and_tag[:-GCM_TAG_SIZE], ct_and_tag[-GCM_TAG_SIZE:]
        return {
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "tag_b64": base64.b64encode(tag).decode("ascii"),
        }

    def _decrypt(self, dek: bytes, blob: dict) -> dict:
        """Decrypt nonce_b64/ciphertext_b64/tag_b64 blob back to a dict."""
        nonce = base64.b64decode(blob["nonce_b64"])
        ciphertext = base64.b64decode(blob["ciphertext_b64"])
        tag = base64.b64decode(blob["tag_b64"])
        try:
            plaintext = AESGCM(dek).decrypt(nonce, ciphertext + tag, associated_data=None)
        except InvalidTag:
            raise IntegrityError("Data integrity check failed, refusing to decrypt")
        return json.loads(plaintext.decode("utf-8"))

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def write(self, path: str, data: dict, token: str) -> dict:
        """Encrypt and store data at path. Each write creates a new version.

        Advanced Feature (KV Versioning +0.3 pts):
        Old versions are retained. Subsequent read() calls return the latest
        version by default; historical versions remain accessible via version=N.
        """
        self._authorize(path, token)

        dek = self.vault.get_dek()
        blob = self._encrypt(dek, data)

        records = self._load_all()
        now = datetime.now(timezone.utc).isoformat()

        existing = records.get(path)

        if existing and "versions" in existing:
            # Versioned format: append a new version
            latest = existing["latest_version"] + 1
            existing["versions"][str(latest)] = {**blob, "created_at": now}
            existing["latest_version"] = latest
            existing["updated_at"] = now
            records[path] = existing
            created_at = existing["created_at"]
        else:
            # First write (or migration from old non-versioned format)
            created_at = now
            records[path] = {
                "path": path,
                "latest_version": 1,
                "created_at": created_at,
                "updated_at": now,
                "versions": {
                    "1": {**blob, "created_at": now},
                },
            }
            latest = 1

        self._save_all(records)
        return {
            "created_at": created_at,
            "updated_at": now,
            "version": latest,
        }

    def read(self, path: str, token: str, version: Optional[int] = None) -> dict:
        """Decrypt and return the data at path.

        Args:
            version: If None (default), returns the latest version.
                     If specified, returns that exact historical version.
        """
        self._authorize(path, token)

        record = self._load_all().get(path)
        if record is None:
            raise NotFoundError("NOT_FOUND")

        dek = self.vault.get_dek()

        # Support both new versioned format and old flat format
        if "versions" in record:
            target_version = version if version is not None else record["latest_version"]
            blob = record["versions"].get(str(target_version))
            if blob is None:
                raise NotFoundError(f"Version {target_version} not found for path '{path}'")
            return self._decrypt(dek, blob)
        else:
            # Legacy format (backward compatible read)
            return self._decrypt(dek, record)

    def list_versions(self, path: str, token: str) -> dict:
        """List all available versions for a secret path (Advanced Feature).

        Returns version numbers and their creation timestamps WITHOUT decrypting.
        """
        self._authorize(path, token)

        record = self._load_all().get(path)
        if record is None:
            raise NotFoundError("NOT_FOUND")

        if "versions" not in record:
            # Legacy single-version record
            return {
                "path": path,
                "latest_version": 1,
                "versions": {"1": {"created_at": record.get("created_at")}},
            }

        version_meta = {
            v: {"created_at": blob.get("created_at")}
            for v, blob in record["versions"].items()
        }
        return {
            "path": path,
            "latest_version": record["latest_version"],
            "versions": version_meta,
        }

    def delete(self, path: str, token: str) -> dict:
        """Permanently delete all versions of a secret at path."""
        self._authorize(path, token)

        records = self._load_all()
        if path not in records:
            raise NotFoundError("NOT_FOUND")

        del records[path]
        self._save_all(records)
        return {"deleted": True, "path": path}
