import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

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

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def write(self, path: str, data: dict, token: str) -> dict:
        self._authorize(path, token)

        dek = self.vault.get_dek()
        plaintext = json.dumps(data).encode("utf-8")
        nonce = os.urandom(NONCE_SIZE)
        ct_and_tag = AESGCM(dek).encrypt(nonce, plaintext, associated_data=None)
        ciphertext, tag = ct_and_tag[:-GCM_TAG_SIZE], ct_and_tag[-GCM_TAG_SIZE:]

        records = self._load_all()
        now = datetime.now(timezone.utc).isoformat()
        created_at = records.get(path, {}).get("created_at", now)  # keep original created_at on overwrite

        records[path] = {
            "path": path,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "tag_b64": base64.b64encode(tag).decode("ascii"),
            "created_at": created_at,
            "updated_at": now,
        }
        self._save_all(records)
        return {"created_at": created_at, "updated_at": now}

    def read(self, path: str, token: str) -> dict:
        self._authorize(path, token)

        record = self._load_all().get(path)
        if record is None:
            raise NotFoundError("NOT_FOUND")

        dek = self.vault.get_dek()
        nonce = base64.b64decode(record["nonce_b64"])
        ciphertext = base64.b64decode(record["ciphertext_b64"])
        tag = base64.b64decode(record["tag_b64"])

        try:
            plaintext = AESGCM(dek).decrypt(nonce, ciphertext + tag, associated_data=None)
        except InvalidTag:
            # Tampered ciphertext/tag on disk. Refuse outright - never
            # return partial/garbage data (Acceptance Criteria 1.1).
            raise IntegrityError("Data integrity check failed, refusing to decrypt")

        return json.loads(plaintext.decode("utf-8"))

    def delete(self, path: str, token: str) -> dict:
        self._authorize(path, token)

        records = self._load_all()
        if path not in records:
            raise NotFoundError("NOT_FOUND")

        del records[path]
        self._save_all(records)
        return {"deleted": True, "path": path}
