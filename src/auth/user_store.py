from typing import Dict, Optional

from ..storage.vault_storage import VaultStorage

DEFAULT_USERS_PATH = "storage/users.json"


class UserStore:
    """Persists user records to a single JSON file.

    Reuses VaultStorage as-is (it's already a generic path -> JSON
    load/save with atomic write-then-rename, nothing vault-specific in its
    implementation) instead of duplicating that logic here.

    File layout on disk:
    {
      "users": {
        "alice@example.com": {
          "email": "alice@example.com",
          "password_hash": "<argon2 hash string>",
          "failed_attempts": 0,
          "locked_until": null,        # epoch seconds, or null
          "created_at": "2026-07-14T10:00:00+00:00"
        },
        ...
      }
    }
    """

    def __init__(self, storage: Optional[VaultStorage] = None):
        self.storage = storage or VaultStorage(path=DEFAULT_USERS_PATH)

    def _load_all(self) -> Dict[str, dict]:
        if not self.storage.exists():
            return {}
        return self.storage.load().get("users", {})

    def get(self, email: str) -> Optional[dict]:
        return self._load_all().get(email.strip().lower())

    def save(self, email: str, record: dict) -> None:
        users = self._load_all()
        users[email.strip().lower()] = record
        self.storage.save({"users": users})
