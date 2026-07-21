import json
import os

DEFAULT_PATH = os.path.join("storage", "vault.json")


class VaultStorage:
    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path

    def exists(self) -> bool:
        return os.path.isfile(self.path)

    def load(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save(self, data: dict) -> None:
        """Atomic write: write to a temp file then rename, so a crash
        mid-write never corrupts the existing vault metadata."""
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)

        tmp_path = self.path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, self.path)
