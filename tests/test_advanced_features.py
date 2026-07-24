"""
tests/test_advanced_features.py

Pytest suite for the 2 advanced (extra credit) features:
  1. KV Versioning — +0.3 pts
  2. Tamper-Evident Hash-Chained Audit Log — +0.3 pts

Note: Key Rotation (+0.4 pts) is tested in tests/test_transit.py.
Total Extra Credit: +1.0 pts (maximum allowed by spec).
"""

import json
import os
import tempfile
import time

import pytest

from src.auth.auth_manager import AuthManager
from src.auth.exceptions import NotFoundError
from src.auth.session_store import SessionStore
from src.auth.user_store import UserStore
from src.core.audit_logger import AuditLogger, _GENESIS_HASH
from src.core.vault import VaultManager
from src.kv.kv_manager import KVManager
from src.storage.vault_storage import VaultStorage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_path_str():
    with tempfile.TemporaryDirectory() as td:
        yield td


@pytest.fixture
def vault(tmp_path_str):
    v = VaultManager(storage=VaultStorage(path=os.path.join(tmp_path_str, "vault_meta.json")))
    v.init_vault("MasterPass1")
    v.unlock("MasterPass1")
    return v


@pytest.fixture
def auth(tmp_path_str):
    user_storage = VaultStorage(path=os.path.join(tmp_path_str, "users.json"))
    return AuthManager(
        user_store=UserStore(storage=user_storage),
        session_store=SessionStore(),
    )


@pytest.fixture
def kv(vault, auth, tmp_path_str):
    kv_storage = VaultStorage(path=os.path.join(tmp_path_str, "kv_store.json"))
    return KVManager(vault=vault, auth=auth, storage=kv_storage)


@pytest.fixture
def registered_user(auth):
    auth.register("alice@test.com", "AlicePass1", "AlicePass1")
    token = auth.login("alice@test.com", "AlicePass1")
    return {"email": "alice@test.com", "passphrase": "AlicePass1", "token": token}


@pytest.fixture
def audit_log(tmp_path_str):
    return AuditLogger(log_path=os.path.join(tmp_path_str, "audit.log"))


# ---------------------------------------------------------------------------
# Feature 1: KV Versioning Tests (+0.3 pts)
# ---------------------------------------------------------------------------

class TestKVVersioning:
    def test_first_write_creates_version_1(self, kv, registered_user):
        """First write must create version 1."""
        path = f"secret/{registered_user['email']}/config"
        result = kv.write(path, {"env": "prod"}, registered_user["token"])
        assert result["version"] == 1

    def test_second_write_creates_version_2(self, kv, registered_user):
        """Second write to the same path must increment to version 2."""
        path = f"secret/{registered_user['email']}/config"
        kv.write(path, {"env": "prod"}, registered_user["token"])
        result = kv.write(path, {"env": "staging"}, registered_user["token"])
        assert result["version"] == 2

    def test_read_latest_version_by_default(self, kv, registered_user):
        """read() without version must return the latest version data."""
        path = f"secret/{registered_user['email']}/config"
        kv.write(path, {"env": "prod"}, registered_user["token"])
        kv.write(path, {"env": "staging"}, registered_user["token"])
        data = kv.read(path, registered_user["token"])
        assert data == {"env": "staging"}

    def test_read_historical_version_1(self, kv, registered_user):
        """read(version=1) must return the original data even after 3 overwrites."""
        path = f"secret/{registered_user['email']}/config"
        kv.write(path, {"env": "prod"}, registered_user["token"])
        kv.write(path, {"env": "staging"}, registered_user["token"])
        kv.write(path, {"env": "dev"}, registered_user["token"])

        data_v1 = kv.read(path, registered_user["token"], version=1)
        assert data_v1 == {"env": "prod"}

    def test_read_specific_version_2(self, kv, registered_user):
        """read(version=2) must return the second write's data."""
        path = f"secret/{registered_user['email']}/config"
        kv.write(path, {"v": 1}, registered_user["token"])
        kv.write(path, {"v": 2}, registered_user["token"])
        kv.write(path, {"v": 3}, registered_user["token"])

        data = kv.read(path, registered_user["token"], version=2)
        assert data == {"v": 2}

    def test_read_nonexistent_version_raises_not_found(self, kv, registered_user):
        """read(version=99) must raise NotFoundError when that version doesn't exist."""
        path = f"secret/{registered_user['email']}/config"
        kv.write(path, {"v": 1}, registered_user["token"])
        with pytest.raises(NotFoundError):
            kv.read(path, registered_user["token"], version=99)

    def test_list_versions_returns_metadata(self, kv, registered_user):
        """list_versions() must return version numbers and timestamps without decrypting."""
        path = f"secret/{registered_user['email']}/config"
        kv.write(path, {"v": 1}, registered_user["token"])
        kv.write(path, {"v": 2}, registered_user["token"])

        result = kv.list_versions(path, registered_user["token"])
        assert result["latest_version"] == 2
        assert "1" in result["versions"]
        assert "2" in result["versions"]
        # Must NOT decrypt or return plaintext
        assert "v" not in str(result["versions"])

    def test_list_versions_no_decryption_of_data(self, kv, registered_user):
        """list_versions() must return ONLY created_at timestamps, not decrypted data."""
        path = f"secret/{registered_user['email']}/secret-key"
        kv.write(path, {"password": "super_secret_123"}, registered_user["token"])

        result = kv.list_versions(path, registered_user["token"])
        versions_str = json.dumps(result)
        assert "super_secret_123" not in versions_str
        assert "password" not in versions_str


# ---------------------------------------------------------------------------
# Feature 2: Tamper-Evident Hash-Chained Audit Log Tests (+0.3 pts)
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_log_creates_entries(self, audit_log):
        """log() must append entries with proper index and hash fields."""
        audit_log.log("ACCESS_DENIED: User 'attacker' tried key 'my-key'")
        entries = audit_log.get_entries()
        assert len(entries) == 1
        assert entries[0]["index"] == 0
        assert "hash" in entries[0]
        assert "prev_hash" in entries[0]
        assert entries[0]["prev_hash"] == _GENESIS_HASH

    def test_multiple_entries_form_chain(self, audit_log):
        """Each entry's prev_hash must match the previous entry's hash."""
        audit_log.log("Event A")
        audit_log.log("Event B")
        audit_log.log("Event C")

        entries = audit_log.get_entries()
        assert entries[1]["prev_hash"] == entries[0]["hash"]
        assert entries[2]["prev_hash"] == entries[1]["hash"]

    def test_verify_integrity_returns_intact_for_clean_log(self, audit_log):
        """verify_integrity() must return intact=True for an unmodified log."""
        audit_log.log("Legitimate access attempt")
        audit_log.log("Another event")
        result = audit_log.verify_integrity()
        assert result["intact"] is True
        assert result["tampered_at_index"] is None

    def test_verify_integrity_empty_log(self, audit_log):
        """verify_integrity() on an empty log must return intact=True."""
        result = audit_log.verify_integrity()
        assert result["intact"] is True
        assert result["total_entries"] == 0

    def test_verify_integrity_detects_event_tampering(self, audit_log):
        """verify_integrity() must detect if the 'event' field of an entry is changed."""
        audit_log.log("Event A")
        audit_log.log("Event B")
        audit_log.log("Event C")

        # Tamper: rewrite the file with Event B modified
        with open(audit_log.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        entry_b = json.loads(lines[1])
        entry_b["event"] = "TAMPERED EVENT"
        lines[1] = json.dumps(entry_b) + "\n"

        with open(audit_log.log_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = audit_log.verify_integrity()
        assert result["intact"] is False
        assert result["tampered_at_index"] == 1

    def test_verify_integrity_detects_hash_tampering(self, audit_log):
        """verify_integrity() must detect if the 'hash' field itself is altered."""
        audit_log.log("Event A")
        audit_log.log("Event B")

        with open(audit_log.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Replace the hash of entry 0 with garbage
        entry_0 = json.loads(lines[0])
        entry_0["hash"] = "a" * 64
        lines[0] = json.dumps(entry_0) + "\n"

        with open(audit_log.log_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = audit_log.verify_integrity()
        assert result["intact"] is False

    def test_verify_integrity_detects_line_deletion(self, audit_log):
        """verify_integrity() must detect if an entry is deleted from the log."""
        audit_log.log("Event A")
        audit_log.log("Event B")
        audit_log.log("Event C")

        with open(audit_log.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Delete line 0 (Event A)
        lines = lines[1:]

        with open(audit_log.log_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = audit_log.verify_integrity()
        assert result["intact"] is False

    def test_get_entries_with_limit(self, audit_log):
        """get_entries(limit=N) must return only the last N entries."""
        for i in range(10):
            audit_log.log(f"Event {i}")

        last_3 = audit_log.get_entries(limit=3)
        assert len(last_3) == 3
        assert last_3[-1]["event"] == "Event 9"

    def test_transit_denied_writes_to_audit_log(self, vault, auth, tmp_path_str):
        """TransitEngine._log_denied_attempt must write to the hash-chained audit log."""
        from src.transit.engine import TransitEngine
        from src.transit.exceptions import PermissionDeniedError

        engine = TransitEngine(vault_manager=vault)
        isolated_audit = AuditLogger(log_path=os.path.join(tmp_path_str, "audit.log"))

        auth.register("owner2@test.com", "Pass1234", "Pass1234")
        auth.register("attacker2@test.com", "Pass1234", "Pass1234")

        # Create key with dynamic name to ensure no collision on persistent storage
        key_name = f"test-audit-key-{int(time.time() * 1000)}"
        engine.create_key(key_name, "owner2@test.com")

        # Patch the module-level _audit logger to our isolated one
        import src.transit.engine as engine_mod
        original_audit = engine_mod._audit
        engine_mod._audit = isolated_audit

        try:
            with pytest.raises(PermissionDeniedError):
                engine.encrypt(key_name, b"secret", "attacker2@test.com")
        finally:
            engine_mod._audit = original_audit

        # Verify the isolated log received an entry
        entries = isolated_audit.get_entries()
        assert len(entries) >= 1
        assert "attacker2@test.com" in entries[-1]["event"]
        assert key_name in entries[-1]["event"]

        # Verify chain integrity
        result = isolated_audit.verify_integrity()
        assert result["intact"] is True
