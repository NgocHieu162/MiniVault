import base64
import json

import pytest

from src.auth.auth_manager import AuthManager
from src.auth.exceptions import (
    IntegrityError,
    NotFoundError,
    PermissionDeniedError,
    UnauthenticatedError,
    VaultLockedError,
)
from src.auth.session_store import SessionStore
from src.auth.user_store import UserStore
from src.core.vault import VaultManager
from src.kv.kv_manager import KVManager
from src.storage.vault_storage import VaultStorage

MASTER_PASSPHRASE = "correct-horse-battery-9"
ALICE_EMAIL = "alice@example.com"
BOB_EMAIL = "bob@example.com"
USER_PASSPHRASE = "hunter2pass"


@pytest.fixture
def env(tmp_path):
    """Boots a real, unlocked vault + two registered/logged-in users
    (alice, bob), all backed by real files under tmp_path."""
    vault = VaultManager(storage=VaultStorage(path=str(tmp_path / "vault.json")))
    vault.init_vault(MASTER_PASSPHRASE)
    vault.unlock(MASTER_PASSPHRASE)

    user_store = UserStore(storage=VaultStorage(path=str(tmp_path / "users.json")))
    auth = AuthManager(user_store=user_store, session_store=SessionStore())

    for email in (ALICE_EMAIL, BOB_EMAIL):
        auth.register(email, USER_PASSPHRASE, USER_PASSPHRASE)

    alice_token = auth.login(ALICE_EMAIL, USER_PASSPHRASE)
    bob_token = auth.login(BOB_EMAIL, USER_PASSPHRASE)

    kv_storage_path = tmp_path / "kv.json"
    kv = KVManager(vault=vault, auth=auth, storage=VaultStorage(path=str(kv_storage_path)))

    return {
        "vault": vault,
        "auth": auth,
        "kv": kv,
        "kv_storage_path": kv_storage_path,
        "alice_token": alice_token,
        "bob_token": bob_token,
    }


# ---------------------------------------------------------------------------
# 1.1 — Encrypted-at-rest
# ---------------------------------------------------------------------------
class TestEncryptedAtRest:
    def test_write_then_read_round_trip(self, env):
        """Checklist #2."""
        kv = env["kv"]
        path = f"secret/{ALICE_EMAIL}/db"
        payload = {"username": "root", "password": "p@ssw0rd"}

        kv.write(path, payload, env["alice_token"])
        assert kv.read(path, env["alice_token"]) == payload

    @pytest.mark.parametrize(
        "payload",
        [
            {"note": "plain text value"},
            {"nested": {"a": 1, "b": [1, 2, 3]}, "flag": True, "n": None},
            {"binary_b64": base64.b64encode(b"\x00\x01\xff\xfe\x10").decode()},
        ],
        ids=["text", "nested_json", "binary_as_base64"],
    )
    def test_round_trip_multiple_data_types(self, env, payload):
        kv = env["kv"]
        path = f"secret/{ALICE_EMAIL}/item"
        kv.write(path, payload, env["alice_token"])
        assert kv.read(path, env["alice_token"]) == payload

    def test_no_plaintext_leaked_on_disk(self, env):
        kv = env["kv"]
        path = f"secret/{ALICE_EMAIL}/db"
        secret_value = "sUp3rSecretPassword"
        kv.write(path, {"password": secret_value}, env["alice_token"])

        raw_file_content = env["kv_storage_path"].read_text(encoding="utf-8")
        assert secret_value not in raw_file_content

    def test_write_overwrites_same_path_no_history(self, env):
        kv = env["kv"]
        path = f"secret/{ALICE_EMAIL}/db"
        kv.write(path, {"v": 1}, env["alice_token"])
        kv.write(path, {"v": 2}, env["alice_token"])
        assert kv.read(path, env["alice_token"]) == {"v": 2}

    def test_tampered_ciphertext_on_disk_read_refuses(self, env):
        """Checklist #3."""
        kv = env["kv"]
        path = f"secret/{ALICE_EMAIL}/db"
        kv.write(path, {"password": "hunter2"}, env["alice_token"])

        _flip_field_on_disk(env["kv_storage_path"], path, "ciphertext_b64")

        with pytest.raises(IntegrityError):
            kv.read(path, env["alice_token"])

    def test_tampered_tag_on_disk_read_refuses(self, env):
        """Checklist #3 (tag variant)."""
        kv = env["kv"]
        path = f"secret/{ALICE_EMAIL}/db"
        kv.write(path, {"password": "hunter2"}, env["alice_token"])

        _flip_field_on_disk(env["kv_storage_path"], path, "tag_b64")

        with pytest.raises(IntegrityError):
            kv.read(path, env["alice_token"])

    def test_read_nonexistent_path_raises_not_found(self, env):
        with pytest.raises(NotFoundError):
            env["kv"].read(f"secret/{ALICE_EMAIL}/nope", env["alice_token"])

    def test_delete_then_read_raises_not_found(self, env):
        kv = env["kv"]
        path = f"secret/{ALICE_EMAIL}/db"
        kv.write(path, {"v": 1}, env["alice_token"])
        kv.delete(path, env["alice_token"])

        with pytest.raises(NotFoundError):
            kv.read(path, env["alice_token"])

    def test_write_while_vault_locked_raises_vault_locked(self, env):
        env["vault"].lock()
        with pytest.raises(VaultLockedError):
            env["kv"].write(f"secret/{ALICE_EMAIL}/db", {"v": 1}, env["alice_token"])


# ---------------------------------------------------------------------------
# 1.2 — Ownership-based access control
# ---------------------------------------------------------------------------
class TestAccessControl:
    def test_user_cannot_read_other_users_secret(self, env):
        """Checklist #4."""
        kv = env["kv"]
        bob_path = f"secret/{BOB_EMAIL}/db"
        kv.write(bob_path, {"password": "bobs-secret"}, env["bob_token"])

        for _ in range(5):
            with pytest.raises(PermissionDeniedError):
                kv.read(bob_path, env["alice_token"])

    def test_user_cannot_write_into_other_users_namespace(self, env):
        with pytest.raises(PermissionDeniedError):
            env["kv"].write(f"secret/{BOB_EMAIL}/injected", {"v": 1}, env["alice_token"])

    def test_user_cannot_delete_other_users_secret(self, env):
        kv = env["kv"]
        bob_path = f"secret/{BOB_EMAIL}/db"
        kv.write(bob_path, {"v": 1}, env["bob_token"])

        with pytest.raises(PermissionDeniedError):
            kv.delete(bob_path, env["alice_token"])

        assert kv.read(bob_path, env["bob_token"]) == {"v": 1}

    def test_denied_access_does_not_reveal_whether_path_exists(self, env):
        kv = env["kv"]
        kv.write(f"secret/{BOB_EMAIL}/real-secret", {"v": 1}, env["bob_token"])

        with pytest.raises(PermissionDeniedError):
            kv.read(f"secret/{BOB_EMAIL}/real-secret", env["alice_token"])

        with pytest.raises(PermissionDeniedError):
            kv.read(f"secret/{BOB_EMAIL}/totally-made-up", env["alice_token"])

    def test_denied_access_is_logged(self, env, caplog):
        kv = env["kv"]
        bob_path = f"secret/{BOB_EMAIL}/db"
        kv.write(bob_path, {"v": 1}, env["bob_token"])

        with caplog.at_level("WARNING", logger="mini_vault.kv.access"):
            with pytest.raises(PermissionDeniedError):
                kv.read(bob_path, env["alice_token"])

        assert any(
            ALICE_EMAIL in r.getMessage() and bob_path in r.getMessage()
            for r in caplog.records
        )

    def test_missing_or_invalid_token_blocked_before_path_check(self, env):
        """Checklist #5: must raise UnauthenticatedError (not
        PermissionDeniedError) even on a path that would ALSO fail the
        ownership check - proving auth runs first."""
        bogus_path = f"secret/{BOB_EMAIL}/db"

        with pytest.raises(UnauthenticatedError):
            env["kv"].read(bogus_path, token=None)

        with pytest.raises(UnauthenticatedError):
            env["kv"].read(bogus_path, token="not-a-real-session-token")

    def test_expired_token_is_rejected(self, env, tmp_path):
        """Real SessionStore, real TTL expiry - not a fake."""
        fake_clock = {"now": 0.0}
        session_store = SessionStore(clock=lambda: fake_clock["now"], ttl_seconds=1)
        user_store = UserStore(storage=VaultStorage(path=str(tmp_path / "users2.json")))
        auth = AuthManager(
            user_store=user_store, session_store=session_store, clock=lambda: fake_clock["now"]
        )
        auth.register(ALICE_EMAIL, USER_PASSPHRASE, USER_PASSPHRASE)
        token = auth.login(ALICE_EMAIL, USER_PASSPHRASE)

        kv = KVManager(vault=env["vault"], auth=auth, storage=env["kv"].storage)
        kv.write(f"secret/{ALICE_EMAIL}/db", {"v": 1}, token)  # still valid

        fake_clock["now"] += 2  # advance past the 1-second TTL

        with pytest.raises(UnauthenticatedError):
            kv.read(f"secret/{ALICE_EMAIL}/db", token)

    def test_path_without_secret_prefix_is_denied(self, env):
        with pytest.raises(PermissionDeniedError):
            env["kv"].read("not-even-a-secret-path", env["alice_token"])


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _flip_field_on_disk(kv_storage_path, path: str, field: str) -> None:
    """Simulates 'manually altering 1 byte on disk' (checklist #3) by
    reading the real JSON file, flipping one bit in the given b64 field,
    and writing it back - exactly what an attacker with disk access would
    have to do."""
    raw = json.loads(kv_storage_path.read_text(encoding="utf-8"))
    record = raw["records"][path]

    corrupted = bytearray(base64.b64decode(record[field]))
    corrupted[0] ^= 0xFF
    record[field] = base64.b64encode(bytes(corrupted)).decode("ascii")

    kv_storage_path.write_text(json.dumps(raw), encoding="utf-8")
