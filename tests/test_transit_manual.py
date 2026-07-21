"""
Manual integration test script for the TransitEngine.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.vault import VaultManager
from src.storage.vault_storage import VaultStorage
from src.transit.engine import TransitEngine
from src.transit.exceptions import (
    KeyAlreadyExistsError,
    KeyRevokedError,
    PermissionDeniedError,
)

def run_tests():
    storage = VaultStorage(path="data/test_vault_meta.json")
    vault = VaultManager(storage)
    transit = TransitEngine(vault, storage_path="data/test_transit_keys.json")
    PASSPHRASE = "correct horse battery staple"
    OWNER = "member_b@example.com"

    if not vault.is_initialized():
        vault.init_vault(PASSPHRASE)
    vault.unlock(PASSPHRASE)

    print("=" * 60)
    print("TRANSIT ENGINE - UNIT TESTS")
    print("=" * 60)

    # --- Feature 2.1: Named Key Management ---
    print("\n[2.1] Named Key Management")

    transit.create_key("my-key", OWNER)
    print("  [OK] create_key: created 'my-key'")

    try:
        transit.create_key("my-key", OWNER)
    except KeyAlreadyExistsError as e:
        print(f"  [OK] create_key (duplicate): {e}")

    keys = transit.list_keys(OWNER)
    assert len(keys) == 1
    assert "encrypted_key_b64" not in keys[0], "list_keys must NOT expose key material!"
    print(f"  [OK] list_keys: {keys[0]['key_name']} (is_revoked={keys[0]['is_revoked']})")

    # --- Feature 2.2: Encrypt / Decrypt ---
    print("\n[2.2] Encrypt / Decrypt as a Service")

    plaintext = b"Hello, MiniVault!"
    ciphertext = transit.encrypt("my-key", plaintext, OWNER)
    assert ciphertext.startswith("vault:my-key:")
    print(f"  [OK] encrypt: {ciphertext[:50]}...")

    recovered = transit.decrypt("my-key", ciphertext, OWNER)
    assert recovered == plaintext
    print(f"  [OK] decrypt: '{recovered.decode()}'")

    # --- Feature 2.3: Access Control ---
    print("\n[2.3] Access Control")

    OTHER = "attacker@example.com"
    try:
        transit.encrypt("my-key", b"unauthorized attempt", OTHER)
    except PermissionDeniedError as e:
        print(f"  [OK] encrypt (wrong owner): {e}")

    try:
        transit.decrypt("my-key", ciphertext, OTHER)
    except PermissionDeniedError as e:
        print(f"  [OK] decrypt (wrong owner): {e}")

    # --- Revoke key and verify it blocks operations ---
    transit.revoke_key("my-key", OWNER)
    keys = transit.list_keys(OWNER)
    assert keys[0]["is_revoked"] is True
    print(f"  [OK] revoke_key: 'my-key' is_revoked=True")

    try:
        transit.encrypt("my-key", b"after revoke", OWNER)
    except KeyRevokedError as e:
        print(f"  [OK] encrypt after revoke: {e}")

if __name__ == "__main__":
    import shutil
    for f in ["data/test_vault_meta.json", "data/test_transit_keys.json"]:
        if os.path.exists(f):
            os.remove(f)
    run_tests()
