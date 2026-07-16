"""
Manual integration test script for the TransitEngine.
Run from project root with: .\\venv\\Scripts\\python.exe tests\\test_transit_manual.py
"""
import os


from src.core.vault import VaultManager
from src.storage.vault_storage import VaultStorage
from src.transit.engine import TransitEngine
from src.transit.exceptions import (
    KeyAlreadyExistsError,
    KeyRevokedError,
    PermissionDeniedError,
)


def run_tests():
    # --- Setup ---
    storage = VaultStorage(path="data/test_vault_meta.json")
    vault = VaultManager(storage)
    transit = TransitEngine(vault, storage_path="data/test_transit_keys.json")
    PASSPHRASE = "correct horse battery staple"
    OWNER = "member_b@example.com"
    OTHER = "attacker@example.com"

    if not vault.is_initialized():
        vault.init_vault(PASSPHRASE)
    vault.unlock(PASSPHRASE)

    print("=" * 60)
    print("TRANSIT ENGINE - INTEGRATION TESTS")
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

    # --- Feature 2.4: Sign & Verify (Ed25519) ---
    print("\n[2.4] Sign & Verify (Ed25519)")

    transit.create_signing_key("sig-key-ed25519", OWNER, algorithm="Ed25519")
    print("  [OK] create_signing_key: 'sig-key-ed25519'")

    message = b"Transfer $100 to Alice"
    signature = transit.sign("sig-key-ed25519", message, OWNER)
    print(f"  [OK] sign: {len(signature)} bytes")

    result = transit.verify("sig-key-ed25519", message, signature, OWNER)
    assert result is True
    print(f"  [OK] verify (valid signature): {result}")

    result_tampered = transit.verify("sig-key-ed25519", b"Transfer $999 to Eve", signature, OWNER)
    assert result_tampered is False
    print(f"  [OK] verify (tampered message): {result_tampered} (correctly rejected)")

    # --- Feature 2.4: Sign & Verify (RSA-2048) ---
    print("\n[2.4] Sign & Verify (RSA-2048)")

    transit.create_signing_key("sig-key-rsa", OWNER, algorithm="RSA-2048")
    print("  [OK] create_signing_key: 'sig-key-rsa'")

    signature_rsa = transit.sign("sig-key-rsa", message, OWNER)
    print(f"  [OK] sign: {len(signature_rsa)} bytes")

    result_rsa = transit.verify("sig-key-rsa", message, signature_rsa, OWNER)
    assert result_rsa is True
    print(f"  [OK] verify (valid signature): {result_rsa}")

    result_rsa_bad = transit.verify("sig-key-rsa", b"wrong message", signature_rsa, OWNER)
    assert result_rsa_bad is False
    print(f"  [OK] verify (tampered message): {result_rsa_bad} (correctly rejected)")

    # --- Advanced Feature: Key Rotation ---
    print("\n[ADVANCED] Key Rotation")

    transit.create_key("rotate-key", OWNER)
    print("  [OK] create_key: 'rotate-key' created at version 1")

    # Encrypt plaintext with version 1
    plaintext_v1 = b"Secret encrypted by key version 1"
    cipher_v1 = transit.encrypt("rotate-key", plaintext_v1, OWNER)
    assert ":1:" in cipher_v1, "Ciphertext must contain version number ':1:'"
    print(f"  [OK] encrypt with v1: {cipher_v1[:55]}...")

    # Rotate the key -> version 2
    new_ver = transit.rotate_key("rotate-key", OWNER)
    assert new_ver == 2
    print(f"  [OK] rotate_key: now at version {new_ver}")

    # Encrypt new plaintext with version 2
    plaintext_v2 = b"Secret encrypted by key version 2"
    cipher_v2 = transit.encrypt("rotate-key", plaintext_v2, OWNER)
    assert ":2:" in cipher_v2, "Ciphertext must contain version number ':2:'"
    print(f"  [OK] encrypt with v2: {cipher_v2[:55]}...")

    # Decrypt ciphertext v1 using old key version (MUST still work)
    recovered_v1 = transit.decrypt("rotate-key", cipher_v1, OWNER)
    assert recovered_v1 == plaintext_v1
    print(f"  [OK] decrypt v1 ciphertext (backward compat): '{recovered_v1.decode()}'")

    # Decrypt ciphertext v2 using new key version
    recovered_v2 = transit.decrypt("rotate-key", cipher_v2, OWNER)
    assert recovered_v2 == plaintext_v2
    print(f"  [OK] decrypt v2 ciphertext: '{recovered_v2.decode()}'")

    # Rotate again -> version 3
    ver3 = transit.rotate_key("rotate-key", OWNER)
    assert ver3 == 3
    print(f"  [OK] rotate_key again: now at version {ver3}")

    # Both old ciphertexts (v1 and v2) must still decrypt correctly
    assert transit.decrypt("rotate-key", cipher_v1, OWNER) == plaintext_v1
    assert transit.decrypt("rotate-key", cipher_v2, OWNER) == plaintext_v2
    print(f"  [OK] all old ciphertexts still decrypt after v3 rotation")

    # New encryption uses version 3
    cipher_v3 = transit.encrypt("rotate-key", b"New data at v3", OWNER)
    assert ":3:" in cipher_v3
    print(f"  [OK] new encryption uses latest version 3")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED [OK]")
    print("=" * 60)


if __name__ == "__main__":
    import shutil
    # Clean up test artifacts before running
    for f in ["data/test_vault_meta.json", "data/test_transit_keys.json"]:
        if os.path.exists(f):
            os.remove(f)
    run_tests()
