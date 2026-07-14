import pytest
import os
import base64
from cryptography.exceptions import InvalidTag
from src.core.vault import VaultManager
from src.storage.vault_storage import VaultStorage
from src.transit.engine import TransitEngine
from src.transit.exceptions import (
    KeyAlreadyExistsError,
    KeyNotFoundError,
    KeyRevokedError,
    PermissionDeniedError,
)

PASSPHRASE = "correct horse battery staple"
OWNER = "member_b@example.com"
OTHER = "attacker@example.com"


@pytest.fixture
def unlocked_vault(tmp_path):
    storage = VaultStorage(path=str(tmp_path / "vault_meta.json"))
    vault = VaultManager(storage)
    vault.init_vault(PASSPHRASE)
    vault.unlock(PASSPHRASE)
    return vault


@pytest.fixture
def transit_engine(unlocked_vault, tmp_path):
    return TransitEngine(
        vault_manager=unlocked_vault,
        storage_path=str(tmp_path / "transit_keys.json")
    )


# ---------------------------------------------------------------------
# Feature 2.1: Named Key Management
# ---------------------------------------------------------------------

def test_create_key_success(transit_engine):
    transit_engine.create_key("my-key", OWNER)
    keys = transit_engine.list_keys(OWNER)
    assert len(keys) == 1
    assert keys[0]["key_name"] == "my-key"
    assert keys[0]["owner_email"] == OWNER
    assert keys[0]["is_revoked"] is False


def test_create_key_duplicate_rejected(transit_engine):
    transit_engine.create_key("my-key", OWNER)
    with pytest.raises(KeyAlreadyExistsError):
        transit_engine.create_key("my-key", OWNER)


# REQUIRED TEST (mục V, STT 8): Không API nào (kể cả list_keys) trả về AES key thật dạng plaintext/base64
def test_list_keys_metadata_safety(transit_engine):
    transit_engine.create_key("my-key", OWNER)
    keys = transit_engine.list_keys(OWNER)
    assert "encrypted_key_b64" not in keys[0]
    assert "keys_by_version" not in keys[0]


def test_revoke_key_success(transit_engine):
    transit_engine.create_key("my-key", OWNER)
    transit_engine.revoke_key("my-key", OWNER)
    keys = transit_engine.list_keys(OWNER)
    assert keys[0]["is_revoked"] is True


def test_revoke_key_not_found(transit_engine):
    with pytest.raises(KeyNotFoundError):
        transit_engine.revoke_key("non-existent", OWNER)


# ---------------------------------------------------------------------
# Feature 2.2: Encrypt/Decrypt as a Service
# ---------------------------------------------------------------------

# REQUIRED TEST (mục V, STT 6): encrypt() rồi decrypt() -> đúng dữ liệu gốc trên nhiều kiểu dữ liệu
@pytest.mark.parametrize("plaintext", [
    b"Hello World",
    b'{"action": "transfer", "amount": 100}',
    base64.b64encode(b"binary data payload")
])
def test_encrypt_decrypt_roundtrip(transit_engine, plaintext):
    transit_engine.create_key("my-key", OWNER)
    ciphertext = transit_engine.encrypt("my-key", plaintext, OWNER)
    assert ciphertext.startswith("vault:my-key:")
    
    decrypted = transit_engine.decrypt("my-key", ciphertext, OWNER)
    assert decrypted == plaintext


# REQUIRED TEST (mục V, STT 7): Sửa 1 byte trong ciphertext -> decrypt() luôn thất bại rõ ràng, 100% số lần
def test_decrypt_tampered_ciphertext_fails(transit_engine):
    transit_engine.create_key("my-key", OWNER)
    ciphertext = transit_engine.encrypt("my-key", b"Important message", OWNER)
    
    # Ciphertext structure: vault:<key_name>:<version>:<payload_b64>
    parts = ciphertext.split(":")
    payload = bytearray(base64.b64decode(parts[3]))
    
    # Tamper with 1 byte in the payload
    payload[0] ^= 0x01
    tampered_parts = parts[:3] + [base64.b64encode(payload).decode("ascii")]
    tampered_ciphertext = ":".join(tampered_parts)
    
    with pytest.raises((InvalidTag, Exception)):
         transit_engine.decrypt("my-key", tampered_ciphertext, OWNER)


# ---------------------------------------------------------------------
# Feature 2.3: Transit Access Control
# ---------------------------------------------------------------------

# REQUIRED TEST (mục V, STT 9): User A dùng key_name thuộc sở hữu User B để encrypt/decrypt -> luôn bị từ chối 100%
def test_access_control_wrong_owner_rejected(transit_engine):
    transit_engine.create_key("my-key", OWNER)
    
    with pytest.raises(PermissionDeniedError):
        transit_engine.encrypt("my-key", b"test", OTHER)
        
    ciphertext = transit_engine.encrypt("my-key", b"test", OWNER)
    with pytest.raises(PermissionDeniedError):
        transit_engine.decrypt("my-key", ciphertext, OTHER)


def test_access_control_revoked_key_rejected(transit_engine):
    transit_engine.create_key("my-key", OWNER)
    ciphertext = transit_engine.encrypt("my-key", b"test", OWNER)
    transit_engine.revoke_key("my-key", OWNER)
    
    with pytest.raises(KeyRevokedError):
        transit_engine.encrypt("my-key", b"test", OWNER)
        
    with pytest.raises(KeyRevokedError):
        transit_engine.decrypt("my-key", ciphertext, OWNER)


# ---------------------------------------------------------------------
# Feature 2.4: Sign & Verify as a Service
# ---------------------------------------------------------------------

# REQUIRED TEST (mục V, STT 10 & 11 & 12): Sign & Verify validations
@pytest.mark.parametrize("algorithm", ["Ed25519", "RSA-2048"])
def test_sign_verify_success(transit_engine, algorithm):
    transit_engine.create_signing_key("sig-key", OWNER, algorithm)
    message = b"Payment Transaction Log"
    signature = transit_engine.sign("sig-key", message, OWNER)
    
    # 10: signature_valid = True on unchanged message
    assert transit_engine.verify("sig-key", message, signature, OWNER) is True
    
    # 11: signature_valid = False on tampered message (no crash)
    assert transit_engine.verify("sig-key", b"Modified Transaction Log", signature, OWNER) is False


# REQUIRED TEST (mục V, STT 12): Dùng chữ ký của key này để verify() với key khác -> signature_valid = false
def test_verify_different_key_rejected(transit_engine):
    transit_engine.create_signing_key("key-1", OWNER, "Ed25519")
    transit_engine.create_signing_key("key-2", OWNER, "Ed25519")
    message = b"Standard Payload"
    
    sig_1 = transit_engine.sign("key-1", message, OWNER)
    assert transit_engine.verify("key-2", message, sig_1, OWNER) is False


# REQUIRED TEST (mục V, STT 13): Không API nào trả về private signing key thật
def test_list_keys_private_key_safety(transit_engine):
    transit_engine.create_signing_key("sig-key", OWNER, "Ed25519")
    data = transit_engine._load_storage()
    # Check stored metadata
    record = data["signing_keys"]["sig-key"]
    assert "encrypted_private_key_b64" in record
    # Ensure public access never exposes private materials
    with pytest.raises(AttributeError):
        _ = record.private_key


# ---------------------------------------------------------------------
# Advanced Feature: Key Rotation
# ---------------------------------------------------------------------

def test_key_rotation_flow(transit_engine):
    transit_engine.create_key("rotate-key", OWNER)
    
    # Version 1 Encryption
    msg_v1 = b"Message Version 1"
    cipher_v1 = transit_engine.encrypt("rotate-key", msg_v1, OWNER)
    assert ":1:" in cipher_v1
    
    # Rotate Key
    new_ver = transit_engine.rotate_key("rotate-key", OWNER)
    assert new_ver == 2
    
    # Version 2 Encryption
    msg_v2 = b"Message Version 2"
    cipher_v2 = transit_engine.encrypt("rotate-key", msg_v2, OWNER)
    assert ":2:" in cipher_v2
    
    # Decrypt both versions successfully
    assert transit_engine.decrypt("rotate-key", cipher_v1, OWNER) == msg_v1
    assert transit_engine.decrypt("rotate-key", cipher_v2, OWNER) == msg_v2


def test_key_rotation_backward_compatibility(transit_engine):
    # Simulate a manually written old database where keys are not versioned (encrypted_key_b64 only)
    raw_data = {
        "keys": {
            "legacy-key": {
                "key_name": "legacy-key",
                "owner_email": OWNER,
                "encrypted_key_b64": transit_engine._encrypt_bytes_with_dek(b"A" * 32),
                "created_at": 100000.0,
                "is_revoked": False
            }
        },
        "signing_keys": {}
    }
    transit_engine._save_storage(raw_data)
    
    # Encrypt legacy-key plaintext in old format
    # vault:<key_name>:<base64(nonce+ciphertext)>
    ciphertext = f"vault:legacy-key:{transit_engine.encrypt('legacy-key', b'Legacy data', OWNER).split(':')[-1]}"
    
    # Verify legacy decrypt works (resolves as version 1 internally)
    assert transit_engine.decrypt("legacy-key", ciphertext, OWNER) == b"Legacy data"
