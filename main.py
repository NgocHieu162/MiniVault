"""
MiniVault REST API — main.py
Run: .\\venv\\Scripts\\uvicorn main:app --reload
Docs: http://127.0.0.1:8000/docs
"""

from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.auth.auth_manager import AuthManager
from src.auth.exceptions import (
    AccountLockedError,
    AccountNotFoundError,
    EmailAlreadyExistsError,
    IntegrityError,
    InvalidCredentialsError,
    InvalidPassphraseError,
    NotFoundError,
    PassphraseMismatchError,
    PermissionDeniedError,
    UnauthenticatedError,
    VaultAlreadyInitializedError,
    VaultLockedError,
    VaultNotInitializedError,
    WeakPassphraseError,
)
from src.core.vault import VaultManager
from src.kv.kv_manager import KVManager
from src.transit.engine import TransitEngine
from src.transit.exceptions import (
    InvalidKeyUsageError,
    KeyAlreadyExistsError,
    KeyNotFoundError,
    KeyRevokedError,
    PermissionDeniedError as TransitPermissionDeniedError,
)

# ---------------------------------------------------------------------------
# Singleton services (shared across all requests in the process)
# ---------------------------------------------------------------------------

vault = VaultManager()
auth = AuthManager()
transit = TransitEngine(vault_manager=vault)
kv = KVManager(vault=vault, auth=auth)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield  # nothing to do on startup / shutdown


app = FastAPI(
    title="🔐 MiniVault",
    description=(
        "A lightweight cryptographic vault service.\n\n"
        "**How to use:**\n"
        "1. `POST /vault/init` — Initialize vault (first run only)\n"
        "2. `POST /vault/unlock` — Unlock with master passphrase\n"
        "3. `POST /auth/register` — Create an account\n"
        "4. `POST /auth/login` — Get session token\n"
        "5. Use `X-Token` header for all KV and Transit endpoints\n\n"
        "**Features:**\n"
        "- **Vault** — Master passphrase / DEK management (Feature 0)\n"
        "- **Auth** — Register, login, session tokens (Feature 0.2)\n"
        "- **KV Engine** — Encrypted secret storage at `secret/<email>/...` (Feature 1)\n"
        "- **Transit Engine** — Encrypt/Decrypt, Sign/Verify, Key Rotation (Feature 2)\n"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helper: convert known exceptions → HTTP errors
# ---------------------------------------------------------------------------

def _http(exc: Exception) -> HTTPException:
    mapping = {
        VaultNotInitializedError:      (424, "Vault not initialized — call POST /vault/init first"),
        VaultAlreadyInitializedError:  (409, "Vault already initialized"),
        InvalidPassphraseError:        (401, "Invalid master passphrase"),
        VaultLockedError:              (423, "Vault is locked — call POST /vault/unlock first"),
        EmailAlreadyExistsError:       (409, str(exc)),
        PassphraseMismatchError:       (400, str(exc)),
        WeakPassphraseError:           (400, str(exc)),
        AccountNotFoundError:          (401, "Invalid email or passphrase"),
        InvalidCredentialsError:       (401, "Invalid email or passphrase"),
        AccountLockedError:            (429, str(exc)),
        UnauthenticatedError:          (401, "Missing, invalid, or expired session token"),
        PermissionDeniedError:         (403, "PERMISSION_DENIED"),
        NotFoundError:                 (404, "NOT_FOUND"),
        IntegrityError:                (422, "Data integrity check failed — ciphertext may be tampered"),
        KeyAlreadyExistsError:         (409, str(exc)),
        KeyNotFoundError:              (404, str(exc)),
        KeyRevokedError:               (410, str(exc)),
        TransitPermissionDeniedError:  (403, str(exc)),
        InvalidKeyUsageError:          (400, str(exc)),
        ValueError:                    (400, str(exc)),
    }
    for exc_type, (code, detail) in mapping.items():
        if isinstance(exc, exc_type):
            return HTTPException(status_code=code, detail=detail)
    return HTTPException(status_code=500, detail=f"Internal error: {exc}")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class VaultPassphraseRequest(BaseModel):
    passphrase: str

class RegisterRequest(BaseModel):
    email: str
    passphrase: str
    confirm_passphrase: str

class LoginRequest(BaseModel):
    email: str
    passphrase: str

class KVWriteRequest(BaseModel):
    data: Dict[str, Any]

class CreateKeyRequest(BaseModel):
    key_name: str

class CreateSigningKeyRequest(BaseModel):
    key_name: str
    algorithm: str = "Ed25519"  # "Ed25519" | "RSA-2048"

class EncryptRequest(BaseModel):
    plaintext: str              # UTF-8 text to encrypt

class DecryptRequest(BaseModel):
    ciphertext: str             # "vault:<name>:<ver>:<b64>" string

class SignRequest(BaseModel):
    message: str                # UTF-8 message (or hex digest if message_type=DIGEST)
    message_type: str = "RAW"  # "RAW" | "DIGEST"

class VerifyRequest(BaseModel):
    message: str                # UTF-8 message (or hex digest if message_type=DIGEST)
    signature_hex: str          # hex-encoded signature bytes
    message_type: str = "RAW"


# ---------------------------------------------------------------------------
# Feature 0.1 — Vault Init & Unlock
# ---------------------------------------------------------------------------

@app.get("/vault/status", tags=["🔒 Vault"], summary="Get vault status")
def vault_status():
    """Check whether the vault is initialized and locked/unlocked."""
    return {
        "initialized": vault.is_initialized(),
        "status": vault.status,
    }


@app.post("/vault/init", tags=["🔒 Vault"], summary="Initialize vault (first run only)")
def vault_init(req: VaultPassphraseRequest):
    """Create the vault for the first time with a master passphrase.

    After init the vault remains **locked** — call `POST /vault/unlock` next.
    """
    try:
        vault.init_vault(req.passphrase)
        return {"message": "Vault initialized. Now call POST /vault/unlock to unlock."}
    except Exception as exc:
        raise _http(exc)


@app.post("/vault/unlock", tags=["🔒 Vault"], summary="Unlock vault with master passphrase")
def vault_unlock(req: VaultPassphraseRequest):
    """Derive the DEK from the master passphrase and hold it in memory.

    Must be called before any KV or Transit operations.
    """
    try:
        vault.unlock(req.passphrase)
        return {"message": "Vault unlocked."}
    except Exception as exc:
        raise _http(exc)


@app.post("/vault/lock", tags=["🔒 Vault"], summary="Lock vault and wipe DEK from memory")
def vault_lock():
    """Immediately wipe the in-memory DEK. All KV/Transit ops will fail until unlocked again."""
    vault.lock()
    return {"message": "Vault locked."}


# ---------------------------------------------------------------------------
# Feature 0.2 — Authentication
# ---------------------------------------------------------------------------

@app.post("/auth/register", tags=["👤 Auth"], summary="Register a new user account")
def auth_register(req: RegisterRequest):
    """Register with email + passphrase.

    Passphrase policy: **minimum 8 characters, at least 1 letter and 1 digit.**
    """
    try:
        auth.register(req.email, req.passphrase, req.confirm_passphrase)
        return {"message": f"Account '{req.email}' registered successfully."}
    except Exception as exc:
        raise _http(exc)


@app.post("/auth/login", tags=["👤 Auth"], summary="Login and receive a session token")
def auth_login(req: LoginRequest):
    """Returns a session **token** valid for 30 minutes.

    Pass it as the `X-Token` header on all KV and Transit endpoints.
    After 5 failed attempts the account is locked for 5 minutes.
    """
    try:
        token = auth.login(req.email, req.passphrase)
        return {"token": token, "email": req.email, "expires_in_seconds": 1800}
    except Exception as exc:
        raise _http(exc)


@app.post("/auth/logout", tags=["👤 Auth"], summary="Invalidate session token")
def auth_logout(x_token: str = Header(..., alias="X-Token")):
    """Invalidate the session token immediately."""
    try:
        auth.logout(x_token)
        return {"message": "Logged out."}
    except Exception as exc:
        raise _http(exc)


# ---------------------------------------------------------------------------
# Feature 1 — KV Engine (Secure Storage)
# ---------------------------------------------------------------------------

@app.post("/kv/{path:path}", tags=["📦 KV Engine"], summary="Write (or overwrite) a secret")
def kv_write(path: str, req: KVWriteRequest, x_token: str = Header(..., alias="X-Token")):
    """Encrypt and store a JSON object.

    **`path`** must start with `secret/<your-email>/`
    — e.g. `secret/alice@example.com/db/password`

    You only need to pass the part after `secret/` in the URL.
    """
    full_path = f"secret/{path}" if not path.startswith("secret/") else path
    try:
        meta = kv.write(full_path, req.data, x_token)
        return {"path": full_path, **meta}
    except Exception as exc:
        raise _http(exc)


@app.get("/kv/{path:path}", tags=["📦 KV Engine"], summary="Read and decrypt a secret")
def kv_read(path: str, x_token: str = Header(..., alias="X-Token")):
    """Decrypt and return the JSON object stored at the given path."""
    full_path = f"secret/{path}" if not path.startswith("secret/") else path
    try:
        data = kv.read(full_path, x_token)
        return {"path": full_path, "data": data}
    except Exception as exc:
        raise _http(exc)


@app.delete("/kv/{path:path}", tags=["📦 KV Engine"], summary="Delete a secret")
def kv_delete(path: str, x_token: str = Header(..., alias="X-Token")):
    """Permanently delete the secret at the given path."""
    full_path = f"secret/{path}" if not path.startswith("secret/") else path
    try:
        result = kv.delete(full_path, x_token)
        return result
    except Exception as exc:
        raise _http(exc)


# ---------------------------------------------------------------------------
# Feature 2.1 — Transit: Named Key Management
# ---------------------------------------------------------------------------

@app.get("/transit/keys", tags=["🔑 Transit — Keys"], summary="List all keys you own")
def transit_list_keys(x_token: str = Header(..., alias="X-Token")):
    """Returns metadata (name, key_usage, algorithm, is_revoked) for all keys owned by the caller.
    Does **not** include any plaintext or encrypted key material.
    """
    try:
        email = auth.validate_session(x_token)
        keys = transit.list_keys(email)
        return {"keys": keys, "count": len(keys)}
    except Exception as exc:
        raise _http(exc)


@app.post("/transit/keys", tags=["🔑 Transit — Keys"], summary="Create a symmetric AES-256 key")
def transit_create_key(req: CreateKeyRequest, x_token: str = Header(..., alias="X-Token")):
    """Create a named symmetric key (AES-256-GCM) for encryption/decryption (`key_usage: ENCRYPT_DECRYPT`)."""
    try:
        email = auth.validate_session(x_token)
        transit.create_key(req.key_name, email)
        return {"message": f"Key '{req.key_name}' created.", "key_usage": "ENCRYPT_DECRYPT"}
    except Exception as exc:
        raise _http(exc)


@app.post("/transit/signing-keys", tags=["🔑 Transit — Keys"], summary="Create an asymmetric signing key pair")
def transit_create_signing_key(req: CreateSigningKeyRequest, x_token: str = Header(..., alias="X-Token")):
    """Create a named asymmetric key pair (`key_usage: SIGN_VERIFY`).

    - **Ed25519** — faster, smaller signatures (64 bytes). *Default.*
    - **RSA-2048** — wider compatibility, larger signatures (256 bytes).
    """
    try:
        email = auth.validate_session(x_token)
        transit.create_signing_key(req.key_name, email, req.algorithm)
        return {
            "message": f"Signing key '{req.key_name}' created.",
            "algorithm": req.algorithm,
            "key_usage": "SIGN_VERIFY",
        }
    except Exception as exc:
        raise _http(exc)


@app.delete("/transit/keys/{key_name}", tags=["🔑 Transit — Keys"], summary="Revoke a key (symmetric or signing)")
def transit_revoke_key(key_name: str, x_token: str = Header(..., alias="X-Token")):
    """Permanently revoke a key. Works for both symmetric and signing keys.
    After revocation the key **cannot** be used for any operation.
    """
    try:
        email = auth.validate_session(x_token)
        transit.revoke_key(key_name, email)
        return {"message": f"Key '{key_name}' revoked."}
    except Exception as exc:
        raise _http(exc)


@app.post("/transit/keys/{key_name}/rotate", tags=["🔑 Transit — Keys"], summary="Rotate a symmetric key [Advanced]")
def transit_rotate_key(key_name: str, x_token: str = Header(..., alias="X-Token")):
    """Generate a **new key version** while keeping all older versions.

    Ciphertexts encrypted with previous versions remain decryptable (backward compatible).
    New encryptions automatically use the latest version.
    """
    try:
        email = auth.validate_session(x_token)
        new_version = transit.rotate_key(key_name, email)
        return {"message": f"Key '{key_name}' rotated.", "new_version": new_version}
    except Exception as exc:
        raise _http(exc)


# ---------------------------------------------------------------------------
# Feature 2.2 — Transit: Encrypt / Decrypt as a Service
# ---------------------------------------------------------------------------

@app.post("/transit/encrypt/{key_name}", tags=["🔐 Transit — Encrypt/Decrypt"], summary="Encrypt plaintext")
def transit_encrypt(key_name: str, req: EncryptRequest, x_token: str = Header(..., alias="X-Token")):
    """Encrypt a UTF-8 string using the named AES-256-GCM key.

    Returns a self-describing ciphertext:
    `vault:<key_name>:<version>:<base64(nonce+ciphertext)>`
    """
    try:
        email = auth.validate_session(x_token)
        ciphertext = transit.encrypt(key_name, req.plaintext.encode("utf-8"), email)
        return {"ciphertext": ciphertext}
    except Exception as exc:
        raise _http(exc)


@app.post("/transit/decrypt/{key_name}", tags=["🔐 Transit — Encrypt/Decrypt"], summary="Decrypt ciphertext")
def transit_decrypt(key_name: str, req: DecryptRequest, x_token: str = Header(..., alias="X-Token")):
    """Decrypt a `vault:...` ciphertext string. Returns the original UTF-8 plaintext."""
    try:
        email = auth.validate_session(x_token)
        plaintext_bytes = transit.decrypt(key_name, req.ciphertext, email)
        return {"plaintext": plaintext_bytes.decode("utf-8")}
    except Exception as exc:
        raise _http(exc)


# ---------------------------------------------------------------------------
# Feature 2.4 — Transit: Sign / Verify as a Service
# ---------------------------------------------------------------------------

@app.post("/transit/sign/{key_name}", tags=["✍️ Transit — Sign/Verify"], summary="Sign a message")
def transit_sign(key_name: str, req: SignRequest, x_token: str = Header(..., alias="X-Token")):
    """Sign a message using an asymmetric key (Ed25519 or RSA-2048).

    Returns the **hex-encoded** signature.

    - `message_type = "RAW"` — hash then sign (default)
    - `message_type = "DIGEST"` — `message` must be a **64-char hex string** (32-byte SHA-256 digest)
    """
    try:
        email = auth.validate_session(x_token)
        msg = bytes.fromhex(req.message) if req.message_type == "DIGEST" else req.message.encode("utf-8")
        sig = transit.sign(key_name, msg, email, message_type=req.message_type)
        return {"signature_hex": sig.hex()}
    except Exception as exc:
        raise _http(exc)


@app.post("/transit/verify/{key_name}", tags=["✍️ Transit — Sign/Verify"], summary="Verify a signature")
def transit_verify(key_name: str, req: VerifyRequest, x_token: str = Header(..., alias="X-Token")):
    """Verify a hex signature against a message.

    Returns `{"valid": true}` or `{"valid": false}`.
    Never raises an error on signature mismatch — only returns false.
    """
    try:
        email = auth.validate_session(x_token)
        msg = bytes.fromhex(req.message) if req.message_type == "DIGEST" else req.message.encode("utf-8")
        sig = bytes.fromhex(req.signature_hex)
        valid = transit.verify(key_name, msg, sig, email, message_type=req.message_type)
        return {"valid": valid}
    except Exception as exc:
        raise _http(exc)


# ---------------------------------------------------------------------------
# Entry point: python main.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
