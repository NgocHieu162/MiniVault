# MiniVault

> **Secure Storage (KV Engine) & Encryption / Signing as a Service (Transit Engine)**

MiniVault is a lightweight, production-ready cryptographic vault service written in Python. It provides secure secret management and encryption/signing services modeled after **HashiCorp Vault** and **AWS KMS**.

---

## Key Features & Architecture

### Core Features
- **Vault Initialization & Unlock (Feature 0.1)**
  - Key Derivation Function (KDF): **Argon2id** with random 16-byte salt per deployment.
  - Data Encryption Key (DEK): Random 256-bit AES key, encrypted with KDF-derived key (**AES-256-GCM**).
  - State Isolation: Always defaults to `LOCKED` on startup. The DEK resides strictly in RAM and is never written to disk in plaintext.
- **User Identity Authentication (Feature 0.2)**
  - Password Hashing: **Argon2id** (never plain SHA).
  - Session Tokens: Cryptographically secure 256-bit random tokens with 30-minute expiration (`X-Token` header).
  - Account Lockout: Mandatory 5-minute lockout after 5 consecutive failed login attempts.
- **KV Engine — Encrypted-at-Rest Storage (Feature 1)**
  - Authenticated Encryption: **AES-256-GCM** AEAD with a unique 96-bit nonce for every write.
  - Access Control: Strict ownership isolation under `secret/<email>/...`. Cross-tenant requests return generic `PERMISSION_DENIED` errors to prevent path discovery.
  - Data Integrity: Full GCM authentication tag verification on read; tampered ciphertexts are refused outright.
- **Transit Engine — Encryption & Signing as a Service (Feature 2)**
  - Named Keys: Symmetric (AES-256-GCM) and Asymmetric (Ed25519, RSA-2048) keys.
  - Key Protection: Named keys are encrypted at rest using the Vault DEK and **NEVER** exposed via any API.
  - Digital Signatures: Supports `RAW` (server SHA-256 hashing) and `DIGEST` (precomputed hash) modes. Signature verification returns structured boolean results without unhandled exceptions.

### Advanced Features (+1.0 Extra Credit Points)
1. **Key Rotation (+0.4 pts)**: Versioned symmetric keys. New encryptions automatically use the latest version (`vault:<name>:<ver>:<payload>`), while older versions remain fully decryptable for backward compatibility.
2. **KV Versioning (+0.3 pts)**: Retains full history of secret modifications. Supports reading specific historical versions (`read(path, version=N)`) and inspecting version metadata without decrypting data.
3. **Tamper-Evident Hash-Chained Audit Log (+0.3 pts)**: Append-only log where each entry embeds `SHA256(index | timestamp | event | prev_hash)`. Includes automated integrity verification (`verify_integrity()`) to detect log alteration or deletion.

---

## Technical Stack & Dependencies

- **Language**: Python 3.9+
- **Cryptography**: `cryptography` (AESGCM, Ed25519, RSA-PSS), `argon2-cffi` (Argon2id KDF and password hashing), `secrets`, `os.urandom`
- **REST API Framework**: FastAPI, Uvicorn, Pydantic
- **Testing Suite**: `pytest`, `pytest-cov`

---

## Installation & Setup

### 1. Environment Setup (Windows / Linux / macOS)

Clone the repository and enter the project directory:

```bash
cd crypto
```

Create and activate a virtual environment:

```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the REST API Server

MiniVault includes a full REST API server built with FastAPI.

### Start the Server

```bash
python -m uvicorn main:app --reload
```

The server starts locally at `http://127.0.0.1:8000`.

### Interactive API Documentation (Swagger UI)

Open your web browser and navigate to:
**`http://127.0.0.1:8000/docs`**

### Step-by-Step API Testing Flow

1. **Initialize Vault**: Call `POST /vault/init` with `{"passphrase": "MasterPassword123"}`.
2. **Unlock Vault**: Call `POST /vault/unlock` with `{"passphrase": "MasterPassword123"}`.
3. **Register User**: Call `POST /auth/register` with email and password.
4. **Login**: Call `POST /auth/login` to receive a `token`.
5. **Use Token**: Pass the token in the `X-Token` header for all `/kv/...`, `/transit/...`, and `/audit/...` requests.

---

## Automated Testing & Quality Assurance

The project includes comprehensive automated unit tests covering all required and advanced features.

### Run All Unit Tests

```bash
pytest -v
```

**Test Results Summary**:
- **Total Test Cases**: `66 Passed` (100% Pass Rate)
- **Execution Time**: ~17 seconds

### Run Code Coverage Report

```bash
pytest --cov=src --cov-report=term-missing
```

**Coverage Summary**:
- `src/auth/`: 98%
- `src/core/`: 94%
- `src/kv/`: 96%
- `src/transit/`: 93%
- **Total Code Coverage**: **94%**

---

## Project Directory Structure

```text
crypto/
├── README.md                   # Project documentation
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Pytest configuration
├── main.py                     # FastAPI REST API server
├── src/
│   ├── core/                   # VaultManager, KDF (Argon2id), AuditLogger
│   ├── auth/                   # AuthManager, UserStore, SessionStore, PasswordHasher
│   ├── kv/                     # KVManager (Encrypted-at-Rest & Versioning)
│   ├── transit/                # TransitEngine (Encryption, Signing, Key Rotation)
│   └── storage/                # VaultStorage (Atomic JSON read/write)
├── tests/
│   ├── test_auth.py            # Authentication & Lockout tests
│   ├── test_kv_manager.py      # KV Engine & Access Control tests
│   ├── test_transit.py         # Transit Engine & Key Rotation tests
│   └── test_advanced_features.py # Advanced Features (Versioning, Audit Log) tests
└── data/                       # Persistent JSON storage & Audit log files
```

---

## Submission Deliverables

- **Source Code**: Complete Python implementation with 94% test coverage.
- **REST API**: Production-ready FastAPI interface at `main.py`.
- **Report Document**: Placed under `docs/report/Report_StudentID1_StudentID2_StudentID3.pdf`.
- **Demo Video**: Link available in report document / submission package.
