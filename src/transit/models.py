import time
from typing import Any, Dict


class KeyRecord:
    """Represents a symmetric AES-256 key managed by the Transit Engine.

    Supports multiple key versions for Key Rotation (Advanced Feature).
    The actual AES keys are stored encrypted using the vault's Master DEK.

    Storage format (keys_by_version):
        {"1": "<encrypted_key_v1_b64>", "2": "<encrypted_key_v2_b64>", ...}
    """
    def __init__(
        self,
        key_name: str,
        owner_email: str,
        keys_by_version: Dict[str, str],
        latest_version: int,
        key_usage: str = "ENCRYPT_DECRYPT",
        created_at: float = None,
        is_revoked: bool = False,
    ):
        self.key_name = key_name
        self.owner_email = owner_email
        self.keys_by_version = keys_by_version  # {"1": encrypted_b64, "2": encrypted_b64, ...}
        self.latest_version = latest_version
        self.key_usage = key_usage
        self.created_at = created_at or time.time()
        self.is_revoked = is_revoked

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_name": self.key_name,
            "owner_email": self.owner_email,
            "key_usage": self.key_usage,
            "keys_by_version": self.keys_by_version,
            "latest_version": self.latest_version,
            "created_at": self.created_at,
            "is_revoked": self.is_revoked,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyRecord":
        # Backward compatibility: migrate old single-key format to versioned format
        if "keys_by_version" not in data:
            keys_by_version = {"1": data["encrypted_key_b64"]}
            latest_version = 1
        else:
            keys_by_version = data["keys_by_version"]
            latest_version = data["latest_version"]

        return cls(
            key_name=data["key_name"],
            owner_email=data["owner_email"],
            keys_by_version=keys_by_version,
            latest_version=latest_version,
            key_usage=data.get("key_usage", "ENCRYPT_DECRYPT"),
            created_at=data["created_at"],
            is_revoked=data.get("is_revoked", False),
        )


class SigningKeyRecord:
    """Represents an asymmetric key pair (RSA or Ed25519) managed by the Transit Engine.
    
    The private key is stored encrypted using the vault's Master DEK.
    The public key is stored in plaintext PEM format for public verification.
    """
    def __init__(
        self,
        key_name: str,
        owner_email: str,
        algorithm: str,
        encrypted_private_key_b64: str,
        public_key_pem: str,
        key_usage: str = "SIGN_VERIFY",
        created_at: float = None,
        is_revoked: bool = False,
    ):
        self.key_name = key_name
        self.owner_email = owner_email
        self.algorithm = algorithm  # e.g., "RSA-2048" or "Ed25519"
        self.encrypted_private_key_b64 = encrypted_private_key_b64
        self.public_key_pem = public_key_pem
        self.key_usage = key_usage
        self.created_at = created_at or time.time()
        self.is_revoked = is_revoked

    def to_dict(self) -> Dict[str, Any]:
        import base64
        return {
            "key_name": self.key_name,
            "owner_email": self.owner_email,
            "key_usage": self.key_usage,
            "algorithm": self.algorithm,
            "signing_algorithm": self.algorithm,
            "encrypted_private_key_b64": self.encrypted_private_key_b64,
            "public_key_pem": self.public_key_pem,
            "public_key_b64": base64.b64encode(self.public_key_pem.encode("ascii")).decode("ascii"),
            "created_at": self.created_at,
            "is_revoked": self.is_revoked,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SigningKeyRecord":
        import base64
        algorithm = data.get("algorithm") or data.get("signing_algorithm")
        public_key_pem = data.get("public_key_pem")
        if not public_key_pem and "public_key_b64" in data:
            public_key_pem = base64.b64decode(data["public_key_b64"]).decode("ascii")

        return cls(
            key_name=data["key_name"],
            owner_email=data["owner_email"],
            algorithm=algorithm,
            encrypted_private_key_b64=data["encrypted_private_key_b64"],
            public_key_pem=public_key_pem,
            key_usage=data.get("key_usage", "SIGN_VERIFY"),
            created_at=data["created_at"],
            is_revoked=data.get("is_revoked", False),
        )
