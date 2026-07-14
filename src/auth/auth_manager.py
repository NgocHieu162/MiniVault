import time
from datetime import datetime, timezone
from typing import Callable, Optional

from .exceptions import (
    AccountLockedError,
    AccountNotFoundError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    PassphraseMismatchError,
    WeakPassphraseError,
)
from .passphrase_policy import is_strong_passphrase
from .password_hasher import hash_password, verify_password
from .session_store import SessionStore
from .user_store import UserStore

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 5 * 60  # 5 minutes, per assignment spec 0.2


class AuthManager:
    """Feature 0.2 - registration, login, session issuance, account lockout.

    `clock` is injected (defaults to time.time) purely so tests can
    fast-forward through the 5-minute lockout window deterministically
    instead of calling time.sleep(300).
    """

    def __init__(
        self,
        user_store: Optional[UserStore] = None,
        session_store: Optional[SessionStore] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.clock = clock
        self.user_store = user_store or UserStore()
        self.session_store = session_store or SessionStore(clock=clock)

    # ------------------------------------------------------------------
    # Register
    # ------------------------------------------------------------------
    def register(self, email: str, passphrase: str, confirm_passphrase: str) -> None:
        email = email.strip().lower()

        if passphrase != confirm_passphrase:
            raise PassphraseMismatchError("Passphrase and confirmation do not match")

        if not is_strong_passphrase(passphrase):
            raise WeakPassphraseError(
                "Passphrase too weak (min 8 chars, at least 1 letter and 1 digit)"
            )

        if self.user_store.get(email) is not None:
            raise EmailAlreadyExistsError("An account with this email already exists")

        record = {
            "email": email,
            "password_hash": hash_password(passphrase),
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.user_store.save(email, record)

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------
    def login(self, email: str, passphrase: str) -> str:
        """Returns a session token on success, else raises."""
        email = email.strip().lower()
        record = self.user_store.get(email)

        if record is None:
            raise AccountNotFoundError("No account found for this email")

        now = self.clock()
        locked_until = record.get("locked_until")

        # Lockout check happens BEFORE password verification, on purpose:
        # even the CORRECT passphrase must be rejected while locked
        # (required test, section 0.2).
        if locked_until is not None:
            if now < locked_until:
                raise AccountLockedError(locked_until - now)
            # Lock window has elapsed -> clear it before proceeding.
            record["failed_attempts"] = 0
            record["locked_until"] = None

        if not verify_password(record["password_hash"], passphrase):
            record["failed_attempts"] = record.get("failed_attempts", 0) + 1

            if record["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
                record["locked_until"] = now + LOCKOUT_SECONDS
                record["failed_attempts"] = 0
                self.user_store.save(email, record)
                raise AccountLockedError(LOCKOUT_SECONDS)

            self.user_store.save(email, record)
            raise InvalidCredentialsError("Invalid email or passphrase")

        # Success: reset failure counters and issue a session token.
        record["failed_attempts"] = 0
        record["locked_until"] = None
        self.user_store.save(email, record)

        return self.session_store.create(email)

    # ------------------------------------------------------------------
    # Session validation - used as middleware by Feature 1 (KV) & Feature 2
    # (Transit). Every endpoint must call this FIRST, before any
    # path/key-ownership check.
    # ------------------------------------------------------------------
    def validate_session(self, token: Optional[str]) -> str:
        """Returns the caller's email, or raises UnauthenticatedError."""
        return self.session_store.validate(token)

    def logout(self, token: str) -> None:
        self.session_store.invalidate(token)
