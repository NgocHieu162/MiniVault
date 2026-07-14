import secrets
import time
from typing import Callable, Dict, Optional

from .exceptions import UnauthenticatedError

SESSION_TTL_SECONDS = 30 * 60  # 30 minutes, per assignment spec 0.2


class SessionStore:
    """Server-side session token store.

    Kept in-memory (tokens don't need to survive a process restart - much
    like the vault itself defaults back to 'locked' on restart). A `clock`
    callable is injected so tests can fast-forward time without sleeping.
    """

    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        ttl_seconds: int = SESSION_TTL_SECONDS,
    ):
        self._sessions: Dict[str, Dict] = {}
        self._clock = clock
        self._ttl = ttl_seconds

    def create(self, email: str) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = {
            "email": email,
            "expires_at": self._clock() + self._ttl,
        }
        return token

    def validate(self, token: Optional[str]) -> str:
        """Return the email bound to `token`, or raise UnauthenticatedError.
        This must be the very first check on every Feature 1 / Feature 2
        call, before any path/key ownership check (Acceptance Criteria 1.2)."""
        if not token or token not in self._sessions:
            raise UnauthenticatedError("Invalid or missing session token")

        session = self._sessions[token]
        if self._clock() >= session["expires_at"]:
            del self._sessions[token]
            raise UnauthenticatedError("Session token expired, please log in again")

        return session["email"]

    def invalidate(self, token: str) -> None:
        """Explicit logout."""
        self._sessions.pop(token, None)
