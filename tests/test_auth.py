import pytest

from src.auth.auth_manager import AuthManager
from src.auth.exceptions import (
    AccountLockedError,
    AccountNotFoundError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    PassphraseMismatchError,
    UnauthenticatedError,
    WeakPassphraseError,
)
from src.auth.session_store import SessionStore
from src.auth.user_store import UserStore
from src.storage.vault_storage import VaultStorage


class FakeClock:
    """Controllable clock so lockout/session-expiry tests don't need
    time.sleep(300)."""

    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def auth_manager(tmp_path, clock):
    storage = VaultStorage(path=str(tmp_path / "users.json"))
    return AuthManager(
        user_store=UserStore(storage=storage),
        session_store=SessionStore(clock=clock),
        clock=clock,
    )


# ---------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------

def test_register_and_login_success(auth_manager):
    auth_manager.register("alice@example.com", "Str0ngPass1", "Str0ngPass1")
    token = auth_manager.login("alice@example.com", "Str0ngPass1")
    assert isinstance(token, str) and token

    email = auth_manager.validate_session(token)
    assert email == "alice@example.com"


def test_register_duplicate_email_rejected(auth_manager):
    auth_manager.register("alice@example.com", "Str0ngPass1", "Str0ngPass1")
    with pytest.raises(EmailAlreadyExistsError):
        auth_manager.register("alice@example.com", "AnotherPass1", "AnotherPass1")


def test_register_passphrase_mismatch(auth_manager):
    with pytest.raises(PassphraseMismatchError):
        auth_manager.register("bob@example.com", "Str0ngPass1", "Different1")


def test_register_weak_passphrase(auth_manager):
    with pytest.raises(WeakPassphraseError):
        auth_manager.register("bob@example.com", "short", "short")


# ---------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------

def test_login_unknown_account(auth_manager):
    with pytest.raises(AccountNotFoundError):
        auth_manager.login("ghost@example.com", "whatever123")


def test_login_wrong_password(auth_manager):
    auth_manager.register("carol@example.com", "Str0ngPass1", "Str0ngPass1")
    with pytest.raises(InvalidCredentialsError):
        auth_manager.login("carol@example.com", "WrongPass1")


# ---------------------------------------------------------------------
# REQUIRED TEST (mục V, STT 1):
# 5 lần sai liên tiếp -> khoá đúng 5 phút; đăng nhập thất bại kể cả đúng
# passphrase trong lúc bị khoá.
# ---------------------------------------------------------------------

def test_required_lockout_after_5_failed_attempts(auth_manager, clock):
    auth_manager.register("dave@example.com", "Str0ngPass1", "Str0ngPass1")

    # Attempts 1-4: wrong password, ordinary error, not yet locked.
    for _ in range(4):
        with pytest.raises(InvalidCredentialsError):
            auth_manager.login("dave@example.com", "WrongPass1")

    # 5th consecutive wrong attempt -> account locks.
    with pytest.raises(AccountLockedError):
        auth_manager.login("dave@example.com", "WrongPass1")

    # Even the CORRECT passphrase must fail while locked.
    with pytest.raises(AccountLockedError):
        auth_manager.login("dave@example.com", "Str0ngPass1")

    # Still inside the 5-minute window -> still locked.
    clock.advance(299)
    with pytest.raises(AccountLockedError):
        auth_manager.login("dave@example.com", "Str0ngPass1")

    # Exactly at/after 5 minutes -> lock lifted, correct passphrase works.
    clock.advance(2)
    token = auth_manager.login("dave@example.com", "Str0ngPass1")
    assert token


# ---------------------------------------------------------------------
# Session validation
# ---------------------------------------------------------------------

def test_validate_session_rejects_missing_or_unknown_token(auth_manager):
    with pytest.raises(UnauthenticatedError):
        auth_manager.validate_session(None)
    with pytest.raises(UnauthenticatedError):
        auth_manager.validate_session("not-a-real-token")


def test_session_expires_after_30_minutes(auth_manager, clock):
    auth_manager.register("erin@example.com", "Str0ngPass1", "Str0ngPass1")
    token = auth_manager.login("erin@example.com", "Str0ngPass1")

    clock.advance(29 * 60)
    assert auth_manager.validate_session(token) == "erin@example.com"

    clock.advance(2 * 60)  # now 31 minutes total
    with pytest.raises(UnauthenticatedError):
        auth_manager.validate_session(token)
