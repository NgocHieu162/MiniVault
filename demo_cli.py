from src.auth.auth_manager import AuthManager
from src.auth.exceptions import (
    AccountLockedError,
    InvalidCredentialsError,
    InvalidPassphraseError,
    VaultLockedError,
)
from src.core.vault import VaultManager
from src.storage.vault_storage import VaultStorage


def demo_vault_unlock():
    storage = VaultStorage(path="data/vault_meta.json")
    vault = VaultManager(storage)

    if not vault.is_initialized():
        print("No vault found. Initializing...")
        vault.init_vault("correct horse battery staple")
        print("Vault initialized. Status:", vault.status)

    # Simulate "process restart": brand-new VaultManager instance,
    # same storage on disk -> status must start as locked.
    vault = VaultManager(storage)
    print("After 'restart', status:", vault.status)

    # Feature 1 / Feature 2 must refuse to operate while locked
    try:
        vault.get_dek()
    except VaultLockedError as e:
        print("Expected error calling get_dek() while locked:", e)

    # Wrong passphrase
    try:
        vault.unlock("wrong passphrase")
    except InvalidPassphraseError as e:
        print("Expected error for wrong passphrase:", e)

    # Correct passphrase
    vault.unlock("correct horse battery staple")
    print("After correct unlock, status:", vault.status)
    dek = vault.get_dek()
    print("DEK successfully retrieved, length in bytes:", len(dek))

    vault.lock()
    print("After explicit lock(), status:", vault.status)


def demo_auth():
    print("\n--- Feature 0.2: register / login / lockout demo ---")

    auth = AuthManager()  # default JSON storage at data/users.json

    email = "bob@example.com"
    correct_pw = "Str0ngPass1"

    if auth.user_store.get(email) is None:
        auth.register(email, correct_pw, correct_pw)
        print(f"Registered {email}")
    else:
        print(f"{email} already registered, skipping register()")

    token = auth.login(email, correct_pw)
    print("Login OK, session token issued:", token[:12] + "...")
    print("validate_session() ->", auth.validate_session(token))

    # 5 consecutive wrong passphrases -> account locks for 5 minutes.
    print("\nSimulating 5 consecutive wrong passphrases...")
    for i in range(1, 6):
        try:
            auth.login(email, "WrongPassword1")
        except InvalidCredentialsError as e:
            print(f"  attempt {i}: invalid credentials -> {e}")
        except AccountLockedError as e:
            print(f"  attempt {i}: account locked -> {e}")

    # Even the correct passphrase must fail now.
    try:
        auth.login(email, correct_pw)
    except AccountLockedError as e:
        print("Correct passphrase rejected while locked (expected):", e)

    print(
        "\n(See tests/test_auth.py for the exact 5-minute lockout timing test, "
        "which uses an injected fake clock instead of sleeping.)"
    )


def main():
    demo_vault_unlock()
    demo_auth()


if __name__ == "__main__":
    main()
