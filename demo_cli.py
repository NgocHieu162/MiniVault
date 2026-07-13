from src.auth.exceptions import InvalidPassphraseError, VaultLockedError
from src.auth.vault import VaultManager
from src.storage.vault_storage import VaultStorage


def main():
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


if __name__ == "__main__":
    main()
