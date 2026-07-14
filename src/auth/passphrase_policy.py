MIN_LENGTH = 8


def is_strong_passphrase(passphrase: str) -> bool:
    if passphrase is None or len(passphrase) < MIN_LENGTH:
        return False
    has_letter = any(c.isalpha() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    return has_letter and has_digit
