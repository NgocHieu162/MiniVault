class TransitError(Exception):
    """Base class for all transit-related errors."""
    pass


class KeyNotFoundError(TransitError):
    """Raised when the requested named key is not found in storage."""
    pass


class KeyAlreadyExistsError(TransitError):
    """Raised when creating a key with a name that is already in use."""
    pass


class KeyRevokedError(TransitError):
    """Raised when attempting to use a key that has been revoked."""
    pass


class PermissionDeniedError(TransitError):
    """Raised when a user attempts to access or manage a key they do not own."""
    pass


class InvalidKeyUsageError(TransitError):
    """Raised when an operation is incompatible with the key type/algorithm."""
    pass
