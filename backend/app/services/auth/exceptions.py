"""
Authentication Exceptions

Custom exceptions for credential and authentication operations.
"""


class AuthMethodMismatchError(Exception):
    """Raised when credential auth method doesn't match requirement.

    This exception is raised when a host requires a specific authentication
    method (e.g., ssh_key) but the available credential uses a different
    method (e.g., password).

    Example:
        if credential.auth_method != required_method:
            raise AuthMethodMismatchError(
                f"Host requires {required_method} but credential uses {credential.auth_method}"
            )
    """

    pass


class CredentialNotFoundError(Exception):
    """Raised when no credential is available for a target.

    This exception is raised when credential resolution fails to find
    any suitable credentials for a host or system default.

    Attributes:
        target_id: The target for which credentials were not found
        message: Descriptive error message

    Example:
        if not credential:
            raise CredentialNotFoundError(
                target_id=str(host_id),
                message="No credentials configured for this host"
            )
    """

    def __init__(self, target_id: str = None, message: str = None):
        self.target_id = target_id
        self.message = message or f"No credentials found for target: {target_id}"
        super().__init__(self.message)


class CredentialValidationError(Exception):
    """Raised when credential validation fails.

    This exception is raised when a credential fails security validation,
    such as weak SSH keys or passwords that don't meet policy requirements.

    Attributes:
        validation_errors: List of specific validation failures
        is_security_rejection: True if rejected for security policy reasons

    Example:
        if not key_assessment.is_valid:
            raise CredentialValidationError(
                validation_errors=["RSA key size 1024 is below minimum 3072"],
                is_security_rejection=True
            )
    """

    def __init__(
        self,
        message: str = None,
        validation_errors: list = None,
        is_security_rejection: bool = False,
    ):
        self.validation_errors = validation_errors or []
        self.is_security_rejection = is_security_rejection
        self.message = message or "; ".join(self.validation_errors)
        super().__init__(self.message)


class CredentialDecryptionError(Exception):
    """Raised when credential decryption fails.

    This exception is raised when encrypted credential data cannot be
    decrypted, typically due to key rotation or corruption.

    Attributes:
        credential_id: ID of the credential that failed to decrypt

    Example:
        try:
            decrypted = encryption_service.decrypt(encrypted_data)
        except Exception as e:
            raise CredentialDecryptionError(
                credential_id=cred_id,
                message=f"Failed to decrypt credential: {e}"
            )
    """

    def __init__(self, credential_id: str = None, message: str = None):
        self.credential_id = credential_id
        self.message = message or f"Failed to decrypt credential: {credential_id}"
        super().__init__(self.message)
