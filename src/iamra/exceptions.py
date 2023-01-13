"""iamra.exceptions.

This module contains the set of Iamra's exceptions.
"""


class IamraExceptionError(Exception):
    """Base exception class for Iamra."""

    def __init__(self, value):
        """Set parameter (text) from value."""
        self.parameter = value

    def __str__(self):
        """Raise exception with text."""
        return repr(self.parameter)


class EncryptionAlgorithmError(IamraExceptionError):
    """Define error class."""


class UntrustedCertificateError(IamraExceptionError):
    """Raised when a certificate is not trusted."""
