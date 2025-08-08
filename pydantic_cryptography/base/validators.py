"""Common Pydantic validators."""

from typing import Any

from cryptography import x509


def oid_to_dotted_string_validator(value: Any) -> Any:
    """Validate a :py:class:`~cryptography.x509.ObjectIdentifier`."""
    if isinstance(value, x509.ObjectIdentifier):
        return value.dotted_string
    return value


def dotted_string_after_validator(value: str) -> str:
    """Validate that the given value is a valid, dotted string."""
    try:
        x509.ObjectIdentifier(value)
    except ValueError as ex:
        raise ValueError(f"{value}: Invalid object identifier") from ex
    return value
