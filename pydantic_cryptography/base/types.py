"""Reusable, annotated type aliases."""

from typing import Annotated

from pydantic import AfterValidator, BeforeValidator

from pydantic_cryptography.base.validators import (
    dotted_string_after_validator,
    oid_to_dotted_string_validator,
)

ObjectIdentifierType = Annotated[
    str,
    BeforeValidator(oid_to_dotted_string_validator),
    AfterValidator(dotted_string_after_validator),
]
"""A string that will convert :py:class:`~cg:cryptography.x509.ObjectIdentifier` objects.

This type alias will also validate that the string is a valid dotted string.
"""
