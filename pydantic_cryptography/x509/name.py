"""Model for x509.Name."""

import base64
from typing import Any, cast

from cryptography import x509
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID
from pydantic import ConfigDict, Field, model_validator

from pydantic_cryptography.base.models import CryptographyModel, CryptographyRootModel
from pydantic_cryptography.base.types import ObjectIdentifierType

_NAME_ATTRIBUTE_OID_DESCRIPTION = (
    "A dotted string representing the OID or a known alias as described in "
    "[NAME_OID_TYPES]"
    "(https://django-ca.readthedocs.io/en/latest/python/constants.html#django_ca.constants.NAME_OID_TYPES)."
)
_NAME_ATTRIBUTE_VALUE_DESCRIPTION = (
    "Actual value of the attribute. For x500 unique identifiers (OID "
    f"{NameOID.X500_UNIQUE_IDENTIFIER.dotted_string}) the value must be the base64 encoded."
)

# Sources for OIDs that can be duplicate:
# * https://www.ibm.com/docs/en/ibm-mq/7.5?topic=certificates-distinguished-names - OU and DC
# * multiple_ous cert from the test suite.
#
# WARNING: sync any updates here to model_settings.SettingsModel._check_name().
#: OIDs that can occur multiple times in a certificate
MULTIPLE_OIDS = (NameOID.DOMAIN_COMPONENT, NameOID.ORGANIZATIONAL_UNIT_NAME, NameOID.STREET_ADDRESS)
MULTIPLE_OID_STRINGS = (oid.dotted_string for oid in MULTIPLE_OIDS)


class NameAttributeModel(CryptographyModel["x509.NameAttribute[str | bytes]"]):
    """
    Pydantic model wrapping :py:class:`~cg:cryptography.x509.NameAttribute`.

    For the `oid`, you can either use a dotted string or an alias from
    :py:attr:`~django_ca.constants.NAME_OID_TYPES`:

    .. pydantic-model:: name_attribute

    When processing a x500 unique identifier attribute, the value is expected to be base64 encoded:

    .. pydantic-model:: name_attribute_x500
    """

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "description": "A NameAttribute is defined by an object identifier (OID) and a value."
        },
    )

    oid: ObjectIdentifierType = Field(
        title="Object identifier",
        description=_NAME_ATTRIBUTE_OID_DESCRIPTION,
        json_schema_extra={"example": NameOID.COMMON_NAME.dotted_string},
    )
    value: str = Field(
        description=_NAME_ATTRIBUTE_VALUE_DESCRIPTION,
        json_schema_extra={"example": "example.com"},
    )

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Validator to handle x500 unique identifiers."""
        if isinstance(data, x509.NameAttribute) and data.oid == NameOID.X500_UNIQUE_IDENTIFIER:
            value = cast(bytes, data.value)
            return {"oid": data.oid.dotted_string, "value": base64.b64encode(value).decode("ascii")}
        return data

    @model_validator(mode="after")
    def validate_name_attribute(self) -> "NameAttributeModel":
        """Validate that country code OIDs have exactly two characters."""
        country_code_oids = (
            NameOID.COUNTRY_NAME.dotted_string,
            NameOID.JURISDICTION_COUNTRY_NAME.dotted_string,
        )
        if self.oid in country_code_oids and len(self.value) != 2:
            raise ValueError(f"{self.value}: Must have exactly two characters")

        cn_oid = NameOID.COUNTRY_NAME.dotted_string
        if self.oid == cn_oid and not 1 <= len(self.value) <= 64:
            raise ValueError(
                f"{cn_oid} length must be >= 1 and <= 64, but it was {len(self.value)}"
            )
        return self

    @property
    def cryptography(self) -> "x509.NameAttribute[str | bytes]":
        """The :py:class:`~cg:cryptography.x509.NameAttribute` instance for this model."""
        oid = x509.ObjectIdentifier(self.oid)
        if oid == NameOID.X500_UNIQUE_IDENTIFIER:
            value = base64.b64decode(self.value)
            return x509.NameAttribute(oid=oid, value=value, _type=_ASN1Type.BitString)

        return x509.NameAttribute(oid=oid, value=self.value)


class NameModel(CryptographyRootModel[list[NameAttributeModel], x509.Name]):
    """
    Pydantic model wrapping :py:class:`~cg:cryptography.x509.Name`.

    This model is a Pydantic :py:class:`~pydantic.root_model.RootModel` that takes a list of
    :py:class:`~django_ca.pydantic.name.NameAttributeModel` instances:

    .. pydantic-model:: name
    """

    root: list[NameAttributeModel] = Field(
        json_schema_extra={
            "format": "X.501 Name",
            "example": [
                {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
            ],
            "description": "A Name is composed of a list of name attributes.",
        },
    )

    @model_validator(mode="before")
    @classmethod
    def parse_cryptography(cls, data: Any) -> Any:
        """Validator for parsing :py:class:`~cg:cryptography.x509.Name`."""
        if isinstance(data, x509.Name):
            return list(data)
        return data

    @model_validator(mode="after")
    def validate_duplicates(self) -> "NameModel":
        """Validator to make sure that OIDs do not occur multiple times."""
        seen = set()

        # for oid in set(oids):
        for attr in self.root:
            oid = attr.oid

            # Check if any fields are duplicate where this is not allowed
            # (e.g. multiple CommonName fields)
            if oid in seen and oid not in MULTIPLE_OID_STRINGS:
                raise ValueError(f"Name attribute of type {oid} must not occur more then once.")
            seen.add(attr.oid)
        return self

    @property
    def cryptography(self) -> x509.Name:
        """The :py:class:`~cg:cryptography.x509.Name` instance for this model."""
        return x509.Name([attr.cryptography for attr in self.root])
