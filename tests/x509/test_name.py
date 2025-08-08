"""Tests for NameAttributeModel and NameModel."""

from typing import Any

import pytest
from cryptography import x509
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID

# from django_ca.tests.base.doctest import doctest_module
from pydantic_cryptography.x509 import NameAttributeModel, NameModel
from tests.assertions import (
    ExpectedErrors,
    assert_cryptography_model,
    assert_validation_errors,
)


@pytest.mark.parametrize(
    ("parameters", "name_attr"),
    (
        (
            {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
            x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com"),
        ),
        (
            {"oid": x509.OID_ORGANIZATIONAL_UNIT_NAME, "value": "OrgUnit"},
            x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="OrgUnit"),
        ),
        (
            {"oid": NameOID.X500_UNIQUE_IDENTIFIER, "value": "ZXhhbXBsZS5jb20="},
            x509.NameAttribute(
                oid=NameOID.X500_UNIQUE_IDENTIFIER, value=b"example.com", _type=_ASN1Type.BitString
            ),
        ),
    ),
)
def test_name_attribute(
    parameters: dict[str, Any], name_attr: "x509.NameAttribute[str | bytes]"
) -> None:
    """Test NameAttributeModel."""
    assert_cryptography_model(NameAttributeModel, parameters, name_attr)


@pytest.mark.parametrize(
    ("parameters", "errors"),
    (
        (
            {"oid": "foo", "value": "example.com"},
            [("value_error", ("oid",), "Value error, foo: Invalid object identifier")],
        ),
    ),
)
def test_name_attribute_errors(parameters: dict[str, str], errors: ExpectedErrors) -> None:
    """Test errors for NameAttributes."""
    assert_validation_errors(NameAttributeModel, parameters, errors)


@pytest.mark.parametrize("value", ("", "A", "ABC"))
@pytest.mark.parametrize(
    "oid",
    (
        NameOID.COUNTRY_NAME,
        NameOID.COUNTRY_NAME.dotted_string,
        NameOID.JURISDICTION_COUNTRY_NAME,
        NameOID.JURISDICTION_COUNTRY_NAME.dotted_string,
    ),
)
def test_name_attribute_country_code_errors(oid: str, value: str) -> None:
    """Test validation for country codes."""
    errors: ExpectedErrors = [
        ("value_error", (), f"Value error, {value}: Must have exactly two characters")
    ]
    assert_validation_errors(NameAttributeModel, {"oid": oid, "value": value}, errors)


@pytest.mark.parametrize("oid", (NameOID.COMMON_NAME, NameOID.COMMON_NAME.dotted_string))
def test_name_attribute_empty_common_name(oid: Any) -> None:
    """Test validation for country codes."""
    errors: ExpectedErrors = [
        (
            "value_error",
            (),
            f"Value error, {NameOID.COMMON_NAME.dotted_string} length must be >= 1 "
            f"and <= 64, but it was 0",
        )
    ]
    assert_validation_errors(NameAttributeModel, {"oid": oid, "value": ""}, errors)


@pytest.mark.parametrize(
    ("serialized", "expected"),
    (
        ([], x509.Name([])),
        ("CN=example.com", [x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")]),
        (
            [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}],
            [x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")],
        ),
        (
            [
                {"oid": NameOID.COUNTRY_NAME.dotted_string, "value": "AT"},
                {"oid": NameOID.ORGANIZATION_NAME.dotted_string, "value": "OrgName"},
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
            ],
            [
                x509.NameAttribute(oid=NameOID.COUNTRY_NAME, value="AT"),
                x509.NameAttribute(oid=NameOID.ORGANIZATION_NAME, value="OrgName"),
                x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com"),
            ],
        ),
    ),
)
def test_name(
    serialized: list[dict[str, Any]], expected: list["x509.NameAttribute[str | bytes]"]
) -> None:
    """Test NameModel."""
    assert_cryptography_model(NameModel, {"root": serialized}, x509.Name(expected))  # type: ignore[type-var]


def test_iterable() -> None:
    """Test that NameModel is iterable."""
    name = NameModel.model_validate("CN=example.com,OU=ExampleOrgUnit,O=ExampleOrg,ST=Vienna,C=AT")
    assert len(name) == 5
    assert list(name) == [
        NameAttributeModel(oid=NameOID.COUNTRY_NAME.dotted_string, value="AT"),
        NameAttributeModel(oid=NameOID.STATE_OR_PROVINCE_NAME.dotted_string, value="Vienna"),
        NameAttributeModel(oid=NameOID.ORGANIZATION_NAME.dotted_string, value="ExampleOrg"),
        NameAttributeModel(
            oid=NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string, value="ExampleOrgUnit"
        ),
        NameAttributeModel(oid=NameOID.COMMON_NAME.dotted_string, value="example.com"),
    ]

    assert name[0] == NameAttributeModel(oid="2.5.4.6", value="AT")
    name_slice: list[NameAttributeModel] = name[4:]  # assignment to test mypy
    assert name_slice == [
        NameAttributeModel(oid=NameOID.COMMON_NAME.dotted_string, value="example.com")
    ]


@pytest.mark.parametrize(
    ("value", "errors"),
    (
        (
            [
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"},
                {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.net"},
            ],
            [
                (
                    "value_error",
                    (),
                    f"Value error, Name attribute of type {NameOID.COMMON_NAME.dotted_string} "
                    f"must not occur more then once.",
                )
            ],
        ),
    ),
)
def test_name_errors(value: list[dict[str, Any]], errors: ExpectedErrors) -> None:
    """Test validation errors for NameModel."""
    assert_validation_errors(NameModel, value, errors)
