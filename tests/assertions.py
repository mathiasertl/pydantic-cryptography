"""Assertion shortcuts for cryptography models."""

import re
from typing import Any, TypeVar, Union

import pytest
from pydantic import BaseModel, ValidationError

from pydantic_cryptography import CryptographyModel, CryptographyRootModel

CryptographyModelTypeVar = TypeVar("CryptographyModelTypeVar", bound=CryptographyModel[Any])
CryptographyRootModelTypeVar = TypeVar(
    "CryptographyRootModelTypeVar", bound=CryptographyRootModel[Any, Any]
)
ExpectedErrors = list[tuple[str, tuple[str, ...], Union[str, "re.Pattern[str]"]]]


def assert_cryptography_model(
    model_class: type[CryptographyModelTypeVar],
    parameters: dict[str, Any],
    expected: Any,
    has_equality: bool = True,
) -> CryptographyModelTypeVar:
    """Test that a cryptography model matches the expected value."""
    model = model_class(**parameters)
    if has_equality:  # many cryptography objects don't implement __eq__ :-(
        assert model.cryptography == expected
    assert model == model_class.model_validate(expected), (model, expected)
    assert model == model_class.model_validate_json(
        model.model_dump_json()
    )  # test JSON serialization
    return model  # for any further tests on the model


def assert_validation_errors(
    model_class: type[BaseModel],
    parameters: list[dict[str, Any]] | dict[str, Any],
    expected_errors: ExpectedErrors,
) -> None:
    """Assertion method to test validation errors."""
    with pytest.raises(ValidationError) as ex_info:  # noqa: PT012
        if isinstance(parameters, list):
            model_class(parameters)  # type: ignore[call-arg]  # ruled out with overload
        else:
            model_class(**parameters)

    errors = ex_info.value.errors()
    assert len(expected_errors) == len(errors)
    for expected, actual in zip(expected_errors, errors, strict=False):
        assert expected[0] == actual["type"]
        assert expected[1] == actual["loc"]
        if isinstance(expected[2], str):
            assert expected[2] == actual["msg"]
        else:  # pragma: no cover
            pattern: re.Pattern[str] = expected[2]
            assert pattern.search(actual["msg"])
