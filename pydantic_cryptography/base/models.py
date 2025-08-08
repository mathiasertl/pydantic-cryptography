"""Base classes for all Pydantic models."""

import abc
from typing import Generic, TypeVar

from pydantic import BaseModel, RootModel
from pydantic.root_model import RootModelRootType

CryptographyModelTypeVar = TypeVar("CryptographyModelTypeVar")


class CryptographyModel(BaseModel, Generic[CryptographyModelTypeVar]):
    """Abstract base class for cryptography-related Pydantic models."""

    @property
    @abc.abstractmethod
    def cryptography(self) -> CryptographyModelTypeVar:
        """Convert to the respective cryptography instance."""


class CryptographyRootModel(
    RootModel[RootModelRootType], Generic[RootModelRootType, CryptographyModelTypeVar]
):
    """Abstract base class for cryptography-related Pydantic models with a different root type."""

    @property
    @abc.abstractmethod
    def cryptography(self) -> CryptographyModelTypeVar:
        """Convert to the respective cryptography instance."""
