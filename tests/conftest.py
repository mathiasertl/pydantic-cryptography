"""Configuration module for pytest."""

import importlib
import sys

from _pytest.config import Config as PytestConfig


def pytest_configure(config: "PytestConfig") -> None:
    """Output libraries when running pytest."""
    print("Testing with:")
    print("* Python: ", sys.version.replace("\n", ""))
    installed_versions = {p.name: p.version for p in importlib.metadata.distributions()}
    for pkg in sorted(["cryptography", "pydantic"]):
        print(f"* {pkg}: {installed_versions[pkg]}")
