import pytest

# Register assertion helpers for better output in our helpers. See also:
#   https://docs.pytest.org/en/latest/how-to/writing_plugins.html#assertion-rewriting
# NOTE: No need to add test_* modules, they are included automatically.
pytest.register_assert_rewrite("tests.assertions")
