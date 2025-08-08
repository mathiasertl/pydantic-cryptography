"""Standard sphinx configuration."""


# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "pydantic-cryptography"
copyright = "2025, Mathias Ertl"
author = "Mathias Ertl"
release = "0.1.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosummary",
    "sphinxcontrib.spelling",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Warn about unresolved references
nitpicky = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
    "cg": ("https://cryptography.io/en/stable/", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}

# autodoc_pydantic_model_show_validator_summary = False
# autodoc_pydantic_model_show_validator_members = False
# autodoc_pydantic_model_show_field_summary = False
# autodoc_pydantic_model_members = False
# autodoc_pydantic_field_list_validators = False

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"

# autodoc_class_signature = "separated"
# html_static_path = ["_static"]

rst_epilog = """
.. |NameAttribute| replace:: cryptography.x509.NameAttribute
.. |NameAttributeRef| replace:: :py:class:`~cg:cryptography.x509.NameAttribute`
.. |Name| replace:: cryptography.x509.Name
"""
