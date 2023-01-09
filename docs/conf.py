"""Sphinx configuration."""
project = "Iamra"
author = "Gavin Adams"
copyright = "2023, Gavin Adams"
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx_click",
    "myst_parser",
]
autodoc_typehints = "description"
html_theme = "furo"
