# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
sys.path.insert(0, os.path.abspath('..'))
sys.path.insert(0, os.path.abspath('.'))   # for local extensions (pysim_fs_sphinx, ...)


# -- Project information -----------------------------------------------------

project = 'osmopysim-usermanual'
copyright = '2009-2025 by Sylvain Munaut, Harald Welte, Philipp Maier, Supreeth Herle, Merlin Chlosta'
author = 'Sylvain Munaut, Harald Welte, Philipp Maier, Supreeth Herle, Merlin Chlosta'

# PDF: Avoid that the authors list exceeds the page by inserting '\and'
# manually as line break (https://github.com/sphinx-doc/sphinx/issues/6875)
latex_elements = {
    "maketitle":
        r"""\author{Sylvain Munaut, Harald Welte, Philipp Maier, \and Supreeth Herle, Merlin Chlosta}
\sphinxmaketitle
"""
}

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
        "sphinx.ext.autodoc",
        "sphinxarg.ext",
        "sphinx.ext.autosectionlabel",
        "sphinx.ext.napoleon",
        "pysim_fs_sphinx",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'alabaster'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

autoclass_content = 'both'

# Mock optional server-side deps of es2p and http_json_api/es9p,
# so that autodoc can import and document those modules.
autodoc_mock_imports = ['klein', 'twisted']

# Workaround for duplicate label warnings:
# https://github.com/sphinx-doc/sphinx-argparse/issues/14
#
# sphinxarg.ext generates generic sub-headings ("Named arguments",
# "Positional arguments", "Sub-commands", "General options", ...) for every
# argparse command/tool.  These repeat across many files and trigger tons
# of autosectionlabel duplicate-label warnings - suppress them.
autosectionlabel_maxdepth = 3
suppress_warnings = [
    'autosectionlabel.filesystem',
    'autosectionlabel.saip-tool',
    'autosectionlabel.shell',
    'autosectionlabel.smpp2sim',
    'autosectionlabel.smpp-ota-tool',
    'autosectionlabel.suci-keytool',
    'autosectionlabel.trace',
]
