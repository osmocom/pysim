"""
Sphinx extension: auto-generate docs/filesystem.rst from the pySim EF class hierarchy.

Hooked into Sphinx's ``builder-inited`` event so the file is always regenerated
from the live Python classes before Sphinx reads any source files.

The table of root objects to document is in SECTIONS near the top of this file.
EXCLUDED lists CardProfile/CardApplication subclasses intentionally omitted from
SECTIONS, with reasons.  Both tables are read by tests/unittests/test_fs_coverage.py
to ensure every class with EF/DF content is accounted for.
"""

import importlib
import inspect
import json
import os
import sys
import textwrap

# Ensure pySim is importable when this module is loaded as a Sphinx extension
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pySim.filesystem import (CardApplication, CardDF, CardMF, CardEF, # noqa: E402
                              TransparentEF, TransRecEF, LinFixedEF, CyclicEF, BerTlvEF)
from pySim.profile import CardProfile # noqa: E402


# Generic EF base classes whose docstrings describe the *type* of file
# (Transparent, LinFixed, ...) rather than a specific file's content.
# Suppress those boilerplate texts in the per-EF entries; they are only
# useful once, at the top of the document or in a dedicated glossary.
_EF_BASE_TYPES = frozenset([TransparentEF,
                            TransRecEF,
                            LinFixedEF,
                            CyclicEF,
                            BerTlvEF])


# ---------------------------------------------------------------------------
# Sections: (heading, module, class-name)
# The class must be either a CardProfile (uses .files_in_mf) or a CardDF
# subclass (uses .children).
# ---------------------------------------------------------------------------
SECTIONS = [
    ('MF / TS 102 221 (UICC)',
     'pySim.ts_102_221', 'CardProfileUICC'),
    ('ADF.USIM / TS 31.102',
     'pySim.ts_31_102',  'ADF_USIM'),
    ('ADF.ISIM / TS 31.103',
     'pySim.ts_31_103',  'ADF_ISIM'),
    ('ADF.HPSIM / TS 31.104',
     'pySim.ts_31_104',  'ADF_HPSIM'),
    ('DF.GSM + DF.TELECOM / TS 51.011 (SIM)',
     'pySim.ts_51_011',  'CardProfileSIM'),
    ('CDMA / IS-820 (RUIM)',
     'pySim.cdma_ruim',  'CardProfileRUIM'),
    ('DF.EIRENE / GSM-R',
     'pySim.gsm_r',      'DF_EIRENE'),
    ('DF.SYSTEM / sysmocom SJA2+SJA5',
     'pySim.sysmocom_sja2', 'DF_SYSTEM'),
]

# ---------------------------------------------------------------------------
# Excluded: {(module, class-name)}
# CardProfile and CardApplication subclasses that have EF/DF children but are
# intentionally absent from SECTIONS.  Keeping this list explicit lets
# test_fs_coverage.py detect newly added classes that the developer forgot to
# add to either table.
# ---------------------------------------------------------------------------
EXCLUDED = {
    # eUICC profiles inherit files_in_mf verbatim from CardProfileUICC; the
    # eUICC-specific content lives in ISD-R / ISD-P applications, not in MF.
    ('pySim.euicc', 'CardProfileEuiccSGP02'),
    ('pySim.euicc', 'CardProfileEuiccSGP22'),
    ('pySim.euicc', 'CardProfileEuiccSGP32'),
    # CardApplication* classes are thin wrappers that embed an ADF_* instance.
    # The ADF contents are already documented via the corresponding ADF_* entry
    # in SECTIONS above.
    ('pySim.ts_31_102', 'CardApplicationUSIM'),
    ('pySim.ts_31_102', 'CardApplicationUSIMnonIMSI'),
    ('pySim.ts_31_103', 'CardApplicationISIM'),
    ('pySim.ts_31_104', 'CardApplicationHPSIM'),
}

# RST underline characters ordered by nesting depth
_HEADING_CHARS = ['=', '=', '-', '~', '^', '"']
# Level 0 uses '=' with overline (page title).
# Level 1 uses '=' without overline (major sections).
# Levels 2+ use the remaining characters for DFs.


# ---------------------------------------------------------------------------
# RST formatting helpers
# ---------------------------------------------------------------------------

def _heading(title: str, level: int) -> str:
    """Return an RST heading string.  Level 0 gets an overline."""
    char = _HEADING_CHARS[level]
    rule = char * len(title)
    if level == 0:
        return f'{rule}\n{title}\n{rule}\n\n'
    return f'{title}\n{rule}\n\n'


def _json_default(obj):
    """Fallback serialiser: bytes -> hex, anything else -> repr."""
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    return repr(obj)


def _examples_block(cls) -> str:
    """Return RST code-block examples (one per vector), or '' if none exist.

    Each example is rendered as a ``json5`` code-block with the hex-encoded
    binary as a ``// comment`` on the first line, followed by the decoded JSON.
    ``json5`` is used instead of ``json`` so that Pygments does not flag the
    ``//`` comment as a syntax error.
    """
    vectors = []
    for attr in ('_test_de_encode', '_test_decode'):
        v = getattr(cls, attr, None)
        if v:
            vectors.extend(v)
    if not vectors:
        return ''

    lines = ['**Examples**\n\n']

    for t in vectors:
        # 2-tuple: (encoded, decoded)
        # 3-tuple: (encoded, record_nr, decoded)   — LinFixedEF / CyclicEF
        if len(t) >= 3:
            encoded, record_nr, decoded = t[0], t[1], t[2]
            comment = f'record {record_nr}: {encoded.lower()}'
        else:
            encoded, decoded = t[0], t[1]
            comment = f'file: {encoded.lower()}'

        json_str = json.dumps(decoded, default=_json_default, indent=2)
        json_indented = textwrap.indent(json_str, '   ')

        lines.append('.. code-block:: json5\n\n')
        lines.append(f'   // {comment}\n')
        lines.append(json_indented + '\n')
        lines.append('\n')

    return ''.join(lines)


def _document_ef(ef: CardEF) -> str:
    """Return RST for a single EF.  Uses ``rubric`` to stay out of the TOC."""
    cls = type(ef)

    parts = [ef.fully_qualified_path_str()]
    if ef.fid:
        parts.append(f'({ef.fid.upper()})')
    if ef.desc:
        parts.append(f'\u2014 {ef.desc}')   # em-dash
    title = ' '.join(parts)

    lines = [f'.. rubric:: {title}\n\n']

    # Only show a docstring if it is specific to this class.  EFs that are
    # direct instances of a base type (TransparentEF, LinFixedEF, ...) carry
    # only the generic "what is a TransparentEF" boilerplate; named subclasses
    # without their own __doc__ have cls.__dict__['__doc__'] == None.  Either
    # way, suppress the text here - it belongs at the document level, not
    # repeated for every single EF entry.
    doc = None if cls in _EF_BASE_TYPES else cls.__dict__.get('__doc__')
    if doc:
        lines.append(inspect.cleandoc(doc) + '\n\n')

    examples = _examples_block(cls)
    if examples:
        lines.append(examples)

    return ''.join(lines)


def _document_df(df: CardDF, level: int) -> str:
    """Return RST for a DF section and all its children, recursively."""
    parts = [df.fully_qualified_path_str()]
    if df.fid:
        parts.append(f'({df.fid.upper()})')
    if df.desc:
        parts.append(f'\u2014 {df.desc}')   # em-dash
    title = ' '.join(parts)

    lines = [_heading(title, level)]

    cls = type(df)
    doc = None if cls in (CardDF, CardMF) else cls.__dict__.get('__doc__')
    if doc:
        lines.append(inspect.cleandoc(doc) + '\n\n')

    for child in df.children.values():
        if isinstance(child, CardDF):
            lines.append(_document_df(child, level + 1))
        elif isinstance(child, CardEF):
            lines.append(_document_ef(child))

    return ''.join(lines)


# ---------------------------------------------------------------------------
# Top-level generator
# ---------------------------------------------------------------------------

def generate_filesystem_rst() -> str:
    """Walk all registered sections and return the full RST document as a string."""
    out = [
        '.. This file is auto-generated by docs/pysim_fs_sphinx.py — do not edit.\n\n',
        _heading('Card Filesystem Reference', 0),
        'This page documents all Elementary Files (EFs) and Dedicated Files (DFs) '
        'implemented in pySim, organised by their location in the card filesystem.\n\n',
    ]

    # Track already-documented classes so that DFs/EFs shared between profiles
    # (e.g. DF.TELECOM / DF.GSM present in both CardProfileSIM and CardProfileRUIM)
    # are only emitted once.
    seen_types: set = set()

    for section_title, module_path, class_name in SECTIONS:
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        obj = cls()

        if isinstance(obj, CardProfile):
            files = obj.files_in_mf
        elif isinstance(obj, CardApplication):
            files = list(obj.adf.children.values())
        elif isinstance(obj, CardDF):
            files = list(obj.children.values())
        else:
            continue

        # Filter out files whose class was already documented in an earlier section.
        files = [f for f in files if type(f) not in seen_types]
        if not files:
            continue

        out.append(_heading(section_title, 1))

        for f in files:
            seen_types.add(type(f))
            if isinstance(f, CardDF):
                out.append(_document_df(f, level=2))
            elif isinstance(f, CardEF):
                out.append(_document_ef(f))

    return ''.join(out)


# ---------------------------------------------------------------------------
# Sphinx integration
# ---------------------------------------------------------------------------

def _on_builder_inited(app):
    output_path = os.path.join(app.srcdir, 'filesystem.rst')
    with open(output_path, 'w') as fh:
        fh.write(generate_filesystem_rst())


def setup(app):
    app.connect('builder-inited', _on_builder_inited)
    return {'version': '0.1', 'parallel_read_safe': True}
