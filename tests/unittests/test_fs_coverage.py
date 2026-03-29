#!/usr/bin/env python3

# (C) 2026 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Verify that every CardProfile / CardApplication subclass with EF/DF content,
and every standalone CardDF subclass (one not reachable as a child of any profile
or application), is either listed in docs/pysim_fs_sphinx.py::SECTIONS or
explicitly EXCLUDED."""

import unittest
import importlib
import inspect
import pkgutil
import sys
import os

# Make docs/pysim_fs_sphinx.py importable without a full Sphinx build.
_DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'docs')
sys.path.insert(0, os.path.abspath(_DOCS_DIR))

import pySim                                                       # noqa: E402
from pySim.filesystem import CardApplication, CardDF, CardMF, CardADF  # noqa: E402
from pySim.profile import CardProfile                              # noqa: E402
from pysim_fs_sphinx import EXCLUDED, SECTIONS                     # noqa: E402


class TestFsCoverage(unittest.TestCase):
    """Ensure SECTIONS + EXCLUDED together account for all classes with content."""

    # Base CardDF types that are not concrete filesystem objects on their own.
    _DF_BASE_TYPES = frozenset([CardDF, CardMF, CardADF])

    @staticmethod
    def _collect_reachable_df_types(obj) -> set:
        """Return the set of all CardDF *types* reachable as children of *obj*."""
        result = set()
        if isinstance(obj, CardProfile):
            children = obj.files_in_mf
        elif isinstance(obj, CardApplication):
            result.add(type(obj.adf))
            children = list(obj.adf.children.values())
        elif isinstance(obj, CardDF):
            children = list(obj.children.values())
        else:
            return result
        queue = list(children)
        while queue:
            child = queue.pop()
            if isinstance(child, CardDF):
                result.add(type(child))
                queue.extend(child.children.values())
        return result

    @staticmethod
    def _has_content(obj) -> bool:
        """Return True if *obj* owns any EFs/DFs."""
        if isinstance(obj, CardProfile):
            return bool(obj.files_in_mf)
        if isinstance(obj, CardApplication):
            return bool(obj.adf.children)
        return False

    def test_all_profiles_and_apps_covered(self):
        # build a set of (module, class-name) pairs that are already accounted for
        covered = {(mod, cls) for (_, mod, cls) in SECTIONS}
        accounted_for = covered | EXCLUDED

        uncovered = []
        reachable_df_types = set()
        loaded_modules = {}

        for modinfo in pkgutil.walk_packages(pySim.__path__, prefix='pySim.'):
            modname = modinfo.name
            try:
                module = importlib.import_module(modname)
            except Exception: # skip inport errors, if any
                continue
            loaded_modules[modname] = module

            for name, cls in inspect.getmembers(module, inspect.isclass):
                # skip classes that are merely imported by this module
                if cls.__module__ != modname:
                    continue
                # examine only subclasses of CardProfile and CardApplication
                if not issubclass(cls, (CardProfile, CardApplication)):
                    continue
                # skip the abstract base classes themselves
                if cls in (CardProfile, CardApplication):
                    continue
                # classes that require constructor arguments cannot be probed
                try:
                    obj = cls()
                except Exception:
                    continue

                # collect all CardDF types reachable from this profile/application
                # (used below to identify standalone DFs)
                reachable_df_types |= self._collect_reachable_df_types(obj)

                if self._has_content(obj) and (modname, name) not in accounted_for:
                    uncovered.append((modname, name))

        # check standalone CardDFs (such as DF.EIRENE or DF.SYSTEM)
        for modname, module in loaded_modules.items():
            for name, cls in inspect.getmembers(module, inspect.isclass):
                if cls.__module__ != modname:
                    continue
                if not issubclass(cls, CardDF):
                    continue
                if cls in self._DF_BASE_TYPES:
                    continue
                if cls in reachable_df_types:
                    continue
                try:
                    obj = cls()
                except Exception:
                    continue
                if obj.children and (modname, name) not in accounted_for:
                    uncovered.append((modname, name))

        if uncovered:
            lines = [
                'The following classes have EFs/DFs, but not listed in SECTIONS or EXCLUDED:',
                *(f'  {modname}.{name}' for modname, name in sorted(uncovered)),
                'Please modify docs/pysim_fs_sphinx.py accordingly',
            ]
            self.fail('\n'.join(lines))


if __name__ == '__main__':
    unittest.main()
