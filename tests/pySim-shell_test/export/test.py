# Testsuite for pySim-shell.py
#
# (C) 2024 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier
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

import unittest
import os
from utils import *

class test_case(UnittestUtils):
    def test_export(self):
        cardname = 'sysmoISIM-SJA5-S17'

        # Generate an export script and verify it
        self.runPySimShell(cardname, "test_export.script")
        ignore_regex_list = [
            '^#.*$', # Ignore all generated comments
            ' [A-Fa-f0-9]*$', # Ignore hex-strings from update_record, update_binary
            '^aram_store_ref_ar_do.*' # Ignore ara-m config (already covered by testcase "export_adf_ara_m")
        ]
        self.assertEqualFiles("export.script.tmp",
                              ignore_regex_list=ignore_regex_list)

        # Try to import the export script we have just generated. Since there are no changes in the file contents,
        # we won't actually write the files, but we will verify that the generated script makes sense and can be
        # executed without causing exceptions.
        self.runPySimShell(cardname, "test_import.script", no_exceptions = True)


if __name__ == "__main__":
    unittest.main()
