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
import json
from utils import *

class test_case(UnittestUtils):
    def test_activate_deactivate(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_activate_deactivate_file.script", add_adm = True)
        self.assertEqualFiles("activate_deactivate_file.tmp",
                              ignore_regex_list = ['.*'],
                              interesting_regex_list = ['.*"life_cycle_status_integer.*"'])

    def test_create_delete_df(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_create_delete_df.script",
                           add_adm = True, no_exceptions = True)

    def test_create_resize_delete_transparent_ef(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_create_resize_delete_transparent_ef.script",
                           add_adm = True, no_exceptions = True)

    def test_create_resize_delete_linear_fixed_ef(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_create_resize_delete_linear_fixed_ef.script",
                           add_adm = True, no_exceptions = True)

if __name__ == "__main__":
    unittest.main()
