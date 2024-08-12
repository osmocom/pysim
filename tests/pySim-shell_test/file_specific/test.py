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
    def test_update_imsi_plmn(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_update_imsi_plmn.script", add_adm = True)
        self.assertEqualFiles("ef_imsi.tmp")

    def test_ef_ust(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_ef_ust.script", add_adm = True)
        self.assertEqualFiles("test_ef_ust.tmp")

    def test_ef_ist(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_ef_ist.script", add_adm = True)
        self.assertEqualFiles("test_ef_ist.tmp")

if __name__ == "__main__":
    unittest.main()
