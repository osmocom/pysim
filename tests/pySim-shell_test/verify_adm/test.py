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
    def test(self):
        cardname = 'sysmoISIM-SJA5-S17'
        adm1 = self.cards[cardname]['adm1']

        # Provide ADM pin via commandline on startup
        self.runPySimShell(cardname, "test_cmdline.script", add_adm = True, no_exceptions = True)

        # Provide ADM pin via CSV file (CardKeyProvider)
        self.runPySimShell(cardname, "test_csv.script", add_csv = True, no_exceptions = True)

        # Privide ADM pin via direct input
        self.equipTemplate("test_direct.script", ADM=adm1)
        self.runPySimShell(cardname, "test_direct.script", no_exceptions = True)

if __name__ == "__main__":
    unittest.main()
