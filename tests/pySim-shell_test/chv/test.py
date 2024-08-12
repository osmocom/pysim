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
    def test_manage(self):
        cardname = 'sysmoISIM-SJA5-S17'
        pin1 = self.cards[cardname]['pin1']
        puk1 = self.cards[cardname]['puk1']

        # Provide PIN via commandline directly
        self.equipTemplate("test_manage_direct.script", PIN1=pin1)
        self.runPySimShell(cardname, "test_manage_direct.script")
        self.assertEqualFiles("test_manage_direct.tmp")
        os.remove("test_manage_direct.script")

        # Provide PIN via CSV file (CardKeyProvider)
        self.equipTemplate("test_manage_csv.script", PIN1=pin1)
        self.runPySimShell(cardname, "test_manage_csv.script", add_csv = True)
        ignore_regex_list = ['\'[A-Fa-f0-9]*\''] # do not compare the actual PIN and ICCID values echoed by the commands
        self.assertEqualFiles("test_manage_csv.tmp",
                              ignore_regex_list=ignore_regex_list)

    def test_unblock(self):
        cardname = 'sysmoISIM-SJA5-S17'
        pin1 = self.cards[cardname]['pin1']
        puk1 = self.cards[cardname]['puk1']

        # Provide PIN via commandline directly
        self.equipTemplate("test_unblock_direct.script", PIN1=pin1, PUK1=puk1)
        self.runPySimShell(cardname, "test_unblock_direct.script")
        self.assertEqualFiles("test_unblock_direct.tmp")

        # Provide PIN via CSV file (CardKeyProvider)
        self.runPySimShell(cardname, "test_unblock_csv.script", add_csv = True)
        ignore_regex_list = ['\'[A-Fa-f0-9]*\''] # do not compare the actual PIN and ICCID values echoed by the commands
        self.assertEqualFiles("test_unblock_csv.tmp",
                              ignore_regex_list=ignore_regex_list)

if __name__ == "__main__":
    unittest.main()
