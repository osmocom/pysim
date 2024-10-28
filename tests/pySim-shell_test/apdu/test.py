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

    def test_apdu_legacy(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_apdu_legacy.script", no_exceptions = True)

    def test_apdu_legacy_scp02(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.equipTemplate("test_apdu_legacy_scp02.script", SEC_LEVEL = 3)
        self.runPySimShell(cardname, "test_apdu_legacy_scp02.script", no_exceptions = True, add_csv = True)
        self.equipTemplate("test_apdu_legacy_scp02.script", SEC_LEVEL = 1)
        self.runPySimShell(cardname, "test_apdu_legacy_scp02.script", no_exceptions = True, add_csv = True)

    def test_apdu_legacy_scp03(self):
        cardname = 'sysmoEUICC1-C2T'

        self.equipTemplate("test_apdu_legacy_scp03.script", SEC_LEVEL = 3)
        self.runPySimShell(cardname, "test_apdu_legacy_scp03.script", no_exceptions = True, add_csv = True)
        self.equipTemplate("test_apdu_legacy_scp03.script", SEC_LEVEL = 1)
        self.runPySimShell(cardname, "test_apdu_legacy_scp03.script", no_exceptions = True, add_csv = True)

    def test_apdu(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test_apdu.script", no_exceptions = True)

    def test_apdu_legacy_scp02(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.equipTemplate("test_apdu_scp02.script", SEC_LEVEL = 3)
        self.runPySimShell(cardname, "test_apdu_scp02.script", no_exceptions = True, add_csv = True)
        self.equipTemplate("test_apdu_scp02.script", SEC_LEVEL = 1)
        self.runPySimShell(cardname, "test_apdu_scp02.script", no_exceptions = True, add_csv = True)

    def test_apdu_legacy_scp03(self):
        cardname = 'sysmoEUICC1-C2T'

        self.equipTemplate("test_apdu_scp03.script", SEC_LEVEL = 3)
        self.runPySimShell(cardname, "test_apdu_scp03.script", no_exceptions = True, add_csv = True)
        self.equipTemplate("test_apdu_scp03.script", SEC_LEVEL = 1)
        self.runPySimShell(cardname, "test_apdu_scp03.script", no_exceptions = True, add_csv = True)

if __name__ == "__main__":
    unittest.main()
