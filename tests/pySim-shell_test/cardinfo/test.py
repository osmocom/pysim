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
        for cardname in self.cards:
            self.equipTemplate("test.script", CARDNAME=cardname)
            self.runPySimShell(cardname, "test.script")
            self.assertEqualFiles(cardname + "-cardinfo.tmp",
                                  mask_regex_list = [' [A-Fa-f0-9]*$'],
                                  interesting_regex_list = ['^  a0.*', '^ ATR.*', '^ Cla.*', '^ Sel.*'])

if __name__ == "__main__":
    unittest.main()
