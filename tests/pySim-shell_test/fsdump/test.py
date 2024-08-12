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
    def test(self):
        cardname = 'sysmoISIM-SJA5-S17'

        self.runPySimShell(cardname, "test.script")

        # Try to load/parse the resulting json file to verify that the resulting JSON file is well formed
        fsdump_json = open("fsdump.json.tmp")
        json.load(fsdump_json)
        fsdump_json.close()

        # TODO: create a JSON schema and validate the contents of fsdump.json.tmp against it

        # Ignore hex-strings sine we are not so much interested in the actual contents
        ignore_regex_list = ['\"[A-Fa-f0-9]*\",', '\"[A-Fa-f0-9]*\"']
        self.assertEqualFiles("fsdump.json.tmp",
                              ignore_regex_list=ignore_regex_list)

if __name__ == "__main__":
    unittest.main()
