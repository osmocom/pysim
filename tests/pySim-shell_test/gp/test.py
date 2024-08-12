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
    def test_est_scp02_direct(self):
        cardnames = ['sysmoISIM-SJA5-S17', 'sysmoISIM-SJA2']

        for cardname in cardnames:
            key_dek = self.cards[cardname]['SCP02_DEK_1'] #kik1
            key_enc = self.cards[cardname]['SCP02_ENC_1'] #kic1
            key_mac = self.cards[cardname]['SCP02_MAC_1'] #kid1
            self.equipTemplate("test_est_scp02_direct.script",
                               KEY_DEK = key_dek, KEY_ENC = key_enc, KEY_MAC = key_mac)
            self.runPySimShell(cardname, "test_est_scp02_direct.script", no_exceptions = True)

    def test_est_scp02_csv(self):
        cardnames = ['sysmoISIM-SJA5-S17', 'sysmoISIM-SJA2']

        for cardname in cardnames:
            self.runPySimShell(cardname, "test_est_scp02_csv.script", no_exceptions = True, add_csv = True)

    def test_est_scp03_direct(self):
        cardname = 'sysmoEUICC1-C2T'

        key_dek = self.cards[cardname]['SCP03_DEK_1'] #kik1
        key_enc = self.cards[cardname]['SCP03_ENC_1'] #kic1
        key_mac = self.cards[cardname]['SCP03_MAC_1'] #kid1
        self.equipTemplate("test_est_scp03_direct.script",
                           KEY_DEK = key_dek, KEY_ENC = key_enc, KEY_MAC = key_mac)
        self.runPySimShell(cardname, "test_est_scp03_direct.script", no_exceptions = True)

    def test_est_scp03_csv(self):
        cardname = 'sysmoEUICC1-C2T'

        self.runPySimShell(cardname, "test_est_scp03_csv.script", no_exceptions = True, add_csv = True)

    def test_put_delete_key(self):
        # TODO: It might be helpful to run this test on an sysmoISIM-SJA5-S17 uicc as well, but unfortunately those
        # cards do not have enough memory for another keyset. We would have to resize the space for the key storage
        # first, or we would have to delete one keyset first. Both options are not very attractive.
        cardname = 'sysmoEUICC1-C2T'

        self.runPySimShell(cardname, "test_put_delete_key.script", no_exceptions = True, add_csv = True)
        self.assertEqualFiles("key_information.tmp",
                              ignore_regex_list = ['.*'],
                              interesting_regex_list = ['.*42.*'])

    def test_get_status(self):
        cardname = 'sysmoEUICC1-C2T'

        self.runPySimShell(cardname, "test_get_status.script", no_exceptions = True, add_csv = True)
        self.assertEqualFiles("get_status_isd.tmp")

if __name__ == "__main__":
    unittest.main()
