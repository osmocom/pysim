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

# This testcase requires a sysmoEUICC1-C2T with the test prfile TS48V1-B-UNIQUE (ICCID 8949449999999990031f)
# installed, and in disabled state. Also the profile must be installed in such a way that notifications are
# generated when the profile is disabled or enabled (ProfileMetadata)

class test_case(UnittestUtils):
    def test_get_eid(self):
        cardname = 'sysmoEUICC1-C2T'

        self.runPySimShell(cardname, "test_get_eid.script")
        self.assertEqualFiles("get_eid.tmp",
                              ignore_regex_list=['\"[A-Fa-f0-9]*\"'])

    def test_get_euicc_info(self):
        cardname = 'sysmoEUICC1-C2T'

        self.runPySimShell(cardname, "test_get_euicc_info.script")
        self.assertEqualFiles("euicc_info1.tmp",
                              ignore_regex_list=[': \".*"'])
        self.assertEqualFiles("euicc_info2.tmp", "euicc_info2.ok",
                              ignore_regex_list=[': \".*"'])

    def test_get_profiles_info(self):
        cardname = 'sysmoEUICC1-C2T'

        self.runPySimShell(cardname, "test_get_profiles_info.script")
        self.assertEqualFiles("get_profiles_info.tmp")

    def test_enable_disable_profile(self):
        cardname = 'sysmoEUICC1-C2T'

        self.runPySimShell(cardname, "test_enable_disable_profile.script")
        self.assertEqualFiles("enable_disable_profile.tmp")

    def test_enable_disable_profile(self):
        cardname = 'sysmoEUICC1-C2T'

        self.runPySimShell(cardname, "test_set_nickname.script")
        self.assertEqualFiles("set_nickname.tmp")

    def test_list_and_rm_notif(self):
        cardname = 'sysmoEUICC1-C2T'

        # Generate two (additional) notification
        self.runPySimShell(cardname, "test_gen_notif.script")

        # List notifications into a file
        self.runPySimShell(cardname, "test_list_notif.script")

        # Parse notifications file (JSON)
        notifications_tmp = open("notifications.tmp")
        notifications = json.load(notifications_tmp)
        notifications_tmp.close()

        # Delete notifications one by one, we expect to see at least one notification
        notification_metadata_list = notifications['notification_metadata_list']
        removed = 0
        for nm in notification_metadata_list:
            seq_number = nm['notification_metadata']['seq_number']
            print("removing notification with seq_number %s:" % seq_number)
            self.equipTemplate("test_rm_notif.script", SEQ_NUMBER = seq_number)
            self.runPySimShell(cardname, "test_rm_notif.script")
            removed = removed + 1
        self.assertTrue(removed >= 2, "we expected to remove at least two notifications, but we have removed none!")

        # List notifications again, require none to be present
        self.runPySimShell(cardname, "test_list_notif.script")
        self.assertEqualFiles("notifications.tmp")

if __name__ == "__main__":
    unittest.main()
