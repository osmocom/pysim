#!/usr/bin/env python3

# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
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
import logging

from pySim.global_platform import *
from pySim.global_platform.scp02 import SCP02
from pySim.utils import b2h, h2b

KIC = h2b('100102030405060708090a0b0c0d0e0f') # enc
KID = h2b('101102030405060708090a0b0c0d0e0f') # MAC
KIK = h2b('102102030405060708090a0b0c0d0e0f') # DEK
ck_3des_70 = GpCardKeyset(0x20, KIC, KID, KIK)

class SCP02_Auth_Test(unittest.TestCase):
    host_challenge = h2b('40A62C37FA6304F8')
    init_update_resp = h2b('00000000000000000000700200016B4524ABEE7CF32EA3838BC148F3')

    def setUp(self):
        self.scp02 = SCP02(card_keys=ck_3des_70)

    def test_mutual_auth_success(self):
        init_upd_cmd = self.scp02.gen_init_update_apdu(host_challenge=self.host_challenge)
        self.assertEqual(b2h(init_upd_cmd).upper(), '805020000840A62C37FA6304F8')
        self.scp02.parse_init_update_resp(self.init_update_resp)
        ext_auth_cmd = self.scp02.gen_ext_auth_apdu()
        self.assertEqual(b2h(ext_auth_cmd).upper(), '8482010010BA6961667737C5BCEBECE14C7D6A4376')

    def test_mutual_auth_fail_card_cryptogram(self):
        init_upd_cmd = self.scp02.gen_init_update_apdu(host_challenge=self.host_challenge)
        self.assertEqual(b2h(init_upd_cmd).upper(), '805020000840A62C37FA6304F8')
        wrong_init_update_resp = self.init_update_resp.copy()
        wrong_init_update_resp[-1:] = b'\xff'
        with self.assertRaises(ValueError):
            self.scp02.parse_init_update_resp(wrong_init_update_resp)


class SCP02_Test(unittest.TestCase):
    host_challenge = h2b('40A62C37FA6304F8')
    init_update_resp = h2b('00000000000000000000700200016B4524ABEE7CF32EA3838BC148F3')

    def setUp(self):
        self.scp02 = SCP02(card_keys=ck_3des_70)
        init_upd_cmd = self.scp02.gen_init_update_apdu(host_challenge=self.host_challenge)
        self.scp02.parse_init_update_resp(self.init_update_resp)
        ext_auth_cmd = self.scp02.gen_ext_auth_apdu()

    def test_mac_command(self):
        wrapped = self.scp02.wrap_cmd_apdu(h2b('80f28002024f00'))
        self.assertEqual(b2h(wrapped).upper(), '84F280020A4F00B21AAFA3EB2D1672')

if __name__ == "__main__":
	unittest.main()
