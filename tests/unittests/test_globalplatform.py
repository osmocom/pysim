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
from osmocom.utils import b2h, h2b

from pySim.global_platform import *
from pySim.global_platform.scp import *

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


class SCP03_Test:
    """some kind of 'abstract base class' for a unittest.UnitTest, implementing common functionality for all
    of our SCP03 test caseses."""
    get_eid_cmd_plain = h2b('80E2910006BF3E035C015A')
    get_eid_rsp_plain = h2b('bf3e125a1089882119900000000000000000000005')

    # must be overridden by derived classes
    init_upd_cmd = b''
    init_upd_rsp = b''
    ext_auth_cmd = b''
    get_eid_cmd = b''
    get_eid_rsp = b''
    keyset = None

    @property
    def host_challenge(self) -> bytes:
        return self.init_upd_cmd[5:]

    @property
    def kvn(self) -> int:
        return self.init_upd_cmd[2]

    @property
    def security_level(self) -> int:
        return self.ext_auth_cmd[2]

    @property
    def card_challenge(self) -> bytes:
        if len(self.init_upd_rsp) in [10+3+8+8, 10+3+8+8+3]:
            return self.init_upd_rsp[10+3:10+3+8]
        else:
            return self.init_upd_rsp[10+3:10+3+16]

    @property
    def card_cryptogram(self) -> bytes:
        if len(self.init_upd_rsp) in [10+3+8+8, 10+3+8+8+3]:
            return self.init_upd_rsp[10+3+8:10+3+8+8]
        else:
            return self.init_upd_rsp[10+3+16:10+3+16+16]

    @classmethod
    def setUpClass(cls):
        cls.scp = SCP03(card_keys = cls.keyset)

    def test_01_initialize_update(self):
        # pylint: disable=no-member
        self.assertEqual(self.init_upd_cmd, self.scp.gen_init_update_apdu(self.host_challenge))

    def test_02_parse_init_upd_resp(self):
        self.scp.parse_init_update_resp(self.init_upd_rsp)

    def test_03_gen_ext_auth_apdu(self):
        # pylint: disable=no-member
        self.assertEqual(self.ext_auth_cmd, self.scp.gen_ext_auth_apdu(self.security_level))

    def test_04_wrap_cmd_apdu_get_eid(self):
        # pylint: disable=no-member
        self.assertEqual(self.get_eid_cmd, self.scp.wrap_cmd_apdu(self.get_eid_cmd_plain))

    def test_05_unwrap_rsp_apdu_get_eid(self):
        # pylint: disable=no-member
        self.assertEqual(self.get_eid_rsp_plain, self.scp.unwrap_rsp_apdu(h2b('9000'), self.get_eid_rsp))


# The SCP03 keysets used for various key lenghs
KEYSET_AES128 = GpCardKeyset(0x30, h2b('000102030405060708090a0b0c0d0e0f'), h2b('101112131415161718191a1b1c1d1e1f'), h2b('202122232425262728292a2b2c2d2e2f'))
KEYSET_AES192 = GpCardKeyset(0x31, h2b('000102030405060708090a0b0c0d0e0f0001020304050607'),
                             h2b('101112131415161718191a1b1c1d1e1f1011121314151617'), h2b('202122232425262728292a2b2c2d2e2f2021222324252627'))
KEYSET_AES256 = GpCardKeyset(0x32, h2b('000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f'),
                             h2b('101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f'),
                             h2b('202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f'))

class SCP03_Test_AES128_11(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES128
    init_upd_cmd = h2b('8050300008b13e5f938fc108c4')
    init_upd_rsp = h2b('000000000000000000003003703eb51047495b249f66c484c1d2ef1948000002')
    ext_auth_cmd = h2b('84821100107d5f5826a993ebc89eea24957fa0b3ce')
    get_eid_cmd = h2b('84e291000ebf3e035c015a558d036518a28297')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005971be68992dbbdfa')

class SCP03_Test_AES128_03(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES128
    init_upd_cmd = h2b('80503000088e1552d0513c60f3')
    init_upd_rsp = h2b('0000000000000000000030037030760cd2c47c1dd395065fe5ead8a9d7000001')
    ext_auth_cmd = h2b('8482030010fd4721a14d9b07003c451d2f8ae6bb21')
    get_eid_cmd = h2b('84e2910018ca9c00f6713d79bc8baa642bdff51c3f6a4082d3bd9ad26c')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005')

class SCP03_Test_AES128_33(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES128
    init_upd_cmd = h2b('8050300008fdf38259a1e0de44')
    init_upd_rsp = h2b('000000000000000000003003703b1aca81e821f219081cdc01c26b372d000003')
    ext_auth_cmd = h2b('84823300108c36f96bcc00724a4e13ad591d7da3f0')
    get_eid_cmd = h2b('84e2910018267a85dfe4a98fca6fb0527e0dfecce4914e40401433c87f')
    get_eid_rsp = h2b('f3ba2b1013aa6224f5e1c138d71805c569e5439b47576260b75fc021b25097cb2e68f8a0144975b9')

class SCP03_Test_AES192_11(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES192
    init_upd_cmd = h2b('80503100087396430b768b085b')
    init_upd_rsp = h2b('000000000000000000003103708cfc23522ffdbf1e5df5542cac8fd866000003')
    ext_auth_cmd = h2b('84821100102145ed30b146f5db252fb7e624cec244')
    get_eid_cmd = h2b('84e291000ebf3e035c015aff42cf801d143944')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005162fbd33e04940a9')

class SCP03_Test_AES192_03(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES192
    init_upd_cmd = h2b('805031000869c65da8202bf19f')
    init_upd_rsp = h2b('00000000000000000000310370b570a67be38446717729d6dd3d2ec5b1000001')
    ext_auth_cmd = h2b('848203001065df4f1a356a887905466516d9e5b7c1')
    get_eid_cmd = h2b('84e2910018d2c6fb477c5d4afe4fd4d21f17eff10d3578ec1774a12a2d')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005')

class SCP03_Test_AES192_33(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES192
    init_upd_cmd = h2b('80503100089b3f2eef0e8c9374')
    init_upd_rsp = h2b('00000000000000000000310370f6bb305a15bae1a68f79fb08212fbed7000002')
    ext_auth_cmd = h2b('84823300109100bc22d58b45b86a26365ce39ff3cf')
    get_eid_cmd = h2b('84e29100188f7f946c84f70d17994bc6e8791251bb1bb1bf02cf8de589')
    get_eid_rsp = h2b('c05176c1b6f72aae50c32cbee63b0e95998928fd4dfb2be9f27ffde8c8476f5909b4805cc4039599')

class SCP03_Test_AES256_11(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES256
    init_upd_cmd = h2b('805032000811666d57866c6f54')
    init_upd_rsp = h2b('0000000000000000000032037053ea8847efa7674e41498a4d66cf0dee000003')
    ext_auth_cmd = h2b('84821100102f2ad190eff2fafc4908996d1cebd310')
    get_eid_cmd = h2b('84e291000ebf3e035c015af4b680372542b59d')
    get_eid_rsp = h2b('bf3e125a10898821199000000000000000000000058012dd7f01f1c4c1')

class SCP03_Test_AES256_03(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES256
    init_upd_cmd = h2b('8050320008c6066990fc426e1d')
    init_upd_rsp = h2b('000000000000000000003203708682cd81bbd8919f2de3f2664581f118000001')
    ext_auth_cmd = h2b('848203001077c493b632edadaf865a1e64acc07ce9')
    get_eid_cmd = h2b('84e29100183ddaa60594963befaada3525b492ede23c2ab2c1ce3afe44')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005')

class SCP03_Test_AES256_33(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES256
    init_upd_cmd = h2b('805032000897b2055fe58599fd')
    init_upd_rsp = h2b('00000000000000000000320370a8439a22cedf045fa9f1903b2834f26e000002')
    ext_auth_cmd = h2b('8482330010508a0fd959d2e547c6b33154a6be2057')
    get_eid_cmd = h2b('84e29100187a5ef717eaf1e135ae92fe54429d0e465decda65f5fe5aea')
    get_eid_rsp = h2b('ea90dbfa648a67c5eb6abc57f8530b97d0cd5647c5e8732016b55203b078dd2ace7f8bc5d1c1cd99')

# FIXME:
#  - for S8 and S16 mode
# FIXME: test auth with random (0x60) vs pseudo-random (0x70) challenge


class SCP03_KCV_Test(unittest.TestCase):
    def test_kcv(self):
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.enc), h2b('C35280'))
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.mac), h2b('013808'))
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.dek), h2b('840DE5'))


if __name__ == "__main__":
	unittest.main()
