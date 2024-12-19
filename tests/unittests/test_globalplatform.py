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
from pySim.global_platform.install_param import *

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
        self.assertEqual(b2h(init_upd_cmd).upper(), '805020000840A62C37FA6304F800')
        self.scp02.parse_init_update_resp(self.init_update_resp)
        ext_auth_cmd = self.scp02.gen_ext_auth_apdu()
        self.assertEqual(b2h(ext_auth_cmd).upper(), '8482010010BA6961667737C5BCEBECE14C7D6A4376')

    def test_mutual_auth_fail_card_cryptogram(self):
        init_upd_cmd = self.scp02.gen_init_update_apdu(host_challenge=self.host_challenge)
        self.assertEqual(b2h(init_upd_cmd).upper(), '805020000840A62C37FA6304F800')
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
        # Case #1: No command data field, No response data field present
        wrapped = self.scp02.wrap_cmd_apdu(h2b('80F22002'))
        self.assertEqual(b2h(wrapped).upper(), '84F220020814DB34FA4341DCA8')

        # Case #2: No command data field, Response data field present
        wrapped = self.scp02.wrap_cmd_apdu(h2b('80ca006600'))
        self.assertEqual(b2h(wrapped).upper(), '84CA00660855ED7C5FF069512B00')

        # Case #3: Command data field present, No response data field
        wrapped = self.scp02.wrap_cmd_apdu(h2b('80F220020a4f0212345c054f9f70c5'))
        self.assertEqual(b2h(wrapped).upper(), '84F22002124F0212345C054F9F70C58FC1B380C4228AF8')

        # Case #4: Command data field present, Response data field present
        wrapped = self.scp02.wrap_cmd_apdu(h2b('80f28002024f0000'))
        self.assertEqual(b2h(wrapped).upper(), '84F280020A4F003B95F09317DE6A4E00')


class SCP03_Test:
    """some kind of 'abstract base class' for a unittest.UnitTest, implementing common functionality for all
    of our SCP03 test caseses."""
    get_eid_cmd_plain = h2b('80E2910006BF3E035C015A00')
    get_eid_rsp_plain = h2b('bf3e125a1089882119900000000000000000000005')
    case_1_apdu_plain = h2b('80F22002')
    case_2_apdu_plain = h2b('80ca006600')
    case_3_apdu_plain = h2b('80F220020a4f0212345c054f9f70c5')
    case_4_apdu_plain = h2b('80f28002024f0000')

    # must be overridden by derived classes
    init_upd_cmd = b''
    init_upd_rsp = b''
    ext_auth_cmd = b''
    get_eid_cmd = b''
    get_eid_rsp = b''
    keyset = None

    @property
    def host_challenge(self) -> bytes:
        return self.init_upd_cmd[5:-1]

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

    def test_06_mac_command(self):
        # pylint: disable=no-member

        # Case #1: No command data field, No response data field present
        self.assertEqual(self.case_1_apdu, self.scp.wrap_cmd_apdu(self.case_1_apdu_plain))

        # Case #2: No command data field, Response data field present
        self.assertEqual(self.case_2_apdu, self.scp.wrap_cmd_apdu(self.case_2_apdu_plain))

        # Case #3: Command data field present, No response data field
        self.assertEqual(self.case_3_apdu, self.scp.wrap_cmd_apdu(self.case_3_apdu_plain))

        # Case #4: Command data field present, Response data field present
        self.assertEqual(self.case_4_apdu, self.scp.wrap_cmd_apdu(self.case_4_apdu_plain))


# The SCP03 keysets used for various key lenghs
KEYSET_AES128 = GpCardKeyset(0x30, h2b('000102030405060708090a0b0c0d0e0f'), h2b('101112131415161718191a1b1c1d1e1f'), h2b('202122232425262728292a2b2c2d2e2f'))
KEYSET_AES192 = GpCardKeyset(0x31, h2b('000102030405060708090a0b0c0d0e0f0001020304050607'),
                             h2b('101112131415161718191a1b1c1d1e1f1011121314151617'), h2b('202122232425262728292a2b2c2d2e2f2021222324252627'))
KEYSET_AES256 = GpCardKeyset(0x32, h2b('000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f'),
                             h2b('101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f'),
                             h2b('202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f'))

class SCP03_Test_AES128_11(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES128
    init_upd_cmd = h2b('8050300008b13e5f938fc108c400')
    init_upd_rsp = h2b('000000000000000000003003703eb51047495b249f66c484c1d2ef1948000002')
    ext_auth_cmd = h2b('84821100107d5f5826a993ebc89eea24957fa0b3ce')
    get_eid_cmd = h2b('84e291000ebf3e035c015a558d036518a2829700')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005971be68992dbbdfa')
    case_1_apdu = h2b('84f220020863a63f8959827fb2')
    case_2_apdu = h2b('84ca006608a0c6a4a74166f7ce00')
    case_3_apdu = h2b('84f22002124f0212345c054f9f70c52249b50272656536')
    case_4_apdu = h2b('84f280020a4f00e91443f6dce6b8ed00')

class SCP03_Test_AES128_03(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES128
    init_upd_cmd = h2b('80503000088e1552d0513c60f300')
    init_upd_rsp = h2b('0000000000000000000030037030760cd2c47c1dd395065fe5ead8a9d7000001')
    ext_auth_cmd = h2b('8482030010fd4721a14d9b07003c451d2f8ae6bb21')
    get_eid_cmd = h2b('84e2910018ca9c00f6713d79bc8baa642bdff51c3f6a4082d3bd9ad26c00')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005')
    case_1_apdu = h2b('84f2200208c9811b11f1264cf1')
    case_2_apdu = h2b('84ca006608e10ab60b3054798800')
    case_3_apdu = h2b('84f22002184e2908bdb48b2315a55482e9e936ca122d6ecfae7d17416e')
    case_4_apdu = h2b('84f28002180dd10a6b6193e5340b9e77d32d5a179cd710ac2773aefb2800')

class SCP03_Test_AES128_33(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES128
    init_upd_cmd = h2b('8050300008fdf38259a1e0de4400')
    init_upd_rsp = h2b('000000000000000000003003703b1aca81e821f219081cdc01c26b372d000003')
    ext_auth_cmd = h2b('84823300108c36f96bcc00724a4e13ad591d7da3f0')
    get_eid_cmd = h2b('84e2910018267a85dfe4a98fca6fb0527e0dfecce4914e40401433c87f00')
    get_eid_rsp = h2b('f3ba2b1013aa6224f5e1c138d71805c569e5439b47576260b75fc021b25097cb2e68f8a0144975b9')
    case_1_apdu = h2b('84f2200208ac6a59024bed84cc')
    case_2_apdu = h2b('84ca006608409912ad8fb7aed000')
    case_3_apdu = h2b('84f22002185f3dafc3ac14c381536a488bf44e06d056df9d74dbd21e5a')
    case_4_apdu = h2b('84f280021865165105be3373347d0424d4400af2ac393f569ec779389e00')

class SCP03_Test_AES192_11(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES192
    init_upd_cmd = h2b('80503100087396430b768b085b00')
    init_upd_rsp = h2b('000000000000000000003103708cfc23522ffdbf1e5df5542cac8fd866000003')
    ext_auth_cmd = h2b('84821100102145ed30b146f5db252fb7e624cec244')
    get_eid_cmd = h2b('84e291000ebf3e035c015aff42cf801d14394400')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005162fbd33e04940a9')
    case_1_apdu = h2b('84f22002084584e4f6784811ee')
    case_2_apdu = h2b('84ca006608937776ebe190fa3000')
    case_3_apdu = h2b('84f22002124f0212345c054f9f70c59a52bddf3040368c')
    case_4_apdu = h2b('84f280020a4f009804b11411f7393d00')

class SCP03_Test_AES192_03(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES192
    init_upd_cmd = h2b('805031000869c65da8202bf19f00')
    init_upd_rsp = h2b('00000000000000000000310370b570a67be38446717729d6dd3d2ec5b1000001')
    ext_auth_cmd = h2b('848203001065df4f1a356a887905466516d9e5b7c1')
    get_eid_cmd = h2b('84e2910018d2c6fb477c5d4afe4fd4d21f17eff10d3578ec1774a12a2d00')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005')
    case_1_apdu = h2b('84f2200208964e188f0b1bb697')
    case_2_apdu = h2b('84ca006608f0820035a41d3e1800')
    case_3_apdu = h2b('84f220021806b076ed452cd1fa84f77f5c08a146aa77a9286757dea791')
    case_4_apdu = h2b('84f2800218d06527e39222dce091fabdb8e9b898417a67a6852d3577db00')

class SCP03_Test_AES192_33(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES192
    init_upd_cmd = h2b('80503100089b3f2eef0e8c937400')
    init_upd_rsp = h2b('00000000000000000000310370f6bb305a15bae1a68f79fb08212fbed7000002')
    ext_auth_cmd = h2b('84823300109100bc22d58b45b86a26365ce39ff3cf')
    get_eid_cmd = h2b('84e29100188f7f946c84f70d17994bc6e8791251bb1bb1bf02cf8de58900')
    get_eid_rsp = h2b('c05176c1b6f72aae50c32cbee63b0e95998928fd4dfb2be9f27ffde8c8476f5909b4805cc4039599')
    case_1_apdu = h2b('84f2200208d5d97754b6b3d2ba')
    case_2_apdu = h2b('84ca006608516c82b8e30adbeb00')
    case_3_apdu = h2b('84f2200218cc247f4761e6944277a4e0d6e32e44025b1e31537e2fc668')
    case_4_apdu = h2b('84f2800218ba22b63d509bef5d093b43e5eaed03ed23144ab2d9cb51de00')

class SCP03_Test_AES256_11(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES256
    init_upd_cmd = h2b('805032000811666d57866c6f5400')
    init_upd_rsp = h2b('0000000000000000000032037053ea8847efa7674e41498a4d66cf0dee000003')
    ext_auth_cmd = h2b('84821100102f2ad190eff2fafc4908996d1cebd310')
    get_eid_cmd = h2b('84e291000ebf3e035c015af4b680372542b59d00')
    get_eid_rsp = h2b('bf3e125a10898821199000000000000000000000058012dd7f01f1c4c1')
    case_1_apdu = h2b('84f2200208d618b7da68d5fe52')
    case_2_apdu = h2b('84ca0066088f3e055db23ad5e500')
    case_3_apdu = h2b('84f22002124f0212345c054f9f70c5b6e15cc42404915e')
    case_4_apdu = h2b('84f280020a4f00aa124aa74afe7f7500')

class SCP03_Test_AES256_03(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES256
    init_upd_cmd = h2b('8050320008c6066990fc426e1d00')
    init_upd_rsp = h2b('000000000000000000003203708682cd81bbd8919f2de3f2664581f118000001')
    ext_auth_cmd = h2b('848203001077c493b632edadaf865a1e64acc07ce9')
    get_eid_cmd = h2b('84e29100183ddaa60594963befaada3525b492ede23c2ab2c1ce3afe4400')
    get_eid_rsp = h2b('bf3e125a1089882119900000000000000000000005')
    case_1_apdu = h2b('84f2200208480ddc8e419da38d')
    case_2_apdu = h2b('84ca0066083e9d6a6c0b2d732000')
    case_3_apdu = h2b('84f22002183ebfef2da8b04af2a85f491f299b76973df76ff08a4031be')
    case_4_apdu = h2b('84f2800218783fff80990f5585b1055010ea95094a26e4a8f1ef4b18e100')

class SCP03_Test_AES256_33(SCP03_Test, unittest.TestCase):
    keyset = KEYSET_AES256
    init_upd_cmd = h2b('805032000897b2055fe58599fd00')
    init_upd_rsp = h2b('00000000000000000000320370a8439a22cedf045fa9f1903b2834f26e000002')
    ext_auth_cmd = h2b('8482330010508a0fd959d2e547c6b33154a6be2057')
    get_eid_cmd = h2b('84e29100187a5ef717eaf1e135ae92fe54429d0e465decda65f5fe5aea00')
    get_eid_rsp = h2b('ea90dbfa648a67c5eb6abc57f8530b97d0cd5647c5e8732016b55203b078dd2ace7f8bc5d1c1cd99')
    case_1_apdu = h2b('84f2200208bcc5c17275545d93')
    case_2_apdu = h2b('84ca00660804806aba9d543bb600')
    case_3_apdu = h2b('84f2200218717222491556ec81a45f49ce48be33320024801a1c4cb0e0')
    case_4_apdu = h2b('84f2800218561f105bccd3a1642904b251ccc1228beb80a82370a8637000')

# FIXME:
#  - for S8 and S16 mode
# FIXME: test auth with random (0x60) vs pseudo-random (0x70) challenge


class SCP03_KCV_Test(unittest.TestCase):
    def test_kcv(self):
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.enc), h2b('C35280'))
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.mac), h2b('013808'))
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.dek), h2b('840DE5'))


class Install_param_Test(unittest.TestCase):
    def test_gen_install_parameters(self):
        load_parameters = gen_install_parameters(256, 256, '010001001505000000000000000000000000')
        self.assertEqual(load_parameters, 'c900ef1cc8020100c7020100ca12010001001505000000000000000000000000')

        load_parameters = gen_install_parameters(None, None, '')
        self.assertEqual(load_parameters, 'c900')

if __name__ == "__main__":
	unittest.main()
