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
import hashlib
from types import SimpleNamespace
from osmocom.utils import b2h, h2b
from osmocom.tlv import bertlv_encode_len

from pySim.global_platform import *
from pySim.global_platform.scp import *
from pySim.global_platform.install_param import gen_install_parameters

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


class KeyComponentBlock_Test(unittest.TestCase):
    """Tests for the kcb of GP CardSpec v2.3
    - Table 11-70 kcv that required padding, preceded by its clear-text length
    - Table 11-71 no padding required"""

    def setUp(self):
        # SCP02 (3DES DEK, 8 byte blocks), same vectors as SCP02_Test
        self.scp02 = SCP02(card_keys=ck_3des_70)
        self.scp02.gen_init_update_apdu(host_challenge=h2b('40A62C37FA6304F8'))
        self.scp02.parse_init_update_resp(h2b('00000000000000000000700200016B4524ABEE7CF32EA3838BC148F3'))
        self.scp02.gen_ext_auth_apdu()
        # SCP03 (AES DEK, 16 byte blocks), same vectors as SCP03_Test_AES128_11
        self.scp03 = SCP03(card_keys=KEYSET_AES128)
        self.scp03.gen_init_update_apdu(h2b('b13e5f938fc108c4'))
        self.scp03.parse_init_update_resp(h2b('000000000000000000003003703eb51047495b249f66c484c1d2ef1948000002'))
        self.scp03.gen_ext_auth_apdu(0x11)

    def test_encrypt_decrypt_key(self):
        for scp in (self.scp02, self.scp03):
            bs = scp.sk.blocksize
            for keylen in range(1, 3 * bs + 1):
                with self.subTest(scp=type(scp).__name__, keylen=keylen):
                    key = bytes(range(keylen))
                    kcb = scp.encrypt_key(key)
                    if keylen % bs:
                        # Table 11-70: <length of clear key component> || <encrypted padded value>
                        self.assertEqual(kcb[0], keylen)
                        self.assertEqual((len(kcb) - 1) % bs, 0)
                        self.assertEqual(len(kcb) - 1, keylen + (bs - keylen % bs))
                    else:
                        # Table 11-71: only the encrypted key component value
                        self.assertEqual(len(kcb), keylen)
                    self.assertEqual(scp.decrypt_key(kcb), key)


class SCP03_KCV_Test(unittest.TestCase):
    def test_kcv(self):
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.enc), h2b('C35280'))
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.mac), h2b('013808'))
        self.assertEqual(compute_kcv('aes', KEYSET_AES128.dek), h2b('840DE5'))


class PutKey_PSK_Test(unittest.TestCase):
    """Tests for the PUT KEY command data field encoding, in particular the PSK TLS ('85') key data
    field defined by GlobalPlatform Amendment B (Remote Application Management over HTTP) Table 3-13."""

    # the PUT KEY encoder we exercise
    C = ADF_SD.AddlShellCommands

    # SCP80 TLS-PSK example key from the do_put_key docstring (16 bytes)
    PSK_CLEAR = h2b('303132333435363738393a3b3c3d3e3f')
    # its DEK ciphertext + Table 3-13 KCV with SCP02 session set up below
    PSK_CIPHERED = h2b('15abf1fe16ccc5aa13743394442942cd')
    PSK_KCV = h2b('06125d')  # = SHA-1(PSK_CLEAR)[:3]

    def setUp(self):
        # SCP02 with the same vectors as SCP02_Test, so that the whole PUT KEY data field is reproducible.
        self.scp02 = SCP02(card_keys=ck_3des_70)
        self.scp02.gen_init_update_apdu(host_challenge=h2b('40A62C37FA6304F8'))
        self.scp02.parse_init_update_resp(h2b('00000000000000000000700200016B4524ABEE7CF32EA3838BC148F3'))
        self.scp02.gen_ext_auth_apdu()

    def test_psk_kcv_is_sha1(self):
        # GP Amendment B Table 3-13: KCV = 3 most significant bytes of SHA-1(clear key)
        self.assertEqual(compute_kcv('tls_psk', self.PSK_CLEAR), hashlib.sha1(self.PSK_CLEAR).digest()[:3])
        self.assertEqual(compute_kcv('tls_psk', self.PSK_CLEAR), self.PSK_KCV)

    def test_encode_psk_framing_golden(self):
        # assert the exact Table 3-13 layout
        #   85 | L1 | L2 | <ciphered> | 03 | <SHA-1(clear)[:3]>
        clear = self.PSK_CLEAR
        ciphered = h2b('aabbccddeeff00112233445566778899')  # arbitrary 16-byte ciphertext
        kcv = hashlib.sha1(clear).digest()[:3]
        field = self.C.encode_key_data_psk(clear, ciphered, kcv)
        #                            85   L1   L2   <---------- ciphered ----------->  03  <-kcv->
        self.assertEqual(b2h(field),'85' '11' '10' 'aabbccddeeff00112233445566778899' '03' + b2h(kcv))
        self.assertEqual(b2h(field),'851110aabbccddeeff0011223344556677889903' + '06125d')

    def test_psk_golden_over_scp02(self):
        # Full PUT KEY data field (KVN 0x40 + single PSK key) enciphered with the SCP02 DEK.
        keys = [{'key_type': 'tls_psk', 'clear_key': self.PSK_CLEAR,
                 'kcv': compute_kcv('tls_psk', self.PSK_CLEAR)}]
        data = self.C.build_put_key_data(0x40, keys, self.scp02)
        self.assertEqual(b2h(data),
                         '40' '85' '11' '10' + b2h(self.PSK_CIPHERED) + '03' + b2h(self.PSK_KCV))

    def test_wrong_basic_format_differs(self):
        # regression test, the generic "Basic format" does NOT match Table 3-13 for a PSK key
        # rejected by card with with 6a88
        wrong_basic = self.C.encode_key_data_basic('tls_psk', self.PSK_CIPHERED, b'')
        right_psk = self.C.encode_key_data_psk(self.PSK_CLEAR, self.PSK_CIPHERED, self.PSK_KCV)
        self.assertEqual(b2h(wrong_basic), '8510' + b2h(self.PSK_CIPHERED) + '00')
        self.assertEqual(b2h(right_psk), '8511' '10' + b2h(self.PSK_CIPHERED) + '03' + b2h(self.PSK_KCV))
        self.assertNotEqual(wrong_basic, right_psk)

    def test_key_component_block_length_is_bertlv(self):
        # GP CardSpec v2.3.1 Section 11.8.2.3.1: all lengths ofPUT KEY are always BER TLV coded
        for kcb_len, exp_len_field in [(127, '7f'), (128, '8180'), (129, '8181'), (256, '820100')]:
            with self.subTest(kcb_len=kcb_len):
                kcb = bytes(kcb_len)
                field = self.C.encode_key_data_basic('rsa_modulus_n', kcb, b'')
                self.assertEqual(b2h(field), 'a2' + exp_len_field + b2h(kcb) + '00')
                # 85 field of Amendment B Table 3-13 uses the same coding
                # single byte inner length (clear key < 128) == block kcb_len bytes long
                psk = self.C.encode_key_data_psk(bytes(120), bytes(kcb_len - 1), b'')
                self.assertEqual(b2h(psk)[:2 + len(exp_len_field)], '85' + exp_len_field)

    def test_basic_format_unchanged(self):
        # as before
        for kt, clear in [('des', h2b('404142434445464748494a4b4c4d4e4f')),
                          ('aes', h2b('000102030405060708090a0b0c0d0e0f'))]:
            ciph = self.scp02.encrypt_key(clear)
            kcv = compute_kcv(kt, clear)
            via_construct = build_construct(self.C.KeyDataBasic, {'key_type': kt, 'kcb': b2h(ciph), 'kcv': b2h(kcv)})
            via_helper = self.C.encode_key_data_basic(kt, ciph, kcv)
            self.assertEqual(via_helper, via_construct)

    def test_psk_padding_no_double_length(self):
        # A PSK key whose length is not a multiple of the DEK block size (DES: 8) is right-padded before
        # ciphering. Table 3-13 states the clear key length (L2) in the '85' DO itself, so the ciphered
        # key field is the bare cryptogram:
        # - ciphered field == padded ciphertext (no duplicated length prefix),
        # - clear key == first L2 bytes.
        for keylen in (18, 20):
            with self.subTest(keylen=keylen):
                clear = bytes(range(keylen))
                padded_len = keylen + (-keylen % 8)
                field = self.C.build_put_key_data(0x40, [{'key_type': 'tls_psk', 'clear_key': clear,
                                                          'kcv': compute_kcv('tls_psk', clear)}], self.scp02)[1:]
                self.assertEqual(field[0], 0x85)
                l1 = field[1]
                l2 = field[2]
                self.assertEqual(l2, keylen)                # single-byte BER length of clear key
                ciphered = field[3:3 + (l1 - 1)]            # value = L2 (1 byte) || ciphered key
                self.assertEqual(len(ciphered), padded_len) # padded to the 8-byte DES block size
                self.assertEqual(l1, 1 + padded_len)        # no duplicated length prefix
                self.assertEqual(self.scp02.dek_decrypt(ciphered)[:keylen], clear)

    def test_psk_clear_key_is_not_padded_in_place(self):
        # padding the bytearray in place would make L2 the padded length,
        # then stored as key material and rejected thanks to the KCV
        clear = h2b('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d')  # 30, not %8
        kcv = compute_kcv('tls_psk', clear)
        field = self.C.build_put_key_data(0x40, [{'key_type': 'tls_psk', 'clear_key': clear,
                                                  'kcv': kcv}], self.scp02)[1:]
        self.assertEqual(len(clear), 30)
        self.assertEqual(field[2], 30)                       # L2 == clear key length, not 32
        self.assertEqual(self.scp02.dek_decrypt(field[3:3 + field[1] - 1])[:30], clear)

    def test_kcv_suppressed(self):
        # --suppress-key-check -> KCV length 00 and no KCV bytes
        field = self.C.build_put_key_data(0x40, [{'key_type': 'tls_psk', 'clear_key': self.PSK_CLEAR,
                                                  'kcv': b''}], self.scp02)[1:]
        self.assertEqual(b2h(field), '8511' '10' + b2h(self.PSK_CIPHERED) + '00')

    def test_multikey_psk_plus_des_dek(self):
        # load a PSK TLS key (KID 1, Amendment B format) together with its DES DEK
        # (KID 2, Basic format) in one PUT KEY.
        # Verify the concatenated data field parses back into the two components with proper type formats.
        dek = h2b('404142434445464748494a4b4c4d4e4f')
        keys = [{'key_type': 'tls_psk', 'clear_key': self.PSK_CLEAR, 'kcv': compute_kcv('tls_psk', self.PSK_CLEAR)},
                {'key_type': 'des', 'clear_key': dek, 'kcv': compute_kcv('des', dek)}]
        data = self.C.build_put_key_data(0x40, keys, self.scp02)

        b = data
        self.assertEqual(b[0], 0x40)            # KVN
        b = b[1:]
        # component 1: PSK TLS (Table 3-13)
        self.assertEqual(b[0], 0x85)
        self.assertEqual(b[1], 0x11)            # L1 = 17
        self.assertEqual(b[2], 0x10)            # L2 = 16 (clear key length)
        self.assertEqual(b[3:3 + 16], self.PSK_CIPHERED)
        self.assertEqual(b[3 + 16], 0x03)       # KCV length
        self.assertEqual(b[3 + 16 + 1:3 + 16 + 1 + 3], self.PSK_KCV)
        b = b[3 + 16 + 1 + 3:]
        # component 2: DES DEK (Basic format)
        self.assertEqual(b[0], 0x80)            # key type des
        kcb_len = b[1]
        self.assertEqual(kcb_len, 16)
        self.assertEqual(b[2:2 + kcb_len], self.scp02.encrypt_key(dek))
        b = b[2 + kcb_len:]
        self.assertEqual(b[0], 0x03)            # KCV length
        self.assertEqual(b[1:1 + 3], compute_kcv('des', dek))
        self.assertEqual(b[1 + 3:], b'')        # no trailing bytes

    def test_no_scp_leaves_key_clear(self):
        # During personalization (no SCP) the key is not enciphered, framing still follows Table 3-13.
        field = self.C.build_put_key_data(0x40, [{'key_type': 'tls_psk', 'clear_key': self.PSK_CLEAR,
                                                  'kcv': self.PSK_KCV}], None)[1:]
        self.assertEqual(b2h(field), '8511' '10' + b2h(self.PSK_CLEAR) + '03' + b2h(self.PSK_KCV))


class PutKey_Length_Test(unittest.TestCase):
    """Tests for the length of the PUT KEY command APDU.  Lc of GP CardSpec v2.3 Table 11-64 is a
    single byte, so an oversized key data field cannot be sent."""

    class PutKeyOnly(ADF_SD.AddlShellCommands):
        """ADF_SD.AddlShellCommands with a canned scc to drive put_key()"""
        def __init__(self, scp=None, max_cmd_len=255):
            super().__init__()
            self.sent = []
            self.scc = SimpleNamespace(scp=scp, max_cmd_len=max_cmd_len,
                                       send_apdu_checksw=lambda pdu: (self.sent.append(pdu), ('', '9000'))[1])

        @property
        def _cmd(self):
            return SimpleNamespace(lchan=SimpleNamespace(scc=self.scc))

    # KVN, key type, two byte BER length of the key component block, KCV length; KCV suppressed
    FRAMING = 1 + 1 + 2 + 1

    @staticmethod
    def key(nbytes: int):
        return [{'key_type': 'rsa_modulus_n', 'clear_key': bytes(nbytes), 'kcv': b''}]

    def test_lc_matches_data_field(self):
        # largest key component block that still fits without a secure channel
        sd = self.PutKeyOnly()
        sd.put_key(0, 0x40, 1, self.key(255 - self.FRAMING))
        apdu = sd.sent[0]
        self.assertEqual(apdu[:8], '80D80001')
        lc = int(apdu[8:10], 16)
        self.assertEqual(lc, 255)                       # Lc ...
        self.assertEqual(len(apdu[10:-2]) // 2, lc)     # ... and it matches the actual data field

    def test_oversized_key_data_raises(self):
        # real world fat example: RSA-2048 modulus does not fit, led to 3 nibble Lc 106,
        # which silently shifted and broke the whole APDU by half a byte.
        sd = self.PutKeyOnly()
        with self.assertRaises(ValueError) as ctx:
            sd.put_key(0, 0x40, 1, self.key(256))
        self.assertIn('262', str(ctx.exception))
        self.assertIn('255', str(ctx.exception))
        self.assertEqual(sd.sent, [])                   # nothing was sent to the card

    def test_secure_channel_overhead_lowers_the_limit(self):
        # scc.max_cmd_len shrinks by the C-MAC + encryption padding of active SCP
        sd = self.PutKeyOnly(max_cmd_len=239)
        sd.put_key(0, 0x40, 1, self.key(239 - self.FRAMING))
        self.assertEqual(int(sd.sent[0][8:10], 16), 239)
        with self.assertRaises(ValueError):
            sd.put_key(0, 0x40, 1, self.key(239 - self.FRAMING + 1))


class Install_param_Test(unittest.TestCase):
    def test_gen_install_parameters(self):
        load_parameters = gen_install_parameters(256, 256, '010001001505000000000000000000000000')
        self.assertEqual(load_parameters, 'c900ef1cc8020100c7020100ca12010001001505000000000000000000000000')

        load_parameters = gen_install_parameters()
        self.assertEqual(load_parameters, 'c900')

class SCP_Overhead_Test(unittest.TestCase):
    """SCP.overhead varies according to the current security level:
    C-MAC + at level >= 3 the worst-case padding!
    """

    def _scp02(self, security_level):
        scp = SCP02(card_keys=ck_3des_70)
        scp.sk = Scp02SessionKeys(0x0001, ck_3des_70)
        scp.security_level = security_level
        return scp

    def _scp03(self, security_level, s_mode=8):
        scp = SCP03(card_keys=KEYSET_AES128, s_mode=s_mode)
        scp.sk = Scp03SessionKeys(KEYSET_AES128, b'\x00' * s_mode, b'\x11' * s_mode)
        scp.security_level = security_level
        return scp

    def test_scp02(self):
        self.assertEqual(self._scp02(0x00).overhead, 0)   # no wrapping at all
        self.assertEqual(self._scp02(0x01).overhead, 8)   # C-MAC
        self.assertEqual(self._scp02(0x03).overhead, 16)  # C-MAC + C-DEC: pad80 to 8, largest fit 239

    def test_scp03_s8(self):
        self.assertEqual(self._scp03(0x00).overhead, 0)
        self.assertEqual(self._scp03(0x01).overhead, 8)
        self.assertEqual(self._scp03(0x03).overhead, 16)  # pad80 to 16 within 247 -> 240, minus pad byte
        self.assertEqual(self._scp03(0x33).overhead, 16)  # R-MAC/R-ENC add no *command* overhead

    def test_scp03_s16(self):
        self.assertEqual(self._scp03(0x01, s_mode=16).overhead, 16)
        self.assertEqual(self._scp03(0x03, s_mode=16).overhead, 32)  # pad80 to 16 within 239 -> 224, minus pad byte


class SCP_Lc_Limit_Test_Base(unittest.TestCase):
    """Test wrap_cmd_apdu() boundary handling: data of (255 - overhead) must produce Lc <= 255 else ValueError"""

    def _load_apdu(self, data_len):
        return h2b('80E80000') + bytes([data_len]) + b'\xa5' * data_len

    def _check_boundary(self, scp):
        fits = 255 - scp.overhead
        wrapped = scp.wrap_cmd_apdu(self._load_apdu(fits))
        self.assertLessEqual(wrapped[4], 255)
        self.assertEqual(len(wrapped), 5 + wrapped[4])  # case #3: header + Lc bytes, no Le
        with self.assertRaises(ValueError) as ctx:
            scp.wrap_cmd_apdu(self._load_apdu(fits + 1))
        self.assertIn('Lc', str(ctx.exception))


class SCP02_Lc_Limit_Test(SCP_Lc_Limit_Test_Base):
    """Same session vectors as SCP02_Auth_Test"""

    def setUp(self):
        self.scp02 = SCP02(card_keys=ck_3des_70)
        self.scp02.gen_init_update_apdu(host_challenge=h2b('40A62C37FA6304F8'))
        self.scp02.parse_init_update_resp(h2b('00000000000000000000700200016B4524ABEE7CF32EA3838BC148F3'))
        self.scp02.gen_ext_auth_apdu()

    def test_cmac_only(self):
        self.scp02.security_level = 0x01
        self._check_boundary(self.scp02)  # 247 fits, 248 raises

    def test_cmac_cdec(self):
        self.scp02.security_level = 0x03
        self._check_boundary(self.scp02)  # 239 fits (-> Lc 248), 240 raises (would be 256)

    def test_cmac_cdec_wrapped_lc(self):
        # my actual failing case: 240 bytes at level 3
        self.scp02.security_level = 0x03
        wrapped = self.scp02.wrap_cmd_apdu(self._load_apdu(239))
        self.assertEqual(wrapped[4], 248)  # 239 -> pad80 -> 240 ciphertext + 8 mac


class SCP03_Lc_Limit_Test(SCP_Lc_Limit_Test_Base):
    """Session keys derived directly"""

    def _scp03(self, security_level, s_mode):
        scp = SCP03(card_keys=KEYSET_AES128, s_mode=s_mode)
        scp.sk = Scp03SessionKeys(KEYSET_AES128, b'\x00' * s_mode, b'\x11' * s_mode)
        scp.security_level = security_level
        return scp

    def test_s8_cmac_only(self):
        self._check_boundary(self._scp03(0x01, 8))    # 247 fits, 248 raises

    def test_s8_cmac_cdec(self):
        self._check_boundary(self._scp03(0x03, 8))    # 239 fits, 240 raises

    def test_s16_cmac_only(self):
        self._check_boundary(self._scp03(0x01, 16))   # 239 fits, 240 raises

    def test_s16_cmac_cdec(self):
        self._check_boundary(self._scp03(0x03, 16))   # 223 fits, 224 raises


class _FakeSccForLoad:
    """mock lchan.scc: records LOAD APDUs, optionally wrapping them through a real SCP
    instance first where the Lc overflow used to blow up"""

    def __init__(self, max_cmd_len=255, scp=None):
        self.max_cmd_len = max_cmd_len
        self.scp = scp
        self.sent = []
        self.wrapped = []

    def send_apdu_checksw(self, apdu, sw='9000'):
        self.sent.append(apdu.lower())
        if self.scp:
            self.wrapped.append(self.scp.wrap_cmd_apdu(h2b(apdu)))
        return ('', '9000')


class Load_ChunkLen_Test(unittest.TestCase):
    """ADF_SD.load() chunking: block size must use scc.max_cmd_len"""

    payload = b'\xaa' * 500  # actual real world case LOAD TLV: C4 + 8201f4 + 500 = 504 total

    def _sd(self, scc):
        cmd = type('_Cmd', (), {'lchan': type('_Lchan', (), {'scc': scc})(),
                                'poutput': lambda self, *args: None})()
        # cmd2 CommandSet has a r/o _cmd property -> shadow it
        _SD = type('_SD', (ADF_SD.AddlShellCommands,), {'_cmd': cmd})
        return _SD.__new__(_SD)

    def _blocks(self, scc):
        """Get (p1, p2, lc) from LOAD APDU"""
        for apdu in scc.sent:
            self.assertEqual(apdu[0:4], '80e8')
            yield int(apdu[4:6], 16), int(apdu[6:8], 16), int(apdu[8:10], 16)

    def test_default_no_scp(self):
        """Without SCP the old 240 byte block size is kept, no idea what else might rely on this number"""
        scc = _FakeSccForLoad(max_cmd_len=255)
        self._sd(scc).load(self.payload)
        blocks = list(self._blocks(scc))
        self.assertEqual([b[2] for b in blocks], [240, 240, 24])
        self.assertEqual([b[0] for b in blocks], [0x00, 0x00, 0x80])  # P1: last block flagged
        self.assertEqual([b[1] for b in blocks], [0, 1, 2])           # P2: block num

    def test_default_scp02_level3(self):
        """max_cmd_len 239 (SCP02 lvl 3) squeezes the blocks"""
        scc = _FakeSccForLoad(max_cmd_len=239)
        self._sd(scc).load(self.payload)
        self.assertEqual([b[2] for b in list(self._blocks(scc))], [239, 239, 26])

    def test_explicit_chunk_len(self):
        scc = _FakeSccForLoad(max_cmd_len=255)
        self._sd(scc).load(self.payload, chunk_len=100)
        self.assertEqual([b[2] for b in list(self._blocks(scc))], [100] * 5 + [4])

    def test_explicit_chunk_len_too_large(self):
        scc = _FakeSccForLoad(max_cmd_len=239)
        with self.assertRaises(ValueError):
            self._sd(scc).load(self.payload, chunk_len=240)
        self.assertEqual(scc.sent, [])  # nothing sent!

    def test_explicit_chunk_len_zero(self):
        scc = _FakeSccForLoad(max_cmd_len=255)
        with self.assertRaises(ValueError):
            self._sd(scc).load(self.payload, chunk_len=0)

    def test_end_to_end_scp02_level3(self):
        """original failure: 286 byte CAP + SCP02 lvl 3"""
        scp02 = SCP02(card_keys=ck_3des_70)
        scp02.gen_init_update_apdu(host_challenge=h2b('40A62C37FA6304F8'))
        scp02.parse_init_update_resp(h2b('00000000000000000000700200016B4524ABEE7CF32EA3838BC148F3'))
        scp02.gen_ext_auth_apdu()
        scp02.security_level = 0x03
        scc = _FakeSccForLoad(max_cmd_len=255 - scp02.overhead, scp=scp02)
        self._sd(scc).load(b'\x5a' * 286)
        self.assertEqual(len(scc.sent), 2)  # 289 byte TLV in blocks of 239
        for wrapped in scc.wrapped:
            self.assertLessEqual(wrapped[4], 255)


class _FakeScc:
    """mock lchan.scc: replays scripted (data, sw) pairs + records the APDUs sent."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    def send_apdu(self, apdu):
        self.sent.append(apdu.lower())
        if not self._responses:
            raise AssertionError('get_status sent unexpected APDU: %s' % apdu)
        return self._responses.pop(0)


class GetStatus_Pagination_Test(unittest.TestCase):
    """GPC v2.3.1 section 11.4.3.2 table 11-38 GET STATUS pagination test

    Card answers 6310 when further matches are pending; command reissued with
    P2 bit 1 "next occurrence" set. Tied to T=0 handling pySim/transport, which
    used to swallow that 6310 and replied with GET RESPONSE, so page 2 was never fetched."""

    ENTRY_1 = 'e3074f05a000000151'
    ENTRY_2 = 'e3074f05a000000152'

    def _sd(self, responses):
        scc = _FakeScc(responses)
        cmd = type('_Cmd', (), {'lchan': type('_Lchan', (), {'scc': scc})()})()
        # cmd2 strikes again, CommandSet exposes _cmd as a read only property, needs shadowing
        _SD = type('_SD', (ADF_SD.AddlShellCommands,), {'_cmd': cmd})
        return _SD.__new__(_SD), scc

    def _aids(self, grd_list):
        return [b2h(grd.to_dict()['gp_registry_related_data'][0]['application_aid']) for grd in grd_list]

    def test_single_page(self):
        sd, scc = self._sd([(self.ENTRY_1, '9000')])
        grd_list = sd.get_status('applications')
        self.assertEqual(scc.sent, ['80f24002094f005c054f9f70c5cc00'])
        self.assertEqual(self._aids(grd_list), ['a000000151'])

    def test_two_pages(self):
        """6310 -> reissue with P2 bit 1 set -> 9000, both pages in result"""
        sd, scc = self._sd([(self.ENTRY_1, '6310'), (self.ENTRY_2, '9000')])
        grd_list = sd.get_status('applications')
        self.assertEqual(scc.sent, ['80f24002094f005c054f9f70c5cc00',
                                    '80f24003094f005c054f9f70c5cc00'])
        self.assertEqual(self._aids(grd_list), ['a000000151', 'a000000152'])

    def test_three_pages_keep_p2_next_occurrence(self):
        sd, scc = self._sd([(self.ENTRY_1, '6310'), (self.ENTRY_2, '6310'), (self.ENTRY_1, '9000')])
        grd_list = sd.get_status('applications')
        self.assertEqual([a[6:8] for a in scc.sent], ['02', '03', '03'])
        self.assertEqual(len(grd_list), 3)

    def test_no_match_returns_empty(self):
        """6A88 "referenced data not found" is empty result not failure."""
        sd, _scc = self._sd([('', '6a88')])
        self.assertEqual(sd.get_status('applications'), [])

    def test_unexpected_sw_is_not_silently_truncated(self):
        """partial is not complete result"""
        sd, _scc = self._sd([(self.ENTRY_1, '6310'), ('', '6982')])
        with self.assertRaises(SwMatchError) as ctx:
            sd.get_status('applications')
        self.assertEqual(ctx.exception.sw_actual, '6982')



if __name__ == "__main__":
	unittest.main()
