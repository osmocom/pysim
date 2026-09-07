#!/usr/bin/env python3

import unittest
from osmocom.utils import h2b, b2h
from pySim.sms import SMS_SUBMIT, SMS_DELIVER, AddressField
from pySim.ota import *

# pre-defined SPI values for use in test cases below
SPI_CC_POR_CIPHERED_CC = {
    'counter':'no_counter',
    'ciphering':True,
    'rc_cc_ds': 'cc',
    'por_in_submit':False,
    'por_shall_be_ciphered':True,
    'por_rc_cc_ds': 'cc',
    'por': 'por_required'
    }

SPI_CC_POR_UNCIPHERED_CC = {
    'counter':'no_counter',
    'ciphering':True,
    'rc_cc_ds': 'cc',
    'por_in_submit':False,
    'por_shall_be_ciphered':False,
    'por_rc_cc_ds': 'cc',
    'por': 'por_required'
}

SPI_CC_POR_UNCIPHERED_NOCC = {
    'counter':'no_counter',
    'ciphering':True,
    'rc_cc_ds': 'cc',
    'por_in_submit':False,
    'por_shall_be_ciphered':False,
    'por_rc_cc_ds': 'no_rc_cc_ds',
    'por': 'por_required'
}

######################################################################
# old-style code-driven test (lots of code copy+paste)
######################################################################

class Test_SMS_AES128(unittest.TestCase):
    tar = h2b('B00011')
    """Test the OtaDialectSms for AES128 algorithms."""
    def __init__(self, foo, **kwargs):
        super().__init__(foo, **kwargs)
        self.od = OtaKeyset(algo_crypt='aes_cbc', kic_idx=2,
                            algo_auth='aes_cmac', kid_idx=2,
                            kic=h2b('200102030405060708090a0b0c0d0e0f'),
                            kid=h2b('201102030405060708090a0b0c0d0e0f'))
        self.dialect = OtaDialectSms()
        self.spi_base = SPI_CC_POR_CIPHERED_CC

    def _check_response(self, r, d):
        self.assertEqual(d['number_of_commands'], 1)
        self.assertEqual(d['last_status_word'], '6132')
        self.assertEqual(d['last_response_data'], u'')
        self.assertEqual(r['response_status'], 'por_ok')

    def test_resp_aes128_ciphered(self):
        spi = self.spi_base
        r, d = self.dialect.decode_resp(self.od, spi, '027100002412b00011ebc6b497e2cad7aedf36ace0e3a29b38853f0fe9ccde81913be5702b73abce1f')
        self._check_response(r, d)

    def test_cmd_aes128_ciphered(self):
        spi = self.spi_base
        apdu = h2b('00a40004023f00')
        r = self.dialect.encode_cmd(self.od, self.tar, spi, apdu)
        self.assertEqual(b2h(r), '00281506192222b00011e87cceebb2d93083011ce294f93fc4d8de80da1abae8c37ca3e72ec4432e5058')
        # also test decoder
        dec_tar, dec_spi, dec_apdu = self.dialect.decode_cmd(self.od, r)
        self.assertEqual(b2h(apdu), b2h(dec_apdu))
        self.assertEqual(b2h(dec_tar), b2h(self.tar))
        self.assertEqual(dec_spi, spi)


class Test_SMS_3DES(unittest.TestCase):
    tar = h2b('b00000')
    apdu = h2b('00a40000023f00')
    """Test the OtaDialectSms for 3DES algorithms."""
    def __init__(self, foo, **kwargs):
        super().__init__(foo, **kwargs)
        # KIC1 + KID1 of 8988211000000467285
        KIC1 = h2b('D0FDA31990D8D64178601317191669B4')
        KID1 = h2b('D24EB461799C5E035C77451FD9404463')
        KIC3 = h2b('C21DD66ACAC13CB3BC8B331B24AFB57B')
        KID3 = h2b('12110C78E678C25408233076AA033615')
        self.od = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=3, kic=KIC3,
                            algo_auth='triple_des_cbc2', kid_idx=3, kid=KID3)
        self.dialect = OtaDialectSms()
        self.spi_base = {
                'counter':'no_counter',
                'ciphering': True,
                'rc_cc_ds': 'cc',
                'por_in_submit':False,
                'por': 'por_required',
                'por_shall_be_ciphered': True,
                'por_rc_cc_ds': 'cc',
            }

    def _check_response(self, r, d):
        self.assertEqual(d['number_of_commands'], 1)
        self.assertEqual(d['last_status_word'], '612f')
        self.assertEqual(d['last_response_data'], u'')
        self.assertEqual(r['response_status'], 'por_ok')

    def test_resp_3des_ciphered(self):
        spi = self.spi_base
        spi['por_shall_be_ciphered'] = True
        spi['por_rc_cc_ds'] = 'cc'
        r, d = self.dialect.decode_resp(self.od, spi, '027100001c12b000119660ebdb81be189b5e4389e9e7ab2bc0954f963ad869ed7c')
        self._check_response(r, d)

    def test_resp_3des_signed(self):
        spi = self.spi_base
        spi['por_shall_be_ciphered'] = False
        spi['por_rc_cc_ds'] = 'cc'
        r, d = self.dialect.decode_resp(self.od, spi, '027100001612b000110000000000000055f47118381175fb01612f')
        self._check_response(r, d)

    def test_resp_3des_signed_err(self):
        """Expect an OtaCheckError exception if the computed CC != received CC"""
        spi = self.spi_base
        spi['por_shall_be_ciphered'] = False
        spi['por_rc_cc_ds'] = 'cc'
        with self.assertRaises(OtaCheckError) as context:
            r, d = self.dialect.decode_resp(self.od, spi, '027100001612b000110000000000000055f47118381175fb02612f')
        self.assertTrue('!= Computed CC' in str(context.exception))

    def test_resp_3des_none(self):
        spi = self.spi_base
        spi['por_shall_be_ciphered'] = False
        spi['por_rc_cc_ds'] = 'no_rc_cc_ds'
        r, d = self.dialect.decode_resp(self.od, spi, '027100000e0ab000110000000000000001612f')
        self._check_response(r, d)

    def test_cmd_3des_ciphered(self):
        spi = self.spi_base
        spi['ciphering'] = True
        spi['rc_cc_ds'] = 'no_rc_cc_ds'
        r = self.dialect.encode_cmd(self.od, self.tar, spi, self.apdu)
        self.assertEqual(b2h(r), '00180d04193535b00000e3ec80a849b554421276af3883927c20')
        # also test decoder
        dec_tar, dec_spi, dec_apdu = self.dialect.decode_cmd(self.od, r)
        self.assertEqual(b2h(self.apdu), b2h(dec_apdu))
        self.assertEqual(b2h(dec_tar), b2h(self.tar))
        self.assertEqual(dec_spi, spi)

    def test_cmd_3des_signed(self):
        spi = self.spi_base
        spi['ciphering'] = False
        spi['rc_cc_ds'] = 'cc'
        r = self.dialect.encode_cmd(self.od, self.tar, spi, self.apdu)
        self.assertEqual(b2h(r), '1502193535b00000000000000000072ea17bdb72060e00a40000023f00')

    def test_cmd_3des_none(self):
        spi = self.spi_base
        spi['ciphering'] = False
        spi['rc_cc_ds'] = 'no_rc_cc_ds'
        r = self.dialect.encode_cmd(self.od, self.tar, spi, self.apdu)
        self.assertEqual(b2h(r), '0d00193535b0000000000000000000a40000023f00')



######################################################################
# new-style data-driven tests
######################################################################

# SJA5 SAMPLE cards provisioned by execute_ipr.py
OTA_KEYSET_SJA5_SAMPLES = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=3,
                                    algo_auth='triple_des_cbc2', kid_idx=3,
                                    kic=h2b('300102030405060708090a0b0c0d0e0f'),
                                    kid=h2b('301102030405060708090a0b0c0d0e0f'))

OTA_KEYSET_SJA5_AES128 = OtaKeyset(algo_crypt='aes_cbc', kic_idx=2,
                                   algo_auth='aes_cmac', kid_idx=2,
                                   kic=h2b('200102030405060708090a0b0c0d0e0f'),
                                   kid=h2b('201102030405060708090a0b0c0d0e0f'))

class OtaTestCase(unittest.TestCase):
    def __init__(self, methodName='runTest', **kwargs):
        super().__init__(methodName, **kwargs)
        # RAM: B00000
        # SIM RFM: B00010
        # USIM RFM: B00011
        self.tar = h2b('B00011')

class SmsOtaTestCase(OtaTestCase):
    # Array describing the input/output data for the tests.  We use the
    # unittest subTests context manager to iterate over the entries of
    # this testdatasets list.  This is much more productive than
    # manually writing one class per test.
    testdatasets = [
        {
            'name': '3DES-SJA5-CIPHERED-CC',
            'ota_keyset': OTA_KEYSET_SJA5_SAMPLES,
            'spi': SPI_CC_POR_CIPHERED_CC,
            'request': {
                'apdu': b'\x00\xa4\x00\x04\x02\x3f\x00',
                'encoded_cmd': '00201506193535b00011ae733256918d050b87c94fbfe12e4dc402f262c41cf67f2f',
                'encoded_tpdu': '400881214365877ff6227052000000000302700000201506193535b00011ae733256918d050b87c94fbfe12e4dc402f262c41cf67f2f',
                },
            'response': {
                'encoded_resp': '027100001c12b000118bb989492c632529326a2f4681feb37c825bc9021c9f6d0b',
                'response_status': 'por_ok',
                'number_of_commands': 1,
                'last_status_word': '6132',
                'last_response_data': '',
                }
        }, {
            'name': '3DES-SJA5-UNCIPHERED-CC',
            'ota_keyset': OTA_KEYSET_SJA5_SAMPLES,
            'spi': SPI_CC_POR_UNCIPHERED_CC,
            'request': {
                'apdu': b'\x00\xa4\x00\x04\x02\x3f\x00',
                'encoded_cmd': '00201506093535b00011c49ac91ab8159ba5b83a54fb6385e0a5e31694f8b215fafc',
                'encoded_tpdu': '400881214365877ff6227052000000000302700000201506093535b00011c49ac91ab8159ba5b83a54fb6385e0a5e31694f8b215fafc',
                },
            'response': {
                'encoded_resp': '027100001612b0001100000000000000b5bcd6353a421fae016132',
                'response_status': 'por_ok',
                'number_of_commands': 1,
                'last_status_word': '6132',
                'last_response_data': '',
                }
        }, {
            'name': '3DES-SJA5-UNCIPHERED-NOCC',
            'ota_keyset': OTA_KEYSET_SJA5_SAMPLES,
            'spi': SPI_CC_POR_UNCIPHERED_NOCC,
            'request': {
                'apdu': b'\x00\xa4\x00\x04\x02\x3f\x00',
                'encoded_cmd': '00201506013535b000113190be334900f52b025f3f7eddfe868e96ebf310023b7769',
                'encoded_tpdu': '400881214365877ff6227052000000000302700000201506013535b000113190be334900f52b025f3f7eddfe868e96ebf310023b7769',
                },
            'response': {
                'encoded_resp': '027100000e0ab0001100000000000000016132',
                'response_status': 'por_ok',
                'number_of_commands': 1,
                'last_status_word': '6132',
                'last_response_data': '',
                }
        }, {
            'name': 'AES128-SJA5-CIPHERED-CC',
            'ota_keyset': OTA_KEYSET_SJA5_AES128,
            'spi': SPI_CC_POR_CIPHERED_CC,
            'request': {
                'apdu': b'\x00\xa4\x00\x04\x02\x3f\x00',
                'encoded_cmd': '00281506192222b00011e87cceebb2d93083011ce294f93fc4d8de80da1abae8c37ca3e72ec4432e5058',
                'encoded_tpdu': '400881214365877ff6227052000000000302700000281506192222b00011e87cceebb2d93083011ce294f93fc4d8de80da1abae8c37ca3e72ec4432e5058',
                },
            'response': {
                'encoded_resp': '027100002412b00011ebc6b497e2cad7aedf36ace0e3a29b38853f0fe9ccde81913be5702b73abce1f',
                'response_status': 'por_ok',
                'number_of_commands': 1,
                'last_status_word': '6132',
                'last_response_data': '',
                }
        },
        # TODO: AES192
        # TODO: AES256
    ]

    def __init__(self, methodName='runTest', **kwargs):
        super().__init__(methodName, **kwargs)
        self.dialect = OtaDialectSms()
        self.da = AddressField('12345678', 'unknown', 'isdn_e164')

    def test_encode_cmd(self):
        for t in SmsOtaTestCase.testdatasets:
            with self.subTest(name=t['name']):
                kset = t['ota_keyset']
                outp = self.dialect.encode_cmd(kset, self.tar, t['spi'], apdu=t['request']['apdu'])
                #print("result: %s" % b2h(outp))
                self.assertEqual(b2h(outp), t['request']['encoded_cmd'])

                with_udh = b'\x02\x70\x00' + outp
                #print("with_udh: %s" % b2h(with_udh))

                tpdu = SMS_DELIVER(tp_udhi=True, tp_oa=self.da, tp_pid=0x7F, tp_dcs=0xF6,
                                   tp_scts=h2b('22705200000000'), tp_udl=3, tp_ud=with_udh)
                #print("TPDU: %s" % tpdu)
                #print("tpdu: %s" % b2h(tpdu.to_bytes()))
                self.assertEqual(b2h(tpdu.to_bytes()), t['request']['encoded_tpdu'])

                # also test decoder
                dec_tar, dec_spi, dec_apdu = self.dialect.decode_cmd(kset, outp)
                self.assertEqual(b2h(t['request']['apdu']), b2h(dec_apdu))
                self.assertEqual(b2h(dec_tar), b2h(self.tar))
                self.assertEqual(dec_spi, t['spi'])

    def test_decode_resp(self):
        for t in SmsOtaTestCase.testdatasets:
            with self.subTest(name=t['name']):
                kset = t['ota_keyset']
                r, d = self.dialect.decode_resp(kset, t['spi'], t['response']['encoded_resp'])
                #print("RESP: %s / %s" % (r, d))
                self.assertEqual(r.response_status, t['response']['response_status'])
                self.assertEqual(d.number_of_commands, t['response']['number_of_commands'])
                self.assertEqual(d.last_status_word, t['response']['last_status_word'])
                self.assertEqual(d.last_response_data, t['response']['last_response_data'])


######################################################################
# Expanded Remote Application data format (ETSI TS 102 226 Section 5.2)
######################################################################

class BerTlvLengthTestCase(unittest.TestCase):
    """The definite-length BER-TLV length field (ISO/IEC 8825-1) used by the
    expanded format, incl. the multi-byte (>127) forms (0x81xx / 0x82xxxx)."""
    def test_roundtrip(self):
        # (length value, expected encoded bytes)
        vectors = [
            (0,     '00'),
            (1,     '01'),
            (127,   '7f'),
            (128,   '8180'),
            (198,   '81c6'),   # big ~198 byte GET STATUS registry from a sja5
            (255,   '81ff'),
            (256,   '820100'),
            (65535, '82ffff'),
        ]
        for length, encoded in vectors:
            with self.subTest(length=length):
                built = BerTlvLen.build(length)
                self.assertEqual(b2h(built), encoded)
                self.assertEqual(BerTlvLen.parse(built), length)


class ExpandedCmdTestCase(unittest.TestCase):
    """Command Scripting template TS 102 226 5.2.1"""

    def test_single_capdu_golden(self):
        # GP GET STATUS, Le=00, TS 102 226 5.2.1.1 R-APDU
        out = encode_expanded_cmd(h2b('80f24002024f0000'))
        # aa = TS 101 220 table 7.18 Command Scripting template tag
        # 0a = length 10
        # 22 = TS 101 220 table 7.19 C-APDU tag
        # 08 = length
        # + C-APDU
        self.assertEqual(b2h(out), 'aa0a220880f24002024f0000')

    def test_multi_capdu_golden(self):
        out = encode_expanded_cmd([h2b('80f24002024f0000'), h2b('00a40004023f0000')])
        self.assertEqual(b2h(out), 'aa14220880f24002024f0000220800a40004023f0000')

    def test_multibyte_length_golden(self):
        # C-APDU: 4 header + 1 Lc + 195 data = 200 bytes.
        # 200 byte C-APDU forces long form BER lengths:
        # C-APDU TLV, 200 -> 81c8 + template 203 -> 81cb
        capdu = h2b('80f24000') + bytes([195]) + bytes(range(195))
        self.assertEqual(len(capdu), 200)
        out = encode_expanded_cmd(capdu)
        # aa 81 cb | 22 81 c8 | <200 byte capdu>
        self.assertEqual(b2h(out[:6]), 'aa81cb2281c8')
        self.assertEqual(out[6:], capdu)

    def test_roundtrip(self):
        for apdus in [[h2b('80f24002024f0000')],
                      [h2b('00a40004023f00'), h2b('80f24002024f0000')],
                      [h2b('00'*250)]]:
            with self.subTest(n=len(apdus)):
                out = encode_expanded_cmd(apdus)
                parsed = ExpandedCmd.parse(out)
                self.assertEqual([h2b(c.c_apdu) for c in parsed.commands], apdus)


class ExpandedRespTestCase(unittest.TestCase):
    """Decoding of the Response Scripting template (TS 102 226 5.2.2)."""

    def test_registry_golden(self):
        # real card case: GET STATUS returns a ~198 byte registry TLV + SW 9000
        # R-APDU = 198 data + 2 SW = 200/81c8
        # 'number of executed' TLV 80 01 01.
        registry = bytes(range(198))
        data = ExpandedRemoteResp.build(dict(body=dict(
                    num_executed=dict(number_of_commands=1),
                    responses=[dict(r_apdu=dict(response_data=b2h(registry), status_word='9000'))])))
        # ab | 81 ce | 80 01 01 | 23 81 c8 | <198 data> 90 00
        self.assertEqual(b2h(data[:9]), 'ab81ce8001012381c8')
        dec = decode_expanded_resp(data)
        self.assertEqual(dec.number_of_commands, 1)
        self.assertEqual(len(dec.commands), 1)
        self.assertEqual(dec.last_status_word, '9000')
        self.assertEqual(dec.last_response_data, b2h(registry))

    def test_status_only_golden(self):
        # last command, no response data, SW 6132
        data = ExpandedRemoteResp.build(dict(body=dict(
                    num_executed=dict(number_of_commands=1),
                    responses=[dict(r_apdu=dict(response_data='', status_word='6132'))])))
        self.assertEqual(b2h(data), 'ab0780010123026132')
        dec = decode_expanded_resp(data)
        self.assertEqual(dec.last_status_word, '6132')
        self.assertEqual(dec.last_response_data, '')

    def test_multi_command(self):
        data = ExpandedRemoteResp.build(dict(body=dict(
                    num_executed=dict(number_of_commands=2),
                    responses=[dict(r_apdu=dict(response_data='6f21', status_word='9000')),
                               dict(r_apdu=dict(response_data='', status_word='6a82'))])))
        dec = decode_expanded_resp(data)
        self.assertEqual(dec.number_of_commands, 2)
        self.assertEqual([(c.status_word, c.response_data) for c in dec.commands],
                         [('9000', '6f21'), ('6a82', '')])
        # last == final R-APDU, error status included
        self.assertEqual(dec.last_status_word, '6a82')
        self.assertEqual(dec.last_response_data, '')

    def test_bad_format(self):
        # ab | 06 | 80 01 01 | 90 01 01
        data = h2b('ab06800101900101')
        dec = decode_expanded_resp(data)
        self.assertEqual(str(dec.bad_format), 'unknown_tag')
        self.assertIsNone(dec.last_status_word)

    def test_immediate_action_error(self):
        # ab | 06 | 80 01 01 | 81 01 01
        data = h2b('ab06800101810101')
        dec = decode_expanded_resp(data)
        self.assertEqual(str(dec.immediate_action_response), 'suspension_error')

    def test_script_chaining_error(self):
        # ab | 06 | 80 01 01 | 83 01 02
        data = h2b('ab06800101830102')
        dec = decode_expanded_resp(data)
        self.assertEqual(str(dec.script_chaining_response), 'not_supported')

    def test_truncation_is_flagged(self):
        """TS 102 226 5.2.1.1: SW 62F1 means the C-APDU response data was truncated, and
        "this shall terminate the processing of the command list"
         halves are invisible in the R-APDU list, truncated + aborted script must not pass as complete"""
        # second command truncated -> processing stopped at that point
        data = ExpandedRemoteResp.build(dict(body=dict(
                    num_executed=dict(number_of_commands=2),
                    responses=[dict(r_apdu=dict(response_data='6f21', status_word='9000')),
                               dict(r_apdu=dict(response_data='aabb', status_word='62f1'))])))
        dec = decode_expanded_resp(data)
        self.assertTrue(dec.truncated)
        self.assertEqual(dec.last_status_word, '62f1')

    def test_untruncated_response_is_not_flagged(self):
        data = ExpandedRemoteResp.build(dict(body=dict(
                    num_executed=dict(number_of_commands=1),
                    responses=[dict(r_apdu=dict(response_data='6f21', status_word='9000'))])))
        self.assertFalse(decode_expanded_resp(data).truncated)
        # 62xx that is not 62F1 is warning, not truncation
        data = ExpandedRemoteResp.build(dict(body=dict(
                    num_executed=dict(number_of_commands=1),
                    responses=[dict(r_apdu=dict(response_data='', status_word='6282'))])))
        self.assertFalse(decode_expanded_resp(data).truncated)


class ExpandedSmsPipelineTestCase(unittest.TestCase):
    """expanded format + TS 102 225 SMS security witj 3DES keyset,
    to ensure remote_format does not affect the compact path"""
    def __init__(self, methodName='runTest', **kwargs):
        super().__init__(methodName, **kwargs)
        self.od = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=3,
                            kic=h2b('C21DD66ACAC13CB3BC8B331B24AFB57B'),
                            algo_auth='triple_des_cbc2', kid_idx=3,
                            kid=h2b('12110C78E678C25408233076AA033615'))
        self.dialect = OtaDialectSms()
        self.tar = h2b('000000')

    def test_cmd_expanded_secured_roundtrip(self):
        spi = SPI_CC_POR_CIPHERED_CC
        enc = self.dialect.encode_cmd(self.od, self.tar, spi, h2b('80f24002024f0000'),
                                      remote_format='expanded')
        # decode_cmd returns opaque 'Command Scripting template'
        dec_tar, dec_spi, dec_secured = self.dialect.decode_cmd(self.od, enc)
        self.assertEqual(b2h(dec_tar), b2h(self.tar))
        self.assertEqual(dec_spi, spi)
        self.assertEqual(b2h(dec_secured), 'aa0a220880f24002024f0000')

    def test_cmd_expanded_list(self):
        spi = SPI_CC_POR_CIPHERED_CC
        enc = self.dialect.encode_cmd(self.od, self.tar, spi,
                                      [h2b('80f24002024f0000'), h2b('00a40004023f0000')],
                                      remote_format='expanded')
        _, _, dec_secured = self.dialect.decode_cmd(self.od, enc)
        parsed = ExpandedCmd.parse(dec_secured)
        self.assertEqual([c.c_apdu for c in parsed.commands],
                         ['80f24002024f0000', '00a40004023f0000'])

    def test_resp_expanded_plaintext(self):
        # plaintext (u:nciphered + no CC) expanded response SMS
        # containing a 198 byte GP registry + SW 9000 as above, decode it through decode_resp().
        spi = SPI_CC_POR_UNCIPHERED_NOCC
        registry = bytes(range(198))
        secured = ExpandedRemoteResp.build(dict(body=dict(
                    num_executed=dict(number_of_commands=1),
                    responses=[dict(r_apdu=dict(response_data=b2h(registry), status_word='9000'))])))
        rpl = 1 + 3 + 5 + 1 + 1 + len(secured)   # RHL-STS + secured data
        resp_body = rpl.to_bytes(2, 'big') + b'\x0a' + self.tar + b'\x00'*5 + b'\x00' + b'\x00' + secured
        sms = b'\x02\x71\x00' + resp_body
        r, dec = self.dialect.decode_resp(self.od, spi, sms, remote_format='expanded')
        self.assertEqual(r.response_status, 'por_ok')
        self.assertEqual(dec.number_of_commands, 1)
        self.assertEqual(dec.last_status_word, '9000')
        self.assertEqual(dec.last_response_data, b2h(registry))

    def test_compact_still_default(self):
        # no remote_format -> compact default
        spi = SPI_CC_POR_UNCIPHERED_NOCC
        r, d = self.dialect.decode_resp(self.od, spi, '027100000e0ab000110000000000000001612f')
        self.assertEqual(d.number_of_commands, 1)
        self.assertEqual(d.last_status_word, '612f')
        self.assertEqual(d.last_response_data, '')


if __name__ == "__main__":
	unittest.main()
