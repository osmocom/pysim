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

if __name__ == "__main__":
	unittest.main()
