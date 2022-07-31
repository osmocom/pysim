#!/usr/bin/env python3

import unittest
from pySim.utils import h2b, b2h
from pySim.ota import *

class Test_SMS_3DES(unittest.TestCase):
    tar = h2b('b00000')
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
        r = self.dialect.encode_cmd(self.od, self.tar, spi, h2b('00a40000023f00'))
        self.assertEqual(b2h(r), '00180d04193535b00000e3ec80a849b554421276af3883927c20')

    def test_cmd_3des_signed(self):
        spi = self.spi_base
        spi['ciphering'] = False
        spi['rc_cc_ds'] = 'cc'
        r = self.dialect.encode_cmd(self.od, self.tar, spi, h2b('00a40000023f00'))
        self.assertEqual(b2h(r), '1502193535b00000000000000000072ea17bdb72060e00a40000023f00')

    def test_cmd_3des_none(self):
        spi = self.spi_base
        spi['ciphering'] = False
        spi['rc_cc_ds'] = 'no_rc_cc_ds'
        r = self.dialect.encode_cmd(self.od, self.tar, spi, h2b('00a40000023f00'))
        self.assertEqual(b2h(r), '0d00193535b0000000000000000000a40000023f00')
