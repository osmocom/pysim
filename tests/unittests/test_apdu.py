#!/usr/bin/env python3

import unittest
from osmocom.utils import h2b, b2h
from osmocom.construct import filter_dict

from pySim.apdu import Apdu
from pySim.apdu.ts_31_102 import UsimAuthenticateEven

class TestApdu(unittest.TestCase):
    def test_successful(self):
        apdu = Apdu('00a40400023f00', '9000')
        self.assertEqual(apdu.successful, True)
        apdu = Apdu('00a40400023f00', '6733')
        self.assertEqual(apdu.successful, False)

    def test_successful_method(self):
        """Test overloading of the success property with a custom method."""
        class SwApdu(Apdu):
            def _is_success(self):
                return False
        apdu = SwApdu('00a40400023f00', '9000')
        self.assertEqual(apdu.successful, False)

# TODO: Tests for TS 102 221 / 31.102 ApduCommands

class TestUsimAuth(unittest.TestCase):
    """Test decoding of the rather complex USIM AUTHENTICATE command."""
    def test_2g(self):
        apdu = ('80880080' + '09' + '080001020304050607',
                '04a0a1a2a308b0b1b2b3b4b5b6b79000')
        res = {
            'cmd': {'p1': 0, 'p2': {'scope': 'df_adf_specific', 'authentication_context': 'gsm'},
                    'body': {'rand': h2b('0001020304050607'), 'autn': None}},
            'rsp': {'body': {'sres': h2b('a0a1a2a3'), 'kc': h2b('b0b1b2b3b4b5b6b7')}}
            }
        u = UsimAuthenticateEven(apdu[0], apdu[1])
        d = filter_dict(u.to_dict())
        self.assertEqual(d, res)

    def test_3g(self):
        apdu = ('80880081' + '12' + '080001020304050607081011121314151617',
                'DB' + '08' + 'a0a1a2a3a4a5a6a7' +
                       '10' + 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
                       '10' + 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' + '9000')
        res = {
            'cmd': {'p1': 0, 'p2': {'scope': 'df_adf_specific', 'authentication_context': 'umts'},
                    'body': {'rand': h2b('0001020304050607'), 'autn': h2b('1011121314151617')}},
            'rsp': {'body': {'tag': 219,
                             'body': {
                                 'res': h2b('a0a1a2a3a4a5a6a7'),
                                 'ck': h2b('b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'),
                                 'ik': h2b('c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'),
                                 'kc': None
                                 }
                             }
                    }
            }
        u = UsimAuthenticateEven(apdu[0], apdu[1])
        d = filter_dict(u.to_dict())
        self.assertEqual(d, res)

    def test_3g_sync(self):
        apdu = ('80880081' + '12' + '080001020304050607081011121314151617',
                'DC' + '08' + 'a0a1a2a3a4a5a6a7' + '9000')
        res = {
            'cmd': {'p1': 0, 'p2': {'scope': 'df_adf_specific', 'authentication_context': 'umts'},
                    'body': {'rand': h2b('0001020304050607'), 'autn': h2b('1011121314151617')}},
            'rsp': {'body': {'tag': 220, 'body': {'auts': h2b('a0a1a2a3a4a5a6a7') }}}
            }
        u = UsimAuthenticateEven(apdu[0], apdu[1])
        d = filter_dict(u.to_dict())
        self.assertEqual(d, res)

    def test_vgcs(self):
        apdu = ('80880082' + '0E' + '04' + '00010203' +
                             '01' + '10' +
                             '08' + '2021222324252627',
                'DB' + '10' + 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' + '9000')
        res = {
            'cmd': {'p1': 0, 'p2': {'scope': 'df_adf_specific', 'authentication_context': 'vgcs_vbs'},
                    'body': { 'vk_id': h2b('10'), 'vservice_id': h2b('00010203'), 'vstk_rand': h2b('2021222324252627')}},
            'rsp': {'body': {'vstk': h2b('b0b1b2b3b4b5b6b7b8b9babbbcbdbebf')}}
            }
        u = UsimAuthenticateEven(apdu[0], apdu[1])
        d = filter_dict(u.to_dict())
        self.assertEqual(d, res)



if __name__ == "__main__":
	unittest.main()
