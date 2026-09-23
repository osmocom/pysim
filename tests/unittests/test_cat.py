#!/usr/bin/env python3
"""Tests for the CAT (Card Application Toolkit) COMPREHENSION-TLV data objects"""

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Eric Wild <ewild@sysmocom.de>
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

# IEs not properly coverd by test_tlvs.py


import unittest

from osmocom.utils import b2h, h2b

from pySim.cat import IMEI, IMEISV, AccessTechnology, SupportedRadioAccessTechnologies


class IMEI_Test(unittest.TestCase):
    """TS 102 223 8.20: the IMEI IE is 8 bytes, coded as valie part of Mobile Identity IE from 124 008"""

    IMEI_15 = '123456789012345'
    ENCODED = '94081a32547698103254'

    def test_encode_is_eight_bytes(self):
        """15 digits in 8 byte: 16 nibbles, one is type/parity framing."""
        tlv = IMEI(decoded=self.IMEI_15).to_tlv()
        self.assertEqual(b2h(tlv), self.ENCODED)
        self.assertEqual(tlv[1], 0x08)               # spec len 8
        self.assertEqual(len(tlv) - 2, 8)

    def test_first_octet_framing(self):
        """TS 24.008 table 10.5.4"""
        octet1 = IMEI(decoded=self.IMEI_15).to_tlv()[2]
        self.assertEqual(octet1 & 0x07, 2)           # IMEI
        self.assertEqual((octet1 >> 3) & 0x01, 1)    # odd
        self.assertEqual(octet1 >> 4, 1)             # digit 1

    def test_decodes_to_the_raw_imei(self):
        """strip framing nibble"""
        ie = IMEI()
        ie.from_tlv(h2b(self.ENCODED))
        self.assertEqual(ie.decoded, self.IMEI_15)

    def test_even_digit_count_uses_the_end_mark(self):
        """"end marker, IMEISV case"""
        ie = IMEI(decoded='1234567890123456')
        tlv = ie.to_tlv()
        self.assertEqual(tlv[2] >> 3 & 0x01, 0)      # even
        self.assertEqual(tlv[-1] >> 4, 0x0f)         # end mark
        back = IMEI()
        back.from_tlv(tlv)
        self.assertEqual(back.decoded, '1234567890123456')


class IMEISV_Test(unittest.TestCase):
    """TS 102 223 8.74, no fixed len, end marker"""

    IMEISV_16 = '1234567890123456'
    ENCODED = 'e2091332547698103254f6'

    def test_encode(self):
        self.assertEqual(b2h(IMEISV(decoded=self.IMEISV_16).to_tlv()), self.ENCODED)

    def test_type_of_identity_and_end_mark(self):
        value = IMEISV(decoded=self.IMEISV_16).to_tlv()[2:]
        self.assertEqual(value[0] & 0x07, 3)         # IMEISV
        self.assertEqual((value[0] >> 3) & 0x01, 0)  # even
        self.assertEqual(value[-1] >> 4, 0x0f)       # end mark
        self.assertEqual(len(value), 9)

    def test_decode(self):
        ie = IMEISV()
        ie.from_tlv(h2b(self.ENCODED))
        self.assertEqual(ie.decoded, self.IMEISV_16)


class SupportedRadioAccessTechnologies_Test(unittest.TestCase):
    """TS 102 223 8.105"""

    def test_encode_technology_enabled(self):
        """The flag used to have a bitmask of 0 so enabled -> 00 (that is disabled..)"""
        ie = SupportedRadioAccessTechnologies(
            decoded=[{'technology': 'eutran', 'state': {'enabled': True}}])
        self.assertEqual(b2h(ie.to_tlv()), 'b4020801')

    def test_encode_technology_disabled(self):
        ie = SupportedRadioAccessTechnologies(
            decoded=[{'technology': 'eutran', 'state': {'enabled': False}}])
        self.assertEqual(b2h(ie.to_tlv()), 'b4020800')

    def test_decode_technology(self):
        """old 0 bitmask = all enabled, no way to disable"""
        for encoded, enabled in [('b4020800', False), ('b4020801', True)]:
            with self.subTest(encoded=encoded):
                ie = SupportedRadioAccessTechnologies()
                ie.from_tlv(h2b(encoded))
                self.assertEqual(ie.decoded[0]['technology'], 'eutran')
                self.assertEqual(ie.decoded[0]['state']['enabled'], enabled)

    def test_decode_technology_multiple(self):
        ie = SupportedRadioAccessTechnologies()
        ie.from_tlv(h2b('b40408010000'))
        self.assertEqual([(e['technology'], e['state']['enabled']) for e in ie.decoded],
                         [('eutran', True), ('gsm', False)])



if __name__ == "__main__":
    unittest.main()
