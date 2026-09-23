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

from pySim.cat import SupportedRadioAccessTechnologies


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
