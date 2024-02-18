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
import copy

from pySim.utils import h2b, b2h
from pySim.esim.saip import *
from pySim.esim.saip.data_source import *
from pySim.esim.saip.personalization import *
from pprint import pprint as pp


class SaipTest(unittest.TestCase):
    with open('smdpp-data/upp/TS48v2_SAIP2.3_NoBERTLV.der', 'rb') as f:
        per_input = f.read()
    pes = ProfileElementSequence.from_der(per_input)
    expected_pet_list = ['header', 'mf', 'pukCodes', 'pinCodes', 'telecom', 'pinCodes', 'genericFileManagement', 'usim', 'opt-usim', 'pinCodes', 'akaParameter', 'gsm-access', 'df-5gs', 'df-saip','csim', 'opt-csim', 'pinCodes', 'cdmaParameter', 'isim', 'opt-isim', 'pinCodes', 'akaParameter', 'genericFileManagement', 'genericFileManagement', 'securityDomain', 'rfm', 'rfm', 'rfm', 'rfm', 'end']

    def test_reencode_sequence(self):
        """Test that we can decode and re-encode the entire DER encoded UPP."""
        reencoded_der = self.pes.to_der()
        self.assertEqual(reencoded_der, self.per_input)

    def test_reencode_pe(self):
        """Test that we can decode and re-encode reach individual ProfileElement."""
        remainder = self.per_input
        while len(remainder):
            first_tlv, remainder = bertlv_first_segment(remainder)
            pe = ProfileElement.from_der(first_tlv)
            with self.subTest(pe.type):
                reenc_tlv = pe.to_der()
                self.assertEqual(reenc_tlv, first_tlv)


    def test_sequence_helpers(self):
        """Verify that the convenience helpers worked as expected."""
        self.assertEqual([x.type for x in self.pes.pe_list], self.expected_pet_list)
        self.assertEqual(len(self.pes.pes_by_naa), 4)

    def test_personalization(self):
        """Test some of the personalization operations."""
        pes = copy.deepcopy(self.pes)
        params = [Puk1('01234567'), Puk2(98765432), Pin1('1111'), Pin2(2222), Adm1('11111111'),
                  K(h2b('000102030405060708090a0b0c0d0e0f')), Opc(h2b('101112131415161718191a1b1c1d1e1f'))]
        for p in params:
            p.validate()
            p.apply(pes)
        # TODO: we don't actually test the results here, but we just verify there is no exception
        pes.to_der()


class DataSourceTest(unittest.TestCase):
    def test_fixed(self):
        FIXED = b'\x01\x02\x03'
        ds = DataSourceFixed(FIXED)
        self.assertEqual(ds.generate_one(), FIXED)
        self.assertEqual(ds.generate_one(), FIXED)
        self.assertEqual(ds.generate_one(), FIXED)

    def test_incrementing(self):
        BASE_VALUE = 100
        ds = DataSourceIncrementing(BASE_VALUE)
        self.assertEqual(ds.generate_one(), BASE_VALUE)
        self.assertEqual(ds.generate_one(), BASE_VALUE+1)
        self.assertEqual(ds.generate_one(), BASE_VALUE+2)
        self.assertEqual(ds.generate_one(), BASE_VALUE+3)

    def test_incrementing_step3(self):
        BASE_VALUE = 300
        ds = DataSourceIncrementing(BASE_VALUE, step_size=3)
        self.assertEqual(ds.generate_one(), BASE_VALUE)
        self.assertEqual(ds.generate_one(), BASE_VALUE+3)
        self.assertEqual(ds.generate_one(), BASE_VALUE+6)

    def test_random(self):
        ds = DataSourceRandomBytes(8)
        res = []
        for i in range(0,100):
            res.append(ds.generate_one())
        for r in res:
            self.assertEqual(len(r), 8)
        # ensure no duplicates exist
        self.assertEqual(len(set(res)), len(res))

    def test_random_int(self):
        ds = DataSourceRandomUInt(below=256)
        res = []
        for i in range(0,100):
            res.append(ds.generate_one())
        for r in res:
            self.assertTrue(r < 256)


if __name__ == "__main__":
	unittest.main()
