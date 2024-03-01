#!/usr/bin/env python3

import unittest

from pySim.euicc import *

class TestEid(unittest.TestCase):

    def test_eid_verify(self):
        for eid in ['89049032123451234512345678901235', '89086030202200000022000023022943',
                    '89044045116727494800000004479366', 89044045116727494800000004479366]:
            self.assertTrue(verify_eid_checksum(eid))

    def test_eid_verify_wrong(self):
        self.assertFalse(verify_eid_checksum('89049032123451234512345678901234'))
        self.assertFalse(verify_eid_checksum(89049032123451234512345678901234))

    def test_eid_encode_with_32_digits(self):
        self.assertEqual(compute_eid_checksum('89049032123451234512345678901200'), '89049032123451234512345678901235')
        self.assertEqual(compute_eid_checksum('89086030202200000022000023022900'), '89086030202200000022000023022943')

    def test_eid_encode_with_30digits(self):
        self.assertEqual(compute_eid_checksum('890490321234512345123456789012'), '89049032123451234512345678901235')

    def test_eid_encode_with_wrong_csum(self):
        # input: EID with wrong checksum
        self.assertEqual(compute_eid_checksum('89049032123451234512345678901299'), '89049032123451234512345678901235')
        self.assertEqual(compute_eid_checksum(89049032123451234512345678901299), '89049032123451234512345678901235')

if __name__ == "__main__":
	unittest.main()
