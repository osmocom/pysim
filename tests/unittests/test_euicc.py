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

class TestResetOptions(unittest.TestCase):

    def test_der_named_bit_string_encodings(self):
        cases = (
            ({}, 'bf3403820100'),
            ({'deleteOperationalProfiles': True}, 'bf340482020780'),
            ({'deleteFieldLoadedTestProfiles': True}, 'bf340482020640'),
            ({'resetDefaultSmdpAddress': True}, 'bf340482020520'),
            ({'deleteOperationalProfiles': True,
              'deleteFieldLoadedTestProfiles': True}, 'bf3404820206c0'),
            ({'deleteOperationalProfiles': True,
              'resetDefaultSmdpAddress': True}, 'bf3404820205a0'),
            ({'deleteFieldLoadedTestProfiles': True,
              'resetDefaultSmdpAddress': True}, 'bf340482020560'),
            ({'deleteOperationalProfiles': True,
              'deleteFieldLoadedTestProfiles': True,
              'resetDefaultSmdpAddress': True}, 'bf3404820205e0'),
        )
        for decoded, expected in cases:
            with self.subTest(decoded=decoded):
                encoded = EuiccMemoryResetReq(children=[ResetOptions(decoded=decoded)]).to_tlv()
                self.assertEqual(encoded.hex(), expected)
                parsed = EuiccMemoryResetReq()
                parsed.from_tlv(encoded)
                actual = parsed.children[0].decoded
                for name in ResetOptionsFlags.flags:
                    self.assertEqual(actual[name], decoded.get(name, False))

    def test_cat_busy_result(self):
        reset = EuiccMemoryResetResp()
        reset.from_tlv(bytes.fromhex('bf3403800105'))
        self.assertEqual(reset.children[0].decoded, 'catBusy')

if __name__ == "__main__":
	unittest.main()
