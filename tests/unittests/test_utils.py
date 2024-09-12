#!/usr/bin/env python3

import unittest
from pySim import utils
from pySim.legacy import utils as legacy_utils
from pySim.ts_31_102 import EF_SUCI_Calc_Info

# we don't really want to thest TS 102 221, but the underlying DataObject codebase
from pySim.ts_102_221 import AM_DO_EF, AM_DO_DF, SC_DO

class DoTestCase(unittest.TestCase):

    def testSeqOfChoices(self):
        """A sequence of two choices with each a variety of DO/TLVs"""
        arr_seq = utils.DataObjectSequence('arr', sequence=[AM_DO_EF, SC_DO])
        # input data
        dec_in = [{'access_mode': ['update_erase', 'read_search_compare']}, {'control_reference_template':'PIN1'}]
        # encode it once
        encoded = arr_seq.encode(dec_in)
        # decode again
        re_decoded = arr_seq.decode(encoded)
        self.assertEqual(dec_in, re_decoded[0])

class DecTestCase(unittest.TestCase):
	# TS33.501 Annex C.4 test keys
	hnet_pubkey_profile_b = "0272DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD1" # ID 27 in test file
	hnet_pubkey_profile_a = "5A8D38864820197C3394B92613B20B91633CBD897119273BF8E4A6F4EEC0A650" # ID 30 in test file  

	# TS31.121 4.9.4 EF_SUCI_Calc_Info test file
	testfile_suci_calc_info = "A006020101020000A14B80011B8121" +hnet_pubkey_profile_b +"80011E8120" +hnet_pubkey_profile_a

	decoded_testfile_suci = {
		'prot_scheme_id_list': [
			{'priority': 0, 'identifier': 2, 'key_index': 1},
			{'priority': 1, 'identifier': 1, 'key_index': 2},
			{'priority': 2, 'identifier': 0, 'key_index': 0}],
		'hnet_pubkey_list': [
			{'hnet_pubkey_identifier': 27, 'hnet_pubkey': hnet_pubkey_profile_b.lower()}, # because h2b/b2h returns all lower-case
			{'hnet_pubkey_identifier': 30, 'hnet_pubkey': hnet_pubkey_profile_a.lower()}]
	}

	def testSplitHexStringToListOf5ByteEntries(self):
		input_str = "ffffff0003ffffff0002ffffff0001"
		expected = [
			"ffffff0003",
			"ffffff0002",
			"ffffff0001",
		]
		self.assertEqual(legacy_utils.hexstr_to_Nbytearr(input_str, 5), expected)

	def testDecMCCfromPLMN(self):
		self.assertEqual(utils.dec_mcc_from_plmn("92f501"), 295)

	def testDecMCCfromPLMN_unused(self):
		self.assertEqual(utils.dec_mcc_from_plmn("ff0f00"), 4095)

	def testDecMCCfromPLMN_str(self):
		self.assertEqual(utils.dec_mcc_from_plmn_str("92f501"), "295")

	def testDecMCCfromPLMN_unused_str(self):
		self.assertEqual(utils.dec_mcc_from_plmn_str("ff0f00"), "")

	def testDecMNCfromPLMN_twoDigitMNC(self):
		self.assertEqual(utils.dec_mnc_from_plmn("92f501"), 10)

	def testDecMNCfromPLMN_threeDigitMNC(self):
		self.assertEqual(utils.dec_mnc_from_plmn("031263"), 361)

	def testDecMNCfromPLMN_unused(self):
		self.assertEqual(utils.dec_mnc_from_plmn("00f0ff"), 4095)

	def testDecMNCfromPLMN_twoDigitMNC_str(self):
		self.assertEqual(utils.dec_mnc_from_plmn_str("92f501"), "10")

	def testDecMNCfromPLMN_threeDigitMNC_str(self):
		self.assertEqual(utils.dec_mnc_from_plmn_str("031263"), "361")

	def testDecMNCfromPLMN_unused_str(self):
		self.assertEqual(utils.dec_mnc_from_plmn_str("00f0ff"), "")

	def test_enc_plmn(self):
		with self.subTest("2-digit MCC"):
			self.assertEqual(utils.enc_plmn("001", "01F"), "00F110")
			self.assertEqual(utils.enc_plmn("001", "01"), "00F110")
			self.assertEqual(utils.enc_plmn("295", "10"), "92F501")

		with self.subTest("3-digit MCC"):
			self.assertEqual(utils.enc_plmn("001", "001"), "001100")
			self.assertEqual(utils.enc_plmn("302", "361"), "031263")

	def testDecAct_noneSet(self):
		self.assertEqual(utils.dec_act("0000"), [])

	def testDecAct_onlyUtran(self):
		self.assertEqual(utils.dec_act("8000"), ["UTRAN"])

	def testDecAct_onlyEUtran(self):
		self.assertEqual(utils.dec_act("4000"), ["E-UTRAN NB-S1", "E-UTRAN WB-S1"])

	def testDecAct_onlyNgRan(self):
		self.assertEqual(utils.dec_act("0800"), ["NG-RAN"])

	def testDecAct_onlyGsm(self):
		self.assertEqual(utils.dec_act("0084"), ["GSM"])

	def testDecAct_onlyGsmCompact(self):
		self.assertEqual(utils.dec_act("0040"), ["GSM COMPACT"])

	def testDecAct_onlyCdma2000HRPD(self):
		self.assertEqual(utils.dec_act("0020"), ["cdma2000 HRPD"])

	def testDecAct_onlyCdma20001xRTT(self):
		self.assertEqual(utils.dec_act("0010"), ["cdma2000 1xRTT"])

	def testDecAct_allSet(self):
		self.assertEqual(utils.dec_act("ffff"), ['E-UTRAN NB-S1', 'E-UTRAN WB-S1', 'EC-GSM-IoT', 'GSM', 'GSM COMPACT', 'NG-RAN', 'UTRAN', 'cdma2000 1xRTT', 'cdma2000 HRPD'])

	def testDecxPlmn_w_act(self):
		expected = {'mcc': '295', 'mnc': '10', 'act': ["UTRAN"]}
		self.assertEqual(utils.dec_xplmn_w_act("92f5018000"), expected)

	def testFormatxPlmn_w_act(self):
		input_str = "92f501800092f5508000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000"
		expected  = "\t92f5018000 # MCC: 295 MNC: 10 AcT: UTRAN\n"
		expected += "\t92f5508000 # MCC: 295 MNC: 05 AcT: UTRAN\n"
		expected += "\tffffff0000 # unused\n"
		expected += "\tffffff0000 # unused\n"
		expected += "\tffffff0000 # unused\n"
		expected += "\tffffff0000 # unused\n"
		expected += "\tffffff0000 # unused\n"
		expected += "\tffffff0000 # unused\n"
		expected += "\tffffff0000 # unused\n"
		expected += "\tffffff0000 # unused\n"
		self.assertEqual(legacy_utils.format_xplmn_w_act(input_str), expected)


	def testDecodeSuciCalcInfo(self):
		suci_calc_info = EF_SUCI_Calc_Info()
		decoded = suci_calc_info.decode_hex(self.testfile_suci_calc_info)
		self.assertDictEqual(self.decoded_testfile_suci, decoded)

	def testEncodeSuciCalcInfo(self):
		suci_calc_info = EF_SUCI_Calc_Info()
		encoded = suci_calc_info.encode_hex(self.decoded_testfile_suci)
		self.assertEqual(encoded.lower(), self.testfile_suci_calc_info.lower())

	def testEnc_msisdn(self):
		msisdn_encoded = legacy_utils.enc_msisdn("+4916012345678", npi=0x01, ton=0x03)
		self.assertEqual(msisdn_encoded, "0891946110325476f8ffffffffff")
		msisdn_encoded = legacy_utils.enc_msisdn("123456", npi=0x01, ton=0x03)
		self.assertEqual(msisdn_encoded, "04b1214365ffffffffffffffffff")
		msisdn_encoded = legacy_utils.enc_msisdn("12345678901234567890", npi=0x01, ton=0x03)
		self.assertEqual(msisdn_encoded, "0bb121436587092143658709ffff")
		msisdn_encoded = legacy_utils.enc_msisdn("+12345678901234567890", npi=0x01, ton=0x03)
		self.assertEqual(msisdn_encoded, "0b9121436587092143658709ffff")
		msisdn_encoded = legacy_utils.enc_msisdn("", npi=0x01, ton=0x03)
		self.assertEqual(msisdn_encoded, "ffffffffffffffffffffffffffff")
		msisdn_encoded = legacy_utils.enc_msisdn("+", npi=0x01, ton=0x03)
		self.assertEqual(msisdn_encoded, "ffffffffffffffffffffffffffff")

	def testDec_msisdn(self):
		msisdn_decoded = legacy_utils.dec_msisdn("0891946110325476f8ffffffffff")
		self.assertEqual(msisdn_decoded, (1, 1, "+4916012345678"))
		msisdn_decoded = legacy_utils.dec_msisdn("04b1214365ffffffffffffffffff")
		self.assertEqual(msisdn_decoded, (1, 3, "123456"))
		msisdn_decoded = legacy_utils.dec_msisdn("0bb121436587092143658709ffff")
		self.assertEqual(msisdn_decoded, (1, 3, "12345678901234567890"))
		msisdn_decoded = legacy_utils.dec_msisdn("ffffffffffffffffffffffffffff")
		self.assertEqual(msisdn_decoded, None)
		msisdn_decoded = legacy_utils.dec_msisdn("00112233445566778899AABBCCDDEEFF001122330bb121436587092143658709ffff")
		self.assertEqual(msisdn_decoded, (1, 3, "12345678901234567890"))
		msisdn_decoded = legacy_utils.dec_msisdn("ffffffffffffffffffffffffffffffffffffffff0bb121436587092143658709ffff")
		self.assertEqual(msisdn_decoded, (1, 3, "12345678901234567890"))

class TestLuhn(unittest.TestCase):
    def test_verify(self):
        utils.verify_luhn('8988211000000530082')

    def test_encode(self):
        self.assertEqual(utils.calculate_luhn('898821100000053008'), 2)

    def test_sanitize_iccid(self):
        # 19 digits with correct luhn; we expect no change
        self.assertEqual(utils.sanitize_iccid('8988211000000530082'), '8988211000000530082')
        # 20 digits with correct luhn; we expect no change
        self.assertEqual(utils.sanitize_iccid('89882110000005300811'), '89882110000005300811')
        # 19 digits without correct luhn; we expect check digit to be added
        self.assertEqual(utils.sanitize_iccid('8988211000000530081'), '89882110000005300811')
        # 18 digits; we expect luhn check digit to be added
        self.assertEqual(utils.sanitize_iccid('898821100000053008'), '8988211000000530082')

if __name__ == "__main__":
	unittest.main()
