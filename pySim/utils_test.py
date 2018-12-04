#!/usr/bin/pyton

import unittest
import utils 

class DecTestCase(unittest.TestCase):

	def testSplitHexStringToListOf5ByteEntries(self):
		input_str = "ffffff0003ffffff0002ffffff0001"
		expected = [
			"ffffff0003",
			"ffffff0002",
			"ffffff0001",
		]
		self.assertEqual(utils.hexstr_to_fivebytearr(input_str), expected)

	def testDecMCCfromPLMN(self):
		self.assertEqual(utils.dec_mcc_from_plmn("92f501"), 295)

	def testDecMCCfromPLMN_unused(self):
		self.assertEqual(utils.dec_mcc_from_plmn("ff0f00"), 4095)

	def testDecMNCfromPLMN_twoDigitMNC(self):
		self.assertEqual(utils.dec_mnc_from_plmn("92f501"), 10)

	def testDecMNCfromPLMN_threeDigitMNC(self):
		self.assertEqual(utils.dec_mnc_from_plmn("031263"), 361)

	def testDecMNCfromPLMN_unused(self):
		self.assertEqual(utils.dec_mnc_from_plmn("00f0ff"), 4095)

	def testDecAct_noneSet(self):
		self.assertEqual(utils.dec_act("0000"), [])

	def testDecAct_onlyUtran(self):
		self.assertEqual(utils.dec_act("8000"), ["UTRAN"])

	def testDecAct_onlyEUtran(self):
		self.assertEqual(utils.dec_act("4000"), ["E-UTRAN"])

	def testDecAct_onlyGsm(self):
		self.assertEqual(utils.dec_act("0080"), ["GSM"])

	def testDecAct_onlyGsmCompact(self):
		self.assertEqual(utils.dec_act("0040"), ["GSM COMPACT"])

	def testDecAct_onlyCdma2000HRPD(self):
		self.assertEqual(utils.dec_act("0020"), ["cdma2000 HRPD"])

	def testDecAct_onlyCdma20001xRTT(self):
		self.assertEqual(utils.dec_act("0010"), ["cdma2000 1xRTT"])

	def testDecAct_allSet(self):
		self.assertEqual(utils.dec_act("ffff"), ["UTRAN", "E-UTRAN", "GSM", "GSM COMPACT", "cdma2000 HRPD", "cdma2000 1xRTT"])

	def testDecxPlmn_w_act(self):
		expected = {'mcc': 295, 'mnc': 10, 'act': ["UTRAN"]}
		self.assertEqual(utils.dec_xplmn_w_act("92f5018000"), expected)

	def testFormatxPlmn_w_act(self):
		input_str = "92f501800092f5508000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000ffffff0000"
		expected = '''92f5018000 # MCC: 295 MNC:  10 AcT: UTRAN
92f5508000 # MCC: 295 MNC:   5 AcT: UTRAN
ffffff0000 # unused
ffffff0000 # unused
ffffff0000 # unused
ffffff0000 # unused
ffffff0000 # unused
ffffff0000 # unused
ffffff0000 # unused
ffffff0000 # unused
'''
		self.assertEqual(utils.format_xplmn_w_act(input_str), expected)

if __name__ == "__main__":
	unittest.main()
