#!/usr/bin/env python3

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier <pmaier@sysmocom.de>
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
import os
from pySim.profile import CardProfile
from pySim.ts_51_011 import CardProfileSIM
from pySim.ts_102_221 import CardProfileUICC

class TestDecodeSelectResponse_CardProfile(unittest.TestCase):

    def decode_select_response(self, card_Profile: CardProfile, testcases: list[dict]):
        for testcase in testcases:
            resp_hex = testcase['resp_hex']
            decoded = card_Profile.decode_select_response(resp_hex)
            if testcase['decoded']:
                self.assertEqual(decoded, testcase['decoded'])
            else:
                print("no testvector to compare against, assuming the following output is correct:")
                print("resp_hex:", resp_hex)
                print("decoded:", decoded)

    def test_CardProfileSIM(self):
        testcases = [
            # MF
            {"resp_hex" : "000000003f000100000000000981020c0400838a838a",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'file_type': 'mf'}}, 'proprietary_info': {'available_memory': 0}, 'file_id': '3f00', 'file_characteristics': '81', 'num_direct_child_df': 2, 'num_direct_child_ef': 12, 'num_chv_unblock_adm_codes': 4}},
            # DF.TELECOM
            {"resp_hex" : "000000007f100200000000000981000d0400838a838a",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'file_type': 'df'}}, 'proprietary_info': {'available_memory': 0}, 'file_id': '7f10', 'file_characteristics': '81', 'num_direct_child_df': 0, 'num_direct_child_ef': 13, 'num_chv_unblock_adm_codes': 4}},
            # EF.MSISDN
            {"resp_hex" : "000000346f40040011ffff0102011a",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'file_type': 'working_ef', 'structure': 'linear_fixed'}, 'record_len': 26, 'num_of_rec': 2}, 'proprietary_info': {}, 'file_id': '6f40', 'file_size': 52, 'access_conditions': '11ffff', 'life_cycle_status_int': 'creation'}},
            # EF.ICCID
            {"resp_hex" : "0000000a2fe204000cffff01020000",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'file_type': 'working_ef', 'structure': 'transparent'}}, 'proprietary_info': {}, 'file_id': '2fe2', 'file_size': 10, 'access_conditions': '0cffff', 'life_cycle_status_int': 'creation'}},
        ]
        self.decode_select_response(CardProfileSIM, testcases)

    def test_CardProfileUICC(self):
        testcases = [
            # MF
            {"resp_hex" : "622c8202782183023f00a50c80017183040003a7388701018a01058b032f0601c60c90016083010183010a83010b",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'shareable': True, 'file_type': 'df', 'structure': 'no_info_given'}, 'record_len': None, 'num_of_rec': None}, 'file_identifier': b'?\x00', 'proprietary_information': {'uicc_characteristics': b'q', 'available_memory': 239416, 'supported_filesystem_commands': {'terminal_capability': True}}, 'life_cycle_status_integer': 'operational_activated', 'security_attrib_referenced': {'ef_arr_file_id': b'/\x06', 'ef_arr_record_nr': 1}, 'pin_status_template_do': [{'ps_do': b'`'}, {'key_reference': 1}, {'key_reference': 10}, {'key_reference': 11}]}},
            # ADF.USIM
            {"resp_hex" : "623d8202782183027fd0840ca0000000871002ff49ff0589a50c80017183040003a7388701018a01058b032f0601c60f90017083010183018183010a83010b",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'shareable': True, 'file_type': 'df', 'structure': 'no_info_given'}, 'record_len': None, 'num_of_rec': None}, 'file_identifier': b'\x7f\xd0', 'df_name': b'\xa0\x00\x00\x00\x87\x10\x02\xffI\xff\x05\x89', 'proprietary_information': {'uicc_characteristics': b'q', 'available_memory': 239416, 'supported_filesystem_commands': {'terminal_capability': True}}, 'life_cycle_status_integer': 'operational_activated', 'security_attrib_referenced': {'ef_arr_file_id': b'/\x06', 'ef_arr_record_nr': 1}, 'pin_status_template_do': [{'ps_do': b'p'}, {'key_reference': 1}, {'key_reference': 129}, {'key_reference': 10}, {'key_reference': 11}]}},
            # ADF.ISIM
            {"resp_hex" : "623d8202782183027fb0840ca0000000871004ff49ff0589a50c80017183040003a7388701018a01058b032f0601c60f90017083010183018183010a83010b",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'shareable': True, 'file_type': 'df', 'structure': 'no_info_given'}, 'record_len': None, 'num_of_rec': None}, 'file_identifier': b'\x7f\xb0', 'df_name': b'\xa0\x00\x00\x00\x87\x10\x04\xffI\xff\x05\x89', 'proprietary_information': {'uicc_characteristics': b'q', 'available_memory': 239416, 'supported_filesystem_commands': {'terminal_capability': True}}, 'life_cycle_status_integer': 'operational_activated', 'security_attrib_referenced': {'ef_arr_file_id': b'/\x06', 'ef_arr_record_nr': 1}, 'pin_status_template_do': [{'ps_do': b'p'}, {'key_reference': 1}, {'key_reference': 129}, {'key_reference': 10}, {'key_reference': 11}]}},
            # EF.IMSI
            {"resp_hex" : "62178202412183026f078a01058b036f060a80020009880138",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'shareable': True, 'file_type': 'working_ef', 'structure': 'transparent'}, 'record_len': None, 'num_of_rec': None}, 'file_identifier': b'o\x07', 'life_cycle_status_integer': 'operational_activated', 'security_attrib_referenced': {'ef_arr_file_id': b'o\x06', 'ef_arr_record_nr': 10}, 'file_size': 9, 'short_file_identifier': 7}},
            # EF.ECC
            {"resp_hex" : "621a82054221000e0283026fb78a01058b036f06088002001c880108",
             "decoded" : {'file_descriptor': {'file_descriptor_byte': {'shareable': True, 'file_type': 'working_ef', 'structure': 'linear_fixed'}, 'record_len': 14, 'num_of_rec': 2}, 'file_identifier': b'o\xb7', 'life_cycle_status_integer': 'operational_activated', 'security_attrib_referenced': {'ef_arr_file_id': b'o\x06', 'ef_arr_record_nr': 8}, 'file_size': 28, 'short_file_identifier': 1}},
        ]
        self.decode_select_response(CardProfileUICC, testcases)

if __name__ == "__main__":
	unittest.main()
