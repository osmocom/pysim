#!/usr/bin/env python3

import unittest
import os
from pySim.card_key_provider import *

class TestCardKeyProviderCsv(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        column_keys = {"KI" : "000424252525535532532A0B0C0D0E0F",
                       "OPC" : "000102030405065545645645645D0E0F",
                       "KIC1" : "06410203546406456456450B0C0D0E0F",
                       "KID1" : "00040267840507667609045645645E0F",
                       "KIK1" : "0001020307687607668678678C0D0E0F",
                       "KIC2" : "000142457594860706090A0B0688678F",
                       "KID2" : "600102030405649468690A0B0C0D648F",
                       "KIK2" : "00010203330506070496330B08640E0F",
                       "KIC3" : "000104030405064684686A068C0D0E0F",
                       "KID3" : "00010243048468070809060B0C0D0E0F",
                       "KIK3" : "00010204040506070809488B0C0D0E0F"}

        csv_file_path = os.path.dirname(os.path.abspath(__file__)) + "/test_card_key_provider.csv"
        card_key_provider_register(CardKeyProviderCsv(csv_file_path, column_keys))
        super().__init__(*args, **kwargs)

    def test_card_key_provider_get(self):
        test_data = [{'EXPECTED' : {'PIN1': '1234', 'PUK1': '12345678', 'PIN2': '1223', 'PUK2': '12345678',
                                    'KI': '48a6d5f60567d45299e3ba08594009e7', 'ADM1': '10101010',
                                    'ADM2': '9999999999999999', 'KIC1': '3eb8567fa0b4b1e63bcab13bff5f2702',
                                    'KIC2': 'fd6c173a5b3f04b563808da24237fb46',
                                    'KIC3': '66c8c848e5dff69d70689d155d44f323',
                                    'KID1': 'd78accce870332dced467c173244dd94',
                                    'KID2': 'b3bf050969747b2d2c9389e127a3d791',
                                    'KID3': '40a77deb50d260b3041bbde1b5040625',
                                    'KIK1': '451b503239d818ea34421aa9c2a8887a',
                                    'KIK2': '967716f5fca8ae179f87f76524d1ae6b',
                                    'KIK3': '0884db5eee5409a00fc1bbc57ac52541',
                                    'OPC': '81817574c1961dd272ad080eb2caf279'}, 'ICCID' :"8988211000000000001"},
                     {'EXPECTED' : {'PIN1': '1234', 'PUK1': '12345678', 'PIN2': '1223', 'PUK2': '12345678',
                                    'KI': 'e94d7fa6fb92375dae86744ff6ecef49', 'ADM1': '10101010',
                                    'ADM2': '9999999999999999', 'KIC1': '79b4e39387c66253da68f653381ded44',
                                    'KIC2': '560561b5dba89c1da8d1920049e5e4f7',
                                    'KIC3': '79ff35e84e39305a119af8c79f84e8e5',
                                    'KID1': '233baf89122159553d67545ecedcf8e0',
                                    'KID2': '8fc2874164d7a8e40d72c968bc894ab8',
                                    'KID3': '2e3320f0dda85054d261be920fbfa065',
                                    'KIK1': 'd51b1b17630103d1672a3e9e0e4827ed',
                                    'KIK2': 'd01edbc48be555139506b0d7982bf7ff',
                                    'KIK3': 'a6487a5170849e8e0a03026afea91f5a',
                                    'OPC': '6b0d19ef28bd12f2daac31828d426939'}, 'ICCID' :"8988211000000000002"},
                     {'EXPECTED' : {'PIN1': '1234', 'PUK1': '12345678', 'PIN2': '1223', 'PUK2': '12345678',
                                    'KI': '3cdec1552ef433a89f327905213c5a6e', 'ADM1': '10101010',
                                    'ADM2': '9999999999999999', 'KIC1': '72986b13ce505e12653ad42df5cfca13',
                                    'KIC2': '8f0d1e58b01e833773e5562c4940674d',
                                    'KIC3': '9c72ba5a14d54f489edbffd3d8802f03',
                                    'KID1': 'd23a42995df9ca83f74b2cfd22695526',
                                    'KID2': '5c3a189d12aa1ac6614883d7de5e6c8c',
                                    'KID3': 'a6ace0d303a2b38a96b418ab83c16725',
                                    'KIK1': 'bf2319467d859c12527aa598430caef2',
                                    'KIK2': '6a4c459934bea7e40787976b8881ab01',
                                    'KIK3': '91cd02c38b5f68a98cc90a1f2299538f',
                                    'OPC': '6df46814b1697daca003da23808bbbc3'}, 'ICCID' :"8988211000000000003"}]

        for t in test_data:
            result = card_key_provider_get(["PIN1","PUK1","PIN2","PUK2","KI","ADM1","ADM2","KIC1",
                                            "KIC2","KIC3","KID1","KID2","KID3","KIK1","KIK2","KIK3","OPC"],
                                           "ICCID", t.get('ICCID'))
            self.assertEqual(result, t.get('EXPECTED'))
            result = card_key_provider_get(["PIN1","puk1","PIN2","PUK2","KI","adm1","ADM2","KIC1",
                                            "KIC2","kic3","KID1","KID2","KID3","kik1","KIK2","KIK3","OPC"],
                                           "iccid", t.get('ICCID'))
            self.assertEqual(result, t.get('EXPECTED'))


    def test_card_key_provider_get_field(self):
        test_data = [{'EXPECTED' : "3eb8567fa0b4b1e63bcab13bff5f2702", 'ICCID' :"8988211000000000001"},
                     {'EXPECTED' : "79b4e39387c66253da68f653381ded44", 'ICCID' :"8988211000000000002"},
                     {'EXPECTED' : "72986b13ce505e12653ad42df5cfca13", 'ICCID' :"8988211000000000003"}]

        for t in test_data:
            result = card_key_provider_get_field("KIC1", "ICCID", t.get('ICCID'))
            self.assertEqual(result, t.get('EXPECTED'))
        for t in test_data:
            result = card_key_provider_get_field("kic1", "iccid", t.get('ICCID'))
            self.assertEqual(result, t.get('EXPECTED'))


class TestCardKeyFieldCryptor(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        transport_keys = {"KI" : "000424252525535532532A0B0C0D0E0F",
                          "OPC" : "000102030405065545645645645D0E0F",
                          "KIC1" : "06410203546406456456450B0C0D0E0F",
                          "UICC_SCP03" : "00040267840507667609045645645E0F"}
        self.crypt = CardKeyFieldCryptor(transport_keys)
        super().__init__(*args, **kwargs)

    def test_encrypt_field(self):
        test_data = [{'EXPECTED' : "0b1e1e56cd62645aeb4c2d72a7c98f27",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "OPC"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "NOCRYPT"},
                     {'EXPECTED' : "00248276d2734f108f9761e2f98e2a9d",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "UICC_SCP03_KIC1"},
                     {'EXPECTED' : "00248276d2734f108f9761e2f98e2a9d",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "UICC_SCP03_KID1"},
                     {'EXPECTED' : "00248276d2734f108f9761e2f98e2a9d",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "UICC_SCP03_KIK1"},
                     {'EXPECTED' : "0b1e1e56cd62645aeb4c2d72a7c98f27",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "opc"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "nocrypt"},
                     {'EXPECTED' : "00248276d2734f108f9761e2f98e2a9d",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "uicc_scp03_kic1"},
                     {'EXPECTED' : "00248276d2734f108f9761e2f98e2a9d",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "uicc_scp03_kid1"},
                     {'EXPECTED' : "00248276d2734f108f9761e2f98e2a9d",
                      'PLAINTEXT_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "uicc_scp03_kik1"}]

        for t in test_data:
            result = self.crypt.encrypt_field(t.get('FIELDNAME'), t.get('PLAINTEXT_VAL'))
            self.assertEqual(result, t.get('EXPECTED'))

    def test_decrypt_field(self):
        test_data = [{'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "0b1e1e56cd62645aeb4c2d72a7c98f27", 'FIELDNAME' : "OPC"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "NOCRYPT"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "00248276d2734f108f9761e2f98e2a9d", 'FIELDNAME' : "UICC_SCP03_KIC1"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "00248276d2734f108f9761e2f98e2a9d", 'FIELDNAME' : "UICC_SCP03_KID1"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "00248276d2734f108f9761e2f98e2a9d", 'FIELDNAME' : "UICC_SCP03_KIK1"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "0b1e1e56cd62645aeb4c2d72a7c98f27", 'FIELDNAME' : "opc"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "000102030405060708090a0b0c0d0e0f", 'FIELDNAME' : "nocrypt"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "00248276d2734f108f9761e2f98e2a9d", 'FIELDNAME' : "uicc_scp03_kic1"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "00248276d2734f108f9761e2f98e2a9d", 'FIELDNAME' : "uicc_scp03_kid1"},
                     {'EXPECTED' : "000102030405060708090a0b0c0d0e0f",
                      'ENCRYPTED_VAL' : "00248276d2734f108f9761e2f98e2a9d", 'FIELDNAME' : "uicc_scp03_kik1"}]

        for t in test_data:
            result = self.crypt.decrypt_field(t.get('FIELDNAME'), t.get('ENCRYPTED_VAL'))
            self.assertEqual(result, t.get('EXPECTED'))


if __name__ == "__main__":
	unittest.main()
