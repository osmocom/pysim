#!/usr/bin/env python3

import unittest
from pySim.construct import *

tests = [
        ( b'\x80', 0x80 ),
        ( b'\x80\x01', 0x8001 ),
        ( b'\x80\x00\x01', 0x800001 ),
        ( b'\x80\x23\x42\x01', 0x80234201 ),
        ]

class TestGreedyInt(unittest.TestCase):
    def test_GreedyInt_decoder(self):
        gi = GreedyInteger()
        for t in tests:
            self.assertEqual(gi.parse(t[0]), t[1])
    def test_GreedyInt_encoder(self):
        gi = GreedyInteger()
        for t in tests:
            self.assertEqual(t[0], gi.build(t[1]))
        pass

class TestUtils(unittest.TestCase):
    def test_filter_dict(self):
        inp = {'foo': 0xf00, '_bar' : 0xba5, 'baz': 0xba2 }
        out = {'foo': 0xf00, 'baz': 0xba2 }
        self.assertEqual(filter_dict(inp), out)

    def test_filter_dict_nested(self):
        inp = {'foo': 0xf00, 'nest': {'_bar' : 0xba5}, 'baz': 0xba2 }
        out = {'foo': 0xf00, 'nest': {}, 'baz': 0xba2 }
        self.assertEqual(filter_dict(inp), out)


class TestUcs2Adapter(unittest.TestCase):
    # the three examples from TS 102 221 Annex A
    EXAMPLE1 = b'\x80\x00\x30\x00\x31\x00\x32\x00\x33'
    EXAMPLE2 = b'\x81\x05\x13\x53\x95\xa6\xa6\xff\xff'
    EXAMPLE3 = b'\x82\x05\x05\x30\x2d\x82\xd3\x2d\x31'
    ad = Ucs2Adapter(GreedyBytes)

    def test_example1_decode(self):
        dec = self.ad._decode(self.EXAMPLE1, None, None)
        self.assertEqual(dec, "0123")

    def test_example2_decode(self):
        dec = self.ad._decode(self.EXAMPLE2, None, None)
        self.assertEqual(dec, "S\u0995\u09a6\u09a6\u09ff")

    def test_example3_decode(self):
        dec = self.ad._decode(self.EXAMPLE3, None, None)
        self.assertEqual(dec, "-\u0532\u0583-1")

    testdata = [
        # variant 2 with only GSM alphabet characters
        ( "mahlzeit", '8108006d61686c7a656974' ),
        # variant 2 with mixed GSM alphabet + UCS2
        ( "mahlzeit\u099523", '810b136d61686c7a656974953233' ),
        # variant 3 due to codepoint exceeding 8 bit
        ( "mahl\u8023zeit", '820980236d61686c807a656974' ),
        # variant 1 as there is no common codepoint pointer / prefix
        ( "\u3000\u2000\u1000", '80300020001000' ),
    ]

    def test_data_decode(self):
        for string, encoded_hex in self.testdata:
            encoded = h2b(encoded_hex)
            dec = self.ad._decode(encoded, None, None)
            self.assertEqual(dec, string)

    def test_data_encode(self):
        for string, encoded_hex in self.testdata:
            encoded = h2b(encoded_hex)
            re_enc = self.ad._encode(string, None, None)
            self.assertEqual(encoded, re_enc)



if __name__ == "__main__":
	unittest.main()
