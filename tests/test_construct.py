#!/usr/bin/env python3

import unittest
from pySim.construct import GreedyInteger

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


if __name__ == "__main__":
	unittest.main()
