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


if __name__ == "__main__":
	unittest.main()
