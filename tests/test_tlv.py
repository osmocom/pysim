#!/usr/bin/env python3

# (C) 2022 by Harald Welte <laforge@osmocom.org>
# All Rights Reserved
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
from pySim.tlv import *

class TestUtils(unittest.TestCase):
    def test_camel_to_snake(self):
        cases = [
            ('CamelCase', 'camel_case'),
            ('CamelCaseUPPER', 'camel_case_upper'),
            ('Camel_CASE_underSCORE', 'camel_case_under_score'),
        ]
        for c in cases:
            self.assertEqual(camel_to_snake(c[0]), c[1])

    def test_flatten_dict_lists(self):
        inp = [
                { 'first': 1 },
                { 'second': 2 },
                { 'third': 3 },
                ]
        out = { 'first': 1, 'second':2, 'third': 3}
        self.assertEqual(flatten_dict_lists(inp), out)

    def test_flatten_dict_lists_nodict(self):
        inp = [
                { 'first': 1 },
                { 'second': 2 },
                { 'third': 3 },
                4,
                ]
        self.assertEqual(flatten_dict_lists(inp), inp)

    def test_flatten_dict_lists_nested(self):
        inp = {'top': [
                { 'first': 1 },
                { 'second': 2 },
                { 'third': 3 },
                ] }
        out = {'top': { 'first': 1, 'second':2, 'third': 3 } }
        self.assertEqual(flatten_dict_lists(inp), out)

class TestTranscodable(unittest.TestCase):
    class XC_constr_class(Transcodable):
        _construct = Int8ub
        def __init__(self):
            super().__init__();

    def test_XC_constr_class(self):
        """Transcodable derived class with _construct class variable"""
        xc = TestTranscodable.XC_constr_class()
        self.assertEqual(xc.from_bytes(b'\x23'), 35)
        self.assertEqual(xc.to_bytes(), b'\x23')

    class XC_constr_instance(Transcodable):
        def __init__(self):
            super().__init__();
            self._construct = Int8ub

    def test_XC_constr_instance(self):
        """Transcodable derived class with _construct instance variable"""
        xc = TestTranscodable.XC_constr_instance()
        self.assertEqual(xc.from_bytes(b'\x23'), 35)
        self.assertEqual(xc.to_bytes(), b'\x23')

    class XC_method_instance(Transcodable):
        def __init__(self):
            super().__init__();
        def _from_bytes(self, do):
            return ('decoded', do)
        def _to_bytes(self):
            return self.decoded[1]

    def test_XC_method_instance(self):
        """Transcodable derived class with _{from,to}_bytes() methods"""
        xc = TestTranscodable.XC_method_instance()
        self.assertEqual(xc.to_bytes(), b'')
        self.assertEqual(xc.from_bytes(b''), None)
        self.assertEqual(xc.from_bytes(b'\x23'), ('decoded', b'\x23'))
        self.assertEqual(xc.to_bytes(), b'\x23')

class TestIE(unittest.TestCase):
    class MyIE(IE, tag=0x23, desc='My IE description'):
        _construct = Int8ub
        def to_ie(self):
            return self.to_bytes()

    def test_IE_empty(self):
        ie = TestIE.MyIE()
        self.assertEqual(ie.to_dict(), {'my_ie': None})
        self.assertEqual(repr(ie), 'MyIE(None)')
        self.assertEqual(ie.is_constructed(), False)

    def test_IE_from_bytes(self):
        ie = TestIE.MyIE()
        ie.from_bytes(b'\x42')
        self.assertEqual(ie.to_dict(), {'my_ie': 66})
        self.assertEqual(repr(ie), 'MyIE(66)')
        self.assertEqual(ie.is_constructed(), False)
        self.assertEqual(ie.to_bytes(), b'\x42')
        self.assertEqual(ie.to_ie(), b'\x42')

if __name__ == "__main__":
	unittest.main()
