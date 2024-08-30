#!/usr/bin/env python3

# (C) 2023 by Harald Welte <laforge@osmocom.org>
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
import logging

from osmocom.utils import b2h, h2b, all_subclasses
from osmocom.tlv import *

import pySim.iso7816_4
import pySim.ts_102_221
import pySim.ts_102_222
import pySim.ts_31_102
import pySim.ts_31_103
import pySim.ts_51_011
import pySim.sysmocom_sja2
import pySim.gsm_r
import pySim.cdma_ruim
import pySim.global_platform
import pySim.global_platform.http

if 'unittest.util' in __import__('sys').modules:
    # Show full diff in self.assertEqual.
    __import__('sys').modules['unittest.util']._MAX_LENGTH = 999999999

def get_qualified_name(c):
    """return the qualified (by module) name of a class."""
    return "%s.%s" % (c.__module__, c.__name__)

class TLV_IE_Test(unittest.TestCase):
    maxDiff = None

    @classmethod
    def get_classes(cls):
        """get list of TLV_IE sub-classes."""
        return all_subclasses(TLV_IE)

    @classmethod
    def setUpClass(cls):
        """set-up method called once for this class by unittest framework"""
        cls.classes = cls.get_classes()

    def test_decode_tlv(self):
        """Test the decoder for a TLV_IE.  Requires the given TLV_IE subclass
        to have a '_test_decode' attribute, containing a list of tuples. Each tuple
        is a 2-tuple (hexstring, decoded_dict).
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_decode'):
                for t in c._test_decode:
                    with self.subTest(name, test_decode=t):
                        inst = c()
                        encoded = t[0]
                        decoded = { camel_to_snake(c.__name__): t[1] }
                        context = t[2] if len(t) == 3 else {}
                        logging.debug("Testing decode of %s", name)
                        inst.from_tlv(h2b(encoded), context=context)
                        re_dec = inst.to_dict()
                        self.assertEqual(decoded, re_dec)

    def test_encode_tlv(self):
        """Test the encoder for a TLV_IE.  Requires the given TLV_IE subclass
        to have a '_test_encode' attribute, containing a list of tuples. Each tuple
        is a 2-tuple (hexstring, decoded_dict).
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_encode'):
                for t in c._test_encode:
                    with self.subTest(name, test_encode=t):
                        inst = c()
                        encoded = t[0]
                        decoded = { camel_to_snake(c.__name__): t[1] }
                        context = t[2] if len(t) == 3 else {}
                        logging.debug("Testing encode of %s", name)
                        inst.from_dict(decoded)
                        re_enc = b2h(inst.to_tlv(context))
                        self.assertEqual(encoded.upper(), re_enc.upper())

    def test_de_encode_tlv(self):
        """Test the decoder and encoder for a TLV_IE.  Performs first a decoder
        test, and then re-encodes the decoded data, comparing the re-encoded data with the
        initial input data.

        Requires the given TLV_IE subclass to have a '_test_de_encode' attribute,
        containing a list of tuples. Each tuple is a 2-tuple (hexstring, decoded_dict).
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_de_encode'):
                for t in c._test_de_encode:
                    with self.subTest(name, test_de_encode=t):
                        inst = c()
                        encoded = t[0]
                        decoded = { camel_to_snake(c.__name__): t[1] }
                        context = t[2] if len(t) == 3 else {}
                        logging.debug("Testing decode of %s", name)
                        inst.from_tlv(h2b(encoded), context=context)
                        re_dec = inst.to_dict()
                        self.assertEqual(decoded, re_dec)
                        logging.debug("Testing re-encode of %s", name)
                        re_enc = b2h(inst.to_tlv(context=context))
                        self.assertEqual(encoded.upper(), re_enc.upper())


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    unittest.main()
