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

from pySim.utils import *
from pySim.filesystem import *

import pySim.iso7816_4
import pySim.ts_102_221
import pySim.ts_102_222
import pySim.ts_31_102
import pySim.ts_31_103
import pySim.ts_51_011
import pySim.sysmocom_sja2
import pySim.gsm_r

def get_qualified_name(c):
    """return the qualified (by module) name of a class."""
    return "%s.%s" % (c.__module__, c.__name__)

class LinFixed_Test(unittest.TestCase):
    classes = all_subclasses(LinFixedEF)

    def test_decode_record(self):
        """Test the decoder for a linear-fixed EF.  Requires the given LinFixedEF subclass
        to have an '_test_decode' attribute, containing a list of tuples. Each tuple can
        either be a
            * 2-tuple (hexstring, decoded_dict) or a
            * 3-tuple (hexstring, record_nr, decoded_dict)
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_decode'):
                for t in c._test_decode:
                    with self.subTest(name, test_decode=t):
                        inst = c()
                        if len(t) == 2:
                            encoded = t[0]
                            rec_num = 1
                            decoded = t[1]
                        else:
                            encoded = t[0]
                            rec_num = t[1]
                            decoded = t[2]
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_record_hex(encoded, rec_num)
                        self.assertEqual(decoded, re_dec)

    def test_encode_record(self):
        """Test the encoder for a linear-fixed EF.  Requires the given LinFixedEF subclass
        to have an '_test_encode' attribute, containing a list of tuples. Each tuple can
        either be a
            * 2-tuple (hexstring, decoded_dict) or a
            * 3-tuple (hexstring, record_nr, decoded_dict)
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_encode'):
                for t in c._test_encode:
                    with self.subTest(name, test_encode=t):
                        inst = c()
                        if len(t) == 2:
                            encoded = t[0]
                            rec_num = 1
                            decoded = t[1]
                        else:
                            encoded = t[0]
                            rec_num = t[1]
                            decoded = t[2]
                        logging.debug("Testing encode of %s", name)
                        re_enc = inst.encode_record_hex(decoded, rec_num)
                        self.assertEqual(encoded, re_enc)

    def test_de_encode_record(self):
        """Test the decoder and encoder for a linear-fixed EF.  Performs first a decoder
        test, and then re-encodes the decoded data, comparing the re-encoded data with the
        initial input data.

        Requires the given LinFixedEF subclass to have a '_test_de_encode' attribute,
        containing a list of tuples. Each tuple can
        either be a
            * 2-tuple (hexstring, decoded_dict) or a
            * 3-tuple (hexstring, record_nr, decoded_dict)
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_de_encode'):
                for t in c._test_de_encode:
                    with self.subTest(name, test_de_encode=t):
                        inst = c()
                        if len(t) == 2:
                            encoded = t[0]
                            rec_num = 1
                            decoded = t[1]
                        else:
                            encoded = t[0]
                            rec_num = t[1]
                            decoded = t[2]
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_record_hex(encoded, rec_num)
                        self.assertEqual(decoded, re_dec)
                        # re-encode the decoded data
                        logging.debug("Testing re-encode of %s", name)
                        re_enc = inst.encode_record_hex(re_dec, rec_num)
                        self.assertEqual(encoded, re_enc)


class TransRecEF_Test(unittest.TestCase):
    classes = all_subclasses(TransRecEF)

    def test_decode_record(self):
        """Test the decoder for a transparent record-oriented EF.  Requires the given TransRecEF subclass
        to have an '_test_decode' attribute, containing a list of tuples. Each tuple has to be a
        2-tuple (hexstring, decoded_dict).
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_decode'):
                for t in c._test_decode:
                    with self.subTest(name, test_decode=t):
                        inst = c()
                        encoded = t[0]
                        decoded = t[1]
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_record_hex(encoded)
                        self.assertEqual(decoded, re_dec)

    def test_encode_record(self):
        """Test the encoder for a transparent record-oriented EF.  Requires the given TransRecEF subclass
        to have an '_test_encode' attribute, containing a list of tuples. Each tuple has to be a
        2-tuple (hexstring, decoded_dict).
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_decode'):
                for t in c._test_decode:
                    with self.subTest(name, test_decode=t):
                        inst = c()
                        encoded = t[0]
                        decoded = t[1]
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_record_hex(encoded)
                        self.assertEqual(decoded, re_dec)


    def test_de_encode_record(self):
        """Test the decoder and encoder for a transparent record-oriented EF.  Performs first a decoder
        test, and then re-encodes the decoded data, comparing the re-encoded data with the
        initial input data.

        Requires the given TransRecEF subclass to have a '_test_de_encode' attribute,
        containing a list of tuples. Each tuple has to be a 2-tuple (hexstring, decoded_dict).
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_de_encode'):
                for t in c._test_de_encode:
                    with self.subTest(name, test_de_encode=t):
                        inst = c()
                        encoded = t[0]
                        decoded = t[1]
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_record_hex(encoded)
                        self.assertEqual(decoded, re_dec)
                        # re-encode the decoded data
                        logging.debug("Testing re-encode of %s", name)
                        re_enc = inst.encode_record_hex(re_dec)
                        self.assertEqual(encoded, re_enc)


class TransparentEF_Test(unittest.TestCase):
    @classmethod
    def get_classes(cls):
        """get list of TransparentEF sub-classes which are not a TransRecEF subclass."""
        classes = all_subclasses(TransparentEF)
        trans_rec_classes = all_subclasses(TransRecEF)
        return filter(lambda c: c not in trans_rec_classes, classes)

    @classmethod
    def setUpClass(cls):
        """set-up method called once for this class by unittest framework"""
        cls.classes = cls.get_classes()

    def test_decode_file(self):
        """Test the decoder for a transparent EF.  Requires the given TransparentEF subclass
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
                        decoded = t[1]
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_hex(encoded)
                        self.assertEqual(decoded, re_dec)

    def test_encode_file(self):
        """Test the encoder for a transparent EF.  Requires the given TransparentEF subclass
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
                        decoded = t[1]
                        logging.debug("Testing encode of %s", name)
                        re_dec = inst.decode_hex(encoded)
                        self.assertEqual(decoded, re_dec)

    def test_de_encode_file(self):
        """Test the decoder and encoder for a transparent EF.  Performs first a decoder
        test, and then re-encodes the decoded data, comparing the re-encoded data with the
        initial input data.

        Requires the given TransparentEF subclass to have a '_test_de_encode' attribute,
        containing a list of tuples. Each tuple is a 2-tuple (hexstring, decoded_dict).
        """
        for c in self.classes:
            name = get_qualified_name(c)
            if hasattr(c, '_test_de_encode'):
                for t in c._test_de_encode:
                    with self.subTest(name, test_de_encode=t):
                        inst = c()
                        encoded = t[0]
                        decoded = t[1]
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_hex(encoded)
                        self.assertEqual(decoded, re_dec)
                        logging.debug("Testing re-encode of %s", name)
                        re_dec = inst.decode_hex(encoded)
                        re_enc = inst.encode_hex(re_dec)
                        self.assertEqual(encoded, re_enc)


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    unittest.main()
