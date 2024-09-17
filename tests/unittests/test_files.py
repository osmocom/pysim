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
from osmocom.utils import *

from pySim.filesystem import *
import pySim.iso7816_4
import pySim.ts_102_221
import pySim.ts_102_222
import pySim.ts_31_102
import pySim.ts_31_103
import pySim.ts_51_011
import pySim.sysmocom_sja2
import pySim.gsm_r
import pySim.cdma_ruim

from construct import Int8ub, Struct, Padding, this
from osmocom.tlv import BER_TLV_IE

def get_qualified_name(c):
    """return the qualified (by module) name of a class."""
    return "%s.%s" % (c.__module__, c.__name__)

class LinFixed_Test(unittest.TestCase):
    classes = all_subclasses(LinFixedEF)
    maxDiff = None

    @staticmethod
    def _parse_t(t):
        """Parse a test description which can either be a 2-tuple of (enc, dec) or
        a 3-tuple of (enc, rec_nr, dec)."""
        if len(t) == 2:
            encoded = t[0]
            rec_num = 1
            decoded = t[1]
        else:
            encoded = t[0]
            rec_num = t[1]
            decoded = t[2]
        return encoded, rec_num, decoded

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
                    encoded, rec_num, decoded = self._parse_t(t)
                    with self.subTest(name, test_decode=t):
                        inst = c()
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_record_hex(encoded, rec_num)
                        self.assertEqual(decoded, re_dec)
                    if hasattr(c, '_test_no_pad') and c._test_no_pad:
                        continue
                    with self.subTest(name, test_decode_padded=t):
                        encoded = encoded + 'ff'
                        inst = c()
                        logging.debug("Testing padded decode of %s", name)
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
                        encoded, rec_num, decoded = self._parse_t(t)
                        logging.debug("Testing encode of %s", name)
                        re_enc = inst.encode_record_hex(decoded, rec_num)
                        self.assertEqual(encoded.upper(), re_enc.upper())

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
                    encoded, rec_num, decoded = self._parse_t(t)
                    with self.subTest(name, test_de_encode=t):
                        inst = c()
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_record_hex(encoded, rec_num)
                        self.assertEqual(decoded, re_dec)
                        # re-encode the decoded data
                        logging.debug("Testing re-encode of %s", name)
                        re_enc = inst.encode_record_hex(re_dec, rec_num)
                        self.assertEqual(encoded.upper(), re_enc.upper())
                    if hasattr(c, '_test_no_pad') and c._test_no_pad:
                        continue
                    with self.subTest(name, test_decode_padded=t):
                        encoded = encoded + 'ff'
                        inst = c()
                        logging.debug("Testing padded decode of %s", name)
                        re_dec = inst.decode_record_hex(encoded, rec_num)
                        self.assertEqual(decoded, re_dec)


class TransRecEF_Test(unittest.TestCase):
    classes = all_subclasses(TransRecEF)
    maxDiff = None

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
                    # there's no point in testing padded input, as TransRecEF have a fixed record
                    # size and we cannot ever receive more input data than that size.

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
                        self.assertEqual(encoded.upper(), re_enc.upper())
                    # there's no point in testing padded input, as TransRecEF have a fixed record
                    # size and we cannot ever receive more input data than that size.


class TransparentEF_Test(unittest.TestCase):
    maxDiff = None

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
                    encoded = t[0]
                    decoded = t[1]
                    with self.subTest(name, test_decode=t):
                        inst = c()
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_hex(encoded)
                        self.assertEqual(decoded, re_dec)
                    if hasattr(c, '_test_no_pad') and c._test_no_pad:
                        continue
                    with self.subTest(name, test_decode_padded=t):
                        encoded = encoded + 'ff'
                        inst = c()
                        logging.debug("Testing padded decode of %s", name)
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
                    encoded = t[0]
                    decoded = t[1]
                    with self.subTest(name, test_de_encode=t):
                        inst = c()
                        logging.debug("Testing decode of %s", name)
                        re_dec = inst.decode_hex(encoded)
                        self.assertEqual(decoded, re_dec)
                        logging.debug("Testing re-encode of %s", name)
                        re_dec = inst.decode_hex(encoded)
                        re_enc = inst.encode_hex(re_dec)
                        self.assertEqual(encoded.upper(), re_enc.upper())
                    if hasattr(c, '_test_no_pad') and c._test_no_pad:
                        continue
                    with self.subTest(name, test_decode_padded=t):
                        encoded = encoded + 'ff'
                        inst = c()
                        logging.debug("Testing padded decode of %s", name)
                        re_dec = inst.decode_hex(encoded)
                        self.assertEqual(decoded, re_dec)


class filesystem_enc_dec_test(unittest.TestCase):
    """ The following set of tests is to verify the code paths in filesystem.py. There are several methods to encode
    or decode a file. Depending on which methods (encode_hex, decode_hex, etc.) or structs (_construct, _tlv) are
    define in the related file object, the encoding/decoding will take a different code path. In this test we will
    try out all of the different encoding/decoding variants by defining one test file for each variant. Then we will
    run an encoding/decoding cycle on each of the test files.

    The test files will also include a padding that is dependent on the total_len keyword argument that is passed
    via the construct context or via **kwargs in case the hand written encoding methods (encode_hex, encode_record_hex,
    etc.) are used. This will ensure that total_len is passed correctly in all possible variants.
    """

    def test_encode_TransparentEF(self):

        class TransparentEF_construct(TransparentEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(2, 2),
                         desc='dummy TransparentEF file to test encoding/decoding via _construct'):
                super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
                self._construct = Struct('test'/Int8ub, Padding(this._.total_len-1))

        class TransparentEF_encode_hex(TransparentEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(2, 2),
                         desc='dummy TransparentEF file to test manual encoding/decoding via _encode/decode_hex'):
                super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
            def _encode_hex(self, in_json, **kwargs):
                return "%02x" % in_json['test'] + "00" * (kwargs.get('total_len') -1)
            def _decode_hex(self, raw_hex):
                return {'test': int(raw_hex[0:2],16)}

        class TransparentEF_encode_bin(TransparentEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(2, 2),
                         desc='dummy TransparentEF file to test manual encoding/decoding via _encode/decode_bin'):
                super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
            def _encode_bin(self, in_json, **kwargs):
                return h2b("%02x" % in_json['test'] + "00" * (kwargs.get('total_len') -1))
            def _decode_bin(self, raw_bin_data: bytearray):
                return {'test': int(b2h(raw_bin_data[0:1]),16)}

        class TransparentEF_tlv(TransparentEF):
            class TestTlv(BER_TLV_IE, tag=0x81):
                _construct = Int8ub
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(1, 1),
                         desc='dummy TransparentEF file to test encoding/decoding via _tlv'):
                super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
                self._tlv = TransparentEF_tlv.TestTlv

        class TransparentEF_raw(TransparentEF):
            class TestTlv(BER_TLV_IE, tag=0x81):
                _construct = Int8ub
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(1, 1),
                         desc='dummy TransparentEF file to test raw encoding/decoding'):
                super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)

        def do_encdec_test(file):
            res = file.encode_hex({'test':0x41})
            self.assertEqual(res,hexstr("4100"))
            res = file.encode_bin({'test':0x41})
            self.assertEqual(b2h(res),hexstr("4100"))
            res = file.encode_hex({'test':0x41}, total_len=3)
            self.assertEqual(res,hexstr("410000"))
            res = file.encode_bin({'test':0x41}, total_len=3)
            self.assertEqual(b2h(res),hexstr("410000"))
            res = file.decode_hex("4100")
            self.assertEqual(res,{'test':0x41})
            res = file.decode_bin(b'\x41\x01')
            self.assertEqual(res,{'test':0x41})

        def do_encdec_test_tlv(file):
            res = file.encode_hex({'test_tlv':0x41})
            self.assertEqual(res,hexstr("810141"))
            res = file.encode_bin({'test_tlv':0x41})
            self.assertEqual(b2h(res),hexstr("810141"))
            res = file.decode_hex(hexstr("810141"))
            self.assertEqual(res,{'test_tlv':0x41})
            res = file.decode_bin(h2b("810141"))
            self.assertEqual(res,{'test_tlv':0x41})

        def do_encdec_test_raw(file):
            res = file.decode_hex("41")
            self.assertEqual(res,{'raw':'41'})
            res = file.decode_bin(b'\x41')
            self.assertEqual(res,{'raw':'41'})

        do_encdec_test(TransparentEF_construct())
        do_encdec_test(TransparentEF_encode_hex())
        do_encdec_test(TransparentEF_encode_bin())
        do_encdec_test_tlv(TransparentEF_tlv())
        do_encdec_test_raw(TransparentEF_raw())

    def test_encode_LinFixedEF(self):

        class LinFixedEF_construct(LinFixedEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY',
                         desc='dummy LinFixedEF file to test encoding/decoding via _construct', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(2, 2), **kwargs)
                self._construct = Struct('test'/Int8ub, Padding(this._.total_len-1))

        class LinFixedEF_encode_hex(LinFixedEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY',
                         desc='dummy LinFixedEF file to test manual encoding/decoding via _encode/decode_hex', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(2, 2), **kwargs)
            def _encode_record_hex(self, in_json, **kwargs):
                return "%02x" % in_json['test'] + "00" * (kwargs.get('total_len') -1)
            def _decode_record_hex(self, in_hex, **kwargs):
                return {'test': int(in_hex[0:2],16)}

        class LinFixedEF_encode_bin(LinFixedEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY',
                         desc='dummy LinFixedEF file to test manual encoding/decoding via _encode/decode_bin', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(2, 2), **kwargs)
            def _encode_record_bin(self, in_json, **kwargs):
                return h2b("%02x" % in_json['test'] + "00" * (kwargs.get('total_len') -1))
            def _decode_record_bin(self, in_bin, **kwargs):
                return {'test': int(b2h(in_bin[0:1]),16)}

        class LinFixedEF_tlv(LinFixedEF):
            class TestTlv(BER_TLV_IE, tag=0x81):
                _construct = Int8ub
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY',
                         desc='dummy LinFixedEF file to test encoding/decoding via _tlv', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(1, 1), **kwargs)
                self._tlv = LinFixedEF_tlv.TestTlv

        class LinFixedEF_raw(LinFixedEF):
            class TestTlv(BER_TLV_IE, tag=0x81):
                _construct = Int8ub
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY',
                         desc='dummy LinFixedEF file to test raw encoding/decoding', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(1, 1), **kwargs)

        def do_encdec_test(file):
            res = file.encode_record_hex({'test':0x41}, 1)
            self.assertEqual(res,hexstr("4100"))
            res = file.encode_record_bin({'test':0x41}, 1)
            self.assertEqual(b2h(res),hexstr("4100"))
            res = file.encode_record_hex({'test':0x41}, 1, total_len=3)
            self.assertEqual(res,hexstr("410000"))
            res = file.encode_record_bin({'test':0x41}, 1, total_len=3)
            self.assertEqual(b2h(res),hexstr("410000"))
            res = file.decode_record_hex("4100", 1)
            self.assertEqual(res,{'test':0x41})
            res = file.decode_record_bin(b'\x41\x00', 1)
            self.assertEqual(res,{'test':0x41})

        def do_encdec_test_tlv(file):
            res = file.encode_record_hex({'test_tlv':0x41}, 1)
            self.assertEqual(res,hexstr("810141"))
            res = file.encode_record_bin({'test_tlv':0x41}, 1)
            self.assertEqual(b2h(res),hexstr("810141"))
            res = file.decode_record_hex(hexstr("810141"), 1)
            self.assertEqual(res,{'test_tlv':0x41})
            res = file.decode_record_bin(h2b("810141"), 1)
            self.assertEqual(res,{'test_tlv':0x41})

        def do_encdec_test_raw(file):
            res = file.decode_record_hex("41", 1)
            self.assertEqual(res,{'raw':'41'})
            res = file.decode_record_bin(b'\x41', 1)
            self.assertEqual(res,{'raw':'41'})

        do_encdec_test(LinFixedEF_construct())
        do_encdec_test(LinFixedEF_encode_hex())
        do_encdec_test(LinFixedEF_encode_bin())
        do_encdec_test_tlv(LinFixedEF_tlv())
        do_encdec_test_raw(LinFixedEF_raw())

    def test_encode_TransRecEF(self):

        class TransRecEF_construct(TransRecEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(2, 2), rec_len=2,
                         desc='dummy TransRecEF file to test encoding/decoding via _construct', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
                self._construct = Struct('test'/Int8ub, Padding(this._.total_len-1))

        class TransRecEF_encode_hex(TransRecEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(2, 2), rec_len=2,
                         desc='dummy TransRecEF file to test manual encoding/decoding via _encode/decode_hex', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
            def _encode_record_hex(self, in_json, **kwargs):
                return "%02x" % in_json['test'] + "00" * (kwargs.get('total_len') -1)
            def _decode_record_hex(self, in_hex, **kwargs):
                return {'test': int(in_hex[0:2],16)}

        class TransRecEF_encode_bin(TransRecEF):
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(2, 2), rec_len=2,
                         desc='dummy TransRecEF file to test manual encoding/decoding via _encode/decode_bin', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
            def _encode_record_bin(self, in_json, **kwargs):
                return h2b("%02x" % in_json['test'] + "00" * (kwargs.get('total_len') -1))
            def _decode_record_bin(self, in_bin, **kwargs):
                return {'test': int(b2h(in_bin[0:1]),16)}

        class TransRecEF_tlv(TransRecEF):
            class TestTlv(BER_TLV_IE, tag=0x81):
                _construct = Int8ub
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(1, 1), rec_len=1,
                         desc='dummy TransRecEF file to test encoding/decoding via _tlv', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
                self._tlv = TransRecEF_tlv.TestTlv

        class TransRecEF_raw(TransRecEF):
            class TestTlv(BER_TLV_IE, tag=0x81):
                _construct = Int8ub
            def __init__(self, fid='0000', sfid=None, name='EF.DUMMY', size=(1, 1), rec_len=1,
                         desc='dummy TransRecEF file to test raw encoding/decoding', **kwargs):
                super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)

        def do_encdec_test(file):
            res = file.encode_record_hex({'test':0x41})
            self.assertEqual(res,hexstr("4100"))
            res = file.encode_record_bin({'test':0x41})
            self.assertEqual(b2h(res),hexstr("4100"))
            res = file.encode_record_hex({'test':0x41}, total_len=3)
            self.assertEqual(res,hexstr("410000"))
            res = file.encode_record_bin({'test':0x41}, total_len=3)
            self.assertEqual(b2h(res),hexstr("410000"))
            res = file.decode_record_hex("4100")
            self.assertEqual(res,{'test':0x41})
            res = file.decode_record_bin(b'\x41\x00')
            self.assertEqual(res,{'test':0x41})

        def do_encdec_test_tlv(file):
            res = file.encode_record_hex({'test_tlv':0x41})
            self.assertEqual(res,hexstr("810141"))
            res = file.encode_record_bin({'test_tlv':0x41})
            self.assertEqual(b2h(res),hexstr("810141"))
            res = file.decode_record_hex(hexstr("810141"))
            self.assertEqual(res,{'test_tlv':0x41})
            res = file.decode_record_bin(h2b("810141"))
            self.assertEqual(res,{'test_tlv':0x41})

        def do_encdec_test_raw(file):
            res = file.decode_record_hex("41")
            self.assertEqual(res,{'raw':'41'})
            res = file.decode_record_bin(b'\x41')
            self.assertEqual(res,{'raw':'41'})

        do_encdec_test(TransRecEF_construct())
        do_encdec_test(TransRecEF_encode_hex())
        do_encdec_test(TransRecEF_encode_bin())
        do_encdec_test_tlv(TransRecEF_tlv())
        do_encdec_test_raw(TransRecEF_raw())


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    unittest.main()
