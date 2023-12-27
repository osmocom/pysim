from construct.lib.containers import Container, ListContainer
from construct.core import EnumIntegerString
import typing
from construct import *
from construct.core import evaluate, BitwisableString
from construct.lib import integertypes
from pySim.utils import b2h, h2b, swap_nibbles
import gsm0338
import codecs
import ipaddress

"""Utility code related to the integration of the 'construct' declarative parser."""

# (C) 2021-2022 by Harald Welte <laforge@osmocom.org>
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


class HexAdapter(Adapter):
    """convert a bytes() type to a string of hex nibbles."""

    def _decode(self, obj, context, path):
        return b2h(obj)

    def _encode(self, obj, context, path):
        return h2b(obj)

class Utf8Adapter(Adapter):
    """convert a bytes() type that contains utf8 encoded text to human readable text."""

    def _decode(self, obj, context, path):
        # In case the string contains only 0xff bytes we interpret it as an empty string
        if obj == b'\xff' * len(obj):
                return ""
        return codecs.decode(obj, "utf-8")

    def _encode(self, obj, context, path):
        return codecs.encode(obj, "utf-8")

class GsmOrUcs2Adapter(Adapter):
    """Try to encode into a GSM 03.38 string; if that fails, fall back to UCS-2 as described
    in TS 102 221 Annex A."""
    def _decode(self, obj, context, path):
        # In case the string contains only 0xff bytes we interpret it as an empty string
        if obj == b'\xff' * len(obj):
                return ""
        # one of the magic bytes of TS 102 221 Annex A
        if obj[0] in [0x80, 0x81, 0x82]:
            ad = Ucs2Adapter(GreedyBytes)
        else:
            ad = GsmString(GreedyBytes)
        return ad._decode(obj, context, path)

    def _encode(self, obj, context, path):
        # first try GSM 03.38; then fall back to TS 102 221 Annex A UCS-2
        try:
            ad = GsmString(GreedyBytes)
            return ad._encode(obj, context, path)
        except:
            ad = Ucs2Adapter(GreedyBytes)
            return ad._encode(obj, context, path)

class Ucs2Adapter(Adapter):
    """convert a bytes() type that contains UCS2 encoded characters encoded as defined in TS 102 221
    Annex A to normal python string representation (and back)."""
    def _decode(self, obj, context, path):
        # In case the string contains only 0xff bytes we interpret it as an empty string
        if obj == b'\xff' * len(obj):
                return ""
        if obj[0] == 0x80:
            # TS 102 221 Annex A Variant 1
            return codecs.decode(obj[1:], 'utf_16_be')
        elif obj[0] == 0x81:
            # TS 102 221 Annex A Variant 2
            out = ""
            # second byte contains a value indicating the number of characters
            num_of_chars = obj[1]
            # the third byte contains an 8 bit number which defines bits 15 to 8 of a 16 bit base
            # pointer, where bit 16 is set to zero, and bits 7 to 1 are also set to zero. These
            # sixteen bits constitute a base pointer to a "half-page" in the UCS2 code space
            base_ptr = obj[2] << 7
            for ch in obj[3:3+num_of_chars]:
                # if bit 8 of the byte is set to zero, the remaining 7 bits of the byte contain a
                # GSM Default Alphabet character, whereas if bit 8 of the byte is set to one, then
                # the remaining seven bits are an offset value added to the 16 bit base pointer
                # defined earlier, and the resultant 16 bit value is a UCS2 code point
                if ch & 0x80:
                    codepoint = (ch & 0x7f) + base_ptr
                    out += codecs.decode(codepoint.to_bytes(2, byteorder='big'), 'utf_16_be')
                else:
                    out += codecs.decode(bytes([ch]), 'gsm03.38')
            return out
        elif obj[0] == 0x82:
            # TS 102 221 Annex A Variant 3
            out = ""
            # second byte contains a value indicating the number of characters
            num_of_chars = obj[1]
            # third and fourth bytes contain a 16 bit number which defines the complete 16 bit base
            # pointer to a half-page in the UCS2 code space, for use with some or all of the
            # remaining bytes in the string
            base_ptr = obj[2] << 8 | obj[3]
            for ch in obj[4:4+num_of_chars]:
                # if bit 8 of the byte is set to zero, the remaining 7 bits of the byte contain a
                # GSM Default Alphabet character, whereas if bit 8 of the byte is set to one, the
                # remaining seven bits are an offset value added to the base pointer defined in
                # bytes three and four, and the resultant 16 bit value is a UCS2 code point, else: #
                # GSM default alphabet
                if ch & 0x80:
                    codepoint = (ch & 0x7f) + base_ptr
                    out += codecs.decode(codepoint.to_bytes(2, byteorder='big'), 'utf_16_be')
                else:
                    out += codecs.decode(bytes([ch]), 'gsm03.38')
            return out
        else:
            raise ValueError('First byte of TS 102 221 UCS-2 must be 0x80, 0x81 or 0x82')

    def _encode(self, obj, context, path):
        def encodable_in_gsm338(instr: str) -> bool:
            """Determine if given input string is encode-ale in gsm03.38."""
            try:
                # TODO: figure out if/how we can constrain to default alphabet.  The gsm0338
                # library seems to include the spanish lock/shift table
                codecs.encode(instr, 'gsm03.38')
            except ValueError:
                return False
            return True

        def codepoints_not_in_gsm338(instr: str) -> typing.List[int]:
            """Return an integer list of UCS2 codepoints for all characters of 'inster'
            which are not representable in the GSM 03.38 default alphabet."""
            codepoint_list = []
            for c in instr:
                if encodable_in_gsm338(c):
                    continue
                c_codepoint = int.from_bytes(codecs.encode(c, 'utf_16_be'), byteorder='big')
                codepoint_list.append(c_codepoint)
            return codepoint_list

        def diff_between_min_and_max_of_list(inlst: typing.List) -> int:
            return max(inlst) - min(inlst)

        def encodable_in_variant2(instr: str) -> bool:
            codepoint_prefix = None
            for c in instr:
                if encodable_in_gsm338(c):
                    continue
                c_codepoint = int.from_bytes(codecs.encode(c, 'utf_16_be'), byteorder='big')
                if c_codepoint >= 0x8000:
                    return False
                c_prefix = c_codepoint >> 7
                if codepoint_prefix is None:
                    codepoint_prefix = c_prefix
                else:
                    if c_prefix != codepoint_prefix:
                        return False
            return True

        def encodable_in_variant3(instr: str) -> bool:
            codepoint_list = codepoints_not_in_gsm338(instr)
            # compute delta between max and min; check if it's encodable in 7 bits
            if diff_between_min_and_max_of_list(codepoint_list) >= 0x80:
                return False
            return True

        def _encode_variant1(instr: str) -> bytes:
            """Encode according to TS 102 221 Annex A Variant 1"""
            return b'\x80' + codecs.encode(obj, 'utf_16_be')

        def _encode_variant2(instr: str) -> bytes:
            """Encode according to TS 102 221 Annex A Variant 2"""
            codepoint_prefix = None
            # second byte contains a value indicating the number of characters
            hdr = b'\x81' + len(instr).to_bytes(1, byteorder='big')
            chars = b''
            for c in instr:
                try:
                    enc = codecs.encode(c, 'gsm03.38')
                except ValueError:
                    c_codepoint = int.from_bytes(codecs.encode(c, 'utf_16_be'), byteorder='big')
                    c_prefix = c_codepoint >> 7
                    if codepoint_prefix is None:
                        codepoint_prefix = c_prefix
                    assert codepoint_prefix == c_prefix
                    enc = (0x80 + (c_codepoint & 0x7f)).to_bytes(1, byteorder='big')
                chars += enc
            if codepoint_prefix == None:
                codepoint_prefix = 0
            return hdr + codepoint_prefix.to_bytes(1, byteorder='big') + chars

        def _encode_variant3(instr: str) -> bytes:
            """Encode according to TS 102 221 Annex A Variant 3"""
            # second byte contains a value indicating the number of characters
            hdr = b'\x82' + len(instr).to_bytes(1, byteorder='big')
            chars = b''
            codepoint_list = codepoints_not_in_gsm338(instr)
            codepoint_base = min(codepoint_list)
            for c in instr:
                try:
                    # if bit 8 of the byte is set to zero, the remaining 7 bits of the byte contain a GSM
                    # Default # Alphabet character
                    enc = codecs.encode(c, 'gsm03.38')
                except ValueError:
                    # if bit 8 of the byte is set to one, the remaining seven bits are an offset
                    # value added to the base pointer defined in bytes three and four, and the
                    # resultant 16 bit value is a UCS2 code point
                    c_codepoint = int.from_bytes(codecs.encode(c, 'utf_16_be'), byteorder='big')
                    c_codepoint_delta = c_codepoint - codepoint_base
                    assert c_codepoint_delta < 0x80
                    enc = (0x80 + c_codepoint_delta).to_bytes(1, byteorder='big')
                chars += enc
            # third and fourth bytes contain a 16 bit number which defines the complete 16 bit base
            # pointer to a half-page in the UCS2 code space
            return hdr + codepoint_base.to_bytes(2, byteorder='big') + chars

        if encodable_in_variant2(obj):
            return _encode_variant2(obj)
        elif encodable_in_variant3(obj):
            return _encode_variant3(obj)
        else:
            return _encode_variant1(obj)

class BcdAdapter(Adapter):
    """convert a bytes() type to a string of BCD nibbles."""

    def _decode(self, obj, context, path):
        return swap_nibbles(b2h(obj))

    def _encode(self, obj, context, path):
        return h2b(swap_nibbles(obj))

class PlmnAdapter(BcdAdapter):
    """convert a bytes(3) type to BCD string like 262-02 or 262-002."""
    def _decode(self, obj, context, path):
        bcd = super()._decode(obj, context, path)
        if bcd[3] == 'f':
            return '-'.join([bcd[:3], bcd[4:]])
        else:
            return '-'.join([bcd[:3], bcd[3:]])

    def _encode(self, obj, context, path):
        l = obj.split('-')
        if len(l[1]) == 2:
            bcd = l[0] + 'f' + l[1]
        else:
            bcd = l[0] + l[1]
        return super()._encode(bcd, context, path)

class InvertAdapter(Adapter):
    """inverse logic (false->true, true->false)."""
    @staticmethod
    def _invert_bool_in_obj(obj):
        for k,v in obj.items():
            # skip all private entries
            if k.startswith('_'):
                continue
            if v == False:
                obj[k] = True
            elif v == True:
                obj[k] = False
        return obj

    def _decode(self, obj, context, path):
        return self._invert_bool_in_obj(obj)

    def _encode(self, obj, context, path):
        return self._invert_bool_in_obj(obj)

class Rpad(Adapter):
    """
    Encoder appends padding bytes (b'\\xff') or characters up to target size.
    Decoder removes trailing padding bytes/characters.

    Parameters:
        subcon: Subconstruct as defined by construct library
        pattern: set padding pattern (default: b'\\xff')
        num_per_byte: number of 'elements' per byte. E.g. for hex nibbles: 2
    """

    def __init__(self, subcon, pattern=b'\xff', num_per_byte=1):
        super().__init__(subcon)
        self.pattern = pattern
        self.num_per_byte = num_per_byte

    def _decode(self, obj, context, path):
        return obj.rstrip(self.pattern)

    def _encode(self, obj, context, path):
        target_size = self.sizeof() * self.num_per_byte
        if len(obj) > target_size:
            raise SizeofError("Input ({}) exceeds target size ({})".format(
                len(obj), target_size))
        return obj + self.pattern * (target_size - len(obj))

class MultiplyAdapter(Adapter):
    """
    Decoder multiplies by multiplicator
    Encoder divides by multiplicator

    Parameters:
        subcon: Subconstruct as defined by construct library
        multiplier: Multiplier to apply to raw encoded value
    """

    def __init__(self, subcon, multiplicator):
        super().__init__(subcon)
        self.multiplicator = multiplicator

    def _decode(self, obj, context, path):
        return obj * 8

    def _encode(self, obj, context, path):
        return obj // 8


class GsmStringAdapter(Adapter):
    """Convert GSM 03.38 encoded bytes to a string."""

    def __init__(self, subcon, codec='gsm03.38', err='strict'):
        super().__init__(subcon)
        self.codec = codec
        self.err = err

    def _decode(self, obj, context, path):
        return obj.decode(self.codec)

    def _encode(self, obj, context, path):
        return obj.encode(self.codec, self.err)

class Ipv4Adapter(Adapter):
    """
    Encoder converts from 4 bytes to string representation (A.B.C.D).
    Decoder converts from string representation (A.B.C.D) to four bytes.
    """
    def _decode(self, obj, context, path):
        ia = ipaddress.IPv4Address(obj)
        return ia.compressed

    def _encode(self, obj, context, path):
        ia = ipaddress.IPv4Address(obj)
        return ia.packed

class Ipv6Adapter(Adapter):
    """
    Encoder converts from 16 bytes to string representation.
    Decoder converts from string representation to 16 bytes.
    """
    def _decode(self, obj, context, path):
        ia = ipaddress.IPv6Address(obj)
        return ia.compressed

    def _encode(self, obj, context, path):
        ia = ipaddress.IPv6Address(obj)
        return ia.packed


def filter_dict(d, exclude_prefix='_'):
    """filter the input dict to ensure no keys starting with 'exclude_prefix' remain."""
    if not isinstance(d, dict):
        return d
    res = {}
    for (key, value) in d.items():
        if key.startswith(exclude_prefix):
            continue
        if type(value) is dict:
            res[key] = filter_dict(value)
        else:
            res[key] = value
    return res


def normalize_construct(c):
    """Convert a construct specific type to a related base type, mostly useful
    so we can serialize it."""
    # we need to include the filter_dict as we otherwise get elements like this
    # in the dict: '_io': <_io.BytesIO object at 0x7fdb64e05860> which we cannot json-serialize
    c = filter_dict(c)
    if isinstance(c, Container) or isinstance(c, dict):
        r = {k: normalize_construct(v) for (k, v) in c.items()}
    elif isinstance(c, ListContainer):
        r = [normalize_construct(x) for x in c]
    elif isinstance(c, list):
        r = [normalize_construct(x) for x in c]
    elif isinstance(c, EnumIntegerString):
        r = str(c)
    else:
        r = c
    return r


def parse_construct(c, raw_bin_data: bytes, length: typing.Optional[int] = None, exclude_prefix: str = '_', context: dict = {}):
    """Helper function to wrap around normalize_construct() and filter_dict()."""
    if not length:
        length = len(raw_bin_data)
    parsed = c.parse(raw_bin_data, total_len=length, **context)
    return normalize_construct(parsed)

def build_construct(c, decoded_data, context: dict = {}):
    """Helper function to handle total_len."""
    return c.build(decoded_data, total_len=None, **context)

# here we collect some shared / common definitions of data types
LV = Prefixed(Int8ub, HexAdapter(GreedyBytes))

# Default value for Reserved for Future Use (RFU) bits/bytes
# See TS 31.101 Sec. "3.4 Coding Conventions"
__RFU_VALUE = 0

# Field that packs Reserved for Future Use (RFU) bit
FlagRFU = Default(Flag, __RFU_VALUE)

# Field that packs Reserved for Future Use (RFU) byte
ByteRFU = Default(Byte, __RFU_VALUE)

# Field that packs all remaining Reserved for Future Use (RFU) bytes
GreedyBytesRFU = Default(GreedyBytes, b'')


def BitsRFU(n=1):
    '''
    Field that packs Reserved for Future Use (RFU) bit(s)
    as defined in TS 31.101 Sec. "3.4 Coding Conventions"

    Use this for (currently) unused/reserved bits whose contents
    should be initialized automatically but should not be cleared
    in the future or when restoring read data (unlike padding).

    Parameters:
        n (Integer): Number of bits (default: 1)
    '''
    return Default(BitsInteger(n), __RFU_VALUE)


def BytesRFU(n=1):
    '''
    Field that packs Reserved for Future Use (RFU) byte(s)
    as defined in TS 31.101 Sec. "3.4 Coding Conventions"

    Use this for (currently) unused/reserved bytes whose contents
    should be initialized automatically but should not be cleared
    in the future or when restoring read data (unlike padding).

    Parameters:
        n (Integer): Number of bytes (default: 1)
    '''
    return Default(Bytes(n), __RFU_VALUE)


def GsmString(n):
    '''
    GSM 03.38 encoded byte string of fixed length n.
    Encoder appends padding bytes (b'\\xff') to maintain
    length. Decoder removes those trailing bytes.

    Exceptions are raised for invalid characters
    and length excess.

    Parameters:
        n (Integer): Fixed length of the encoded byte string
    '''
    return GsmStringAdapter(Rpad(Bytes(n), pattern=b'\xff'), codec='gsm03.38')

def GsmOrUcs2String(n):
    '''
    GSM 03.38 or UCS-2 (TS 102 221 Annex A) encoded byte string of fixed length n.
    Encoder appends padding bytes (b'\\xff') to maintain
    length. Decoder removes those trailing bytes.

    Exceptions are raised for invalid characters
    and length excess.

    Parameters:
        n (Integer): Fixed length of the encoded byte string
    '''
    return GsmOrUcs2Adapter(Rpad(Bytes(n), pattern=b'\xff'))

class GreedyInteger(Construct):
    """A variable-length integer implementation, think of combining GrredyBytes with BytesInteger."""
    def __init__(self, signed=False, swapped=False, minlen=0):
        super().__init__()
        self.signed = signed
        self.swapped = swapped
        self.minlen = minlen

    def _parse(self, stream, context, path):
        data = stream_read_entire(stream, path)
        if evaluate(self.swapped, context):
            data = swapbytes(data)
        try:
            return int.from_bytes(data, byteorder='big', signed=self.signed)
        except ValueError as e:
            raise IntegerError(str(e), path=path)

    def __bytes_required(self, i, minlen=0):
        if self.signed:
            raise NotImplementedError("FIXME: Implement support for encoding signed integer")

        # compute how many bytes we need
        nbytes = 1
        while True:
            i = i >> 8
            if i == 0:
                break
            else:
                nbytes = nbytes + 1

        # round up to the minimum number
        # of bytes we anticipate
        if nbytes < minlen:
            nbytes = minlen

        return nbytes

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, integertypes):
            raise IntegerError(f"value {obj} is not an integer", path=path)
        length = self.__bytes_required(obj, self.minlen)
        try:
            data = obj.to_bytes(length, byteorder='big', signed=self.signed)
        except ValueError as e:
            raise IntegerError(str(e), path=path)
        if evaluate(self.swapped, context):
            data = swapbytes(data)
        stream_write(stream, data, length, path)
        return obj

# merged definitions of 24.008 + 23.040
TypeOfNumber = Enum(BitsInteger(3), unknown=0, international=1, national=2, network_specific=3,
                    short_code=4, alphanumeric=5, abbreviated=6, reserved_for_extension=7)
NumberingPlan = Enum(BitsInteger(4), unknown=0, isdn_e164=1, data_x121=3, telex_f69=4,
                     sc_specific_5=5, sc_specific_6=6, national=8, private=9,
                     ermes=10, reserved_cts=11, reserved_for_extension=15)
TonNpi = BitStruct('ext'/Flag, 'type_of_number'/TypeOfNumber, 'numbering_plan_id'/NumberingPlan)
