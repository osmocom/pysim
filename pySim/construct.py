import typing
from construct import *
from pySim.utils import b2h, h2b, swap_nibbles
import gsm0338

"""Utility code related to the integration of the 'construct' declarative parser."""

# (C) 2021 by Harald Welte <laforge@osmocom.org>
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

class BcdAdapter(Adapter):
    """convert a bytes() type to a string of BCD nibbles."""
    def _decode(self, obj, context, path):
        return swap_nibbles(b2h(obj))
    def _encode(self, obj, context, path):
        return h2b(swap_nibbles(obj))

class Rpad(Adapter):
    """
    Encoder appends padding bytes (b'\\xff') up to target size.
    Decoder removes trailing padding bytes.

    Parameters:
        subcon: Subconstruct as defined by construct library
        pattern: set padding pattern (default: b'\\xff')
    """

    def __init__(self, subcon, pattern=b'\xff'):
        super().__init__(subcon)
        self.pattern = pattern

    def _decode(self, obj, context, path):
        return obj.rstrip(self.pattern)

    def _encode(self, obj, context, path):
        if len(obj) > self.sizeof():
            raise SizeofError("Input ({}) exceeds target size ({})".format(len(obj), self.sizeof()))
        return obj + self.pattern * (self.sizeof() - len(obj))

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

from construct.lib.containers import Container, ListContainer
from construct.core import EnumIntegerString

def normalize_construct(c):
    """Convert a construct specific type to a related base type, mostly useful
    so we can serialize it."""
    # we need to include the filter_dict as we otherwise get elements like this
    # in the dict: '_io': <_io.BytesIO object at 0x7fdb64e05860> which we cannot json-serialize
    c = filter_dict(c)
    if isinstance(c, Container) or isinstance(c, dict):
        r = {k : normalize_construct(v) for (k, v) in c.items()}
    elif isinstance(c, ListContainer):
        r = [normalize_construct(x) for x in c]
    elif isinstance(c, list):
        r = [normalize_construct(x) for x in c]
    elif isinstance(c, EnumIntegerString):
        r = str(c)
    else:
        r = c
    return r

def parse_construct(c, raw_bin_data:bytes, length:typing.Optional[int]=None, exclude_prefix:str='_'):
    """Helper function to wrap around normalize_construct() and filter_dict()."""
    if not length:
        length = len(raw_bin_data)
    parsed = c.parse(raw_bin_data, total_len=length)
    return normalize_construct(parsed)

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
