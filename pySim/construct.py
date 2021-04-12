from construct import *
from pySim.utils import b2h, h2b, swap_nibbles

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

def filter_dict(d, exclude_prefix='_'):
    """filter the input dict to ensure no keys starting with 'exclude_prefix' remain."""
    res = {}
    for (key, value) in d.items():
        if key.startswith(exclude_prefix):
            continue
        if type(value) is dict:
            res[key] = filter_dict(value)
        else:
            res[key] = value
    return res

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
