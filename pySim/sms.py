"""Code related to SMS Encoding/Decoding"""
# simplistic SMS T-PDU code, as unfortunately nobody bothered to port the python smspdu
# module to python3, and I gave up after >= 3 hours of trying and failing to do so

# (C) 2022 by Harald Welte <laforge@osmocom.org>
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

import typing
from construct import Int8ub, Bytes
from construct import Struct, Tell, this, RepeatUntil

from pySim.utils import Hexstr, h2b, b2h

BytesOrHex = typing.Union[Hexstr, bytes]

class UserDataHeader:
    # a single IE in the user data header
    ie_c = Struct('offset'/Tell, 'iei'/Int8ub, 'length'/Int8ub, 'data'/Bytes(this.length))
    # parser for the full UDH: Length octet followed by sequence of IEs
    _construct = Struct('udhl'/Int8ub,
                        # FIXME: somehow the below lambda is not working, we always only get the first IE?
                        'ies'/RepeatUntil(lambda obj,lst,ctx: ctx._io.tell() > 1+this.udhl, ie_c))

    def __init__(self, ies=[]):
        self.ies = ies

    def __repr__(self) -> str:
        return 'UDH(%r)' % self.ies

    def has_ie(self, iei:int) -> bool:
        for ie in self.ies:
            if ie['iei'] == iei:
                return True
        return False

    @classmethod
    def fromBytes(cls, inb: BytesOrHex) -> typing.Tuple['UserDataHeader', bytes]:
        if isinstance(inb, str):
            inb = h2b(inb)
        res = cls._construct.parse(inb)
        return cls(res['ies']), inb[1+res['udhl']:]
