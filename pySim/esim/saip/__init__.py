# Implementation of SimAlliance/TCA Interoperable Profile handling
#
# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import abc
from typing import Tuple, List, Optional, Dict

import asn1tools

from pySim.utils import bertlv_parse_tag, bertlv_parse_len
from pySim.esim import compile_asn1_subdir

asn1 = compile_asn1_subdir('saip')

class ProfileElement:
    def _fixup_sqnInit_dec(self):
        """asn1tools has a bug when working with SEQUENCE OF that have DEFAULT values. Let's work around
        this."""
        if self.type != 'akaParameter':
            return
        sqn_init = self.decoded.get('sqnInit', None)
        if not sqn_init:
            return
        # this weird '0x' value in a string is what we get from our (slightly hacked) ASN.1 syntax
        if sqn_init == '0x000000000000':
            # SEQUENCE (SIZE (32)) OF OCTET STRING (SIZE (6))
            self.decoded['sqnInit'] = [b'\x00'*6] * 32

    def _fixup_sqnInit_enc(self):
        """asn1tools has a bug when working with SEQUENCE OF that have DEFAULT values. Let's work around
        this."""
        if self.type != 'akaParameter':
            return
        sqn_init = self.decoded.get('sqnInit', None)
        if not sqn_init:
            return
        for s in sqn_init:
            if any(s):
                return
        # none of the fields were initialized with a non-default (non-zero) value, so we can skip it
        del self.decoded['sqnInit']

    def parse_der(self, der: bytes):
        """Parse a sequence of PE and store the result in instance attributes."""
        self.type, self.decoded = asn1.decode('ProfileElement', der)
        # work around asn1tools bug regarding DEFAULT for a SEQUENCE OF
        self._fixup_sqnInit_dec()

    @classmethod
    def from_der(cls, der: bytes) -> 'ProfileElement':
        """Construct an instance from given raw, DER encoded bytes."""
        inst = cls()
        inst.parse_der(der)
        return inst

    def to_der(self) -> bytes:
        """Build an encoded DER representation of the instance."""
        # work around asn1tools bug regarding DEFAULT for a SEQUENCE OF
        self._fixup_sqnInit_enc()
        return asn1.encode('ProfileElement', (self.type, self.decoded))

    def __str__(self):
        return self.type


def bertlv_first_segment(binary: bytes) -> Tuple[bytes, bytes]:
    """obtain the first segment of a binary concatenation of BER-TLV objects.
        Returns: tuple of first TLV and remainder."""
    tagdict, remainder = bertlv_parse_tag(binary)
    length, remainder = bertlv_parse_len(remainder)
    tl_length = len(binary) - len(remainder)
    tlv_length = tl_length + length
    return binary[:tlv_length], binary[tlv_length:]

class ProfileElementSequence:
    """A sequence of ProfileElement objects, which is the overall representation of an eSIM profile."""
    def __init__(self):
        self.pe_list: List[ProfileElement] = None
        self.pe_by_type: Dict = {}
        self.pes_by_naa: Dict = {}

    def get_pes_for_type(self, tname: str) -> List[ProfileElement]:
        return self.pe_by_type.get(tname, [])

    def get_pe_for_type(self, tname: str) -> Optional[ProfileElement]:
        l = self.get_pes_for_type(tname)
        if len(l) == 0:
            return None
        assert len(l) == 1
        return l[0]

    def parse_der(self, der: bytes):
        """Parse a sequence of PE and store the result in self.pe_list."""
        self.pe_list = []
        remainder = der
        while len(remainder):
            first_tlv, remainder = bertlv_first_segment(remainder)
            self.pe_list.append(ProfileElement.from_der(first_tlv))
        self._process_pelist()

    def _process_pelist(self):
        self._rebuild_pe_by_type()
        self._rebuild_pes_by_naa()

    def _rebuild_pe_by_type(self):
        self.pe_by_type = {}
        # build a dict {pe_type: [pe, pe, pe]}
        for pe in self.pe_list:
            if pe.type in self.pe_by_type:
                self.pe_by_type[pe.type].append(pe)
            else:
                self.pe_by_type[pe.type] = [pe]

    def _rebuild_pes_by_naa(self):
        """rebuild the self.pes_by_naa dict {naa: [ [pe, pe, pe], [pe, pe] ]} form,
        which basically means for every NAA there's a lsit of instances, and each consists
        of a list of a list of PEs."""
        self.pres_by_naa = {}
        petype_not_naa_related = ['securityDomain', 'rfm', 'application', 'end']
        naa = ['mf', 'usim', 'isim', 'csim']
        cur_naa = None
        cur_naa_list = []
        for pe in self.pe_list:
            # skip all PE that are not related to NAA
            if pe.type in petype_not_naa_related:
                continue
            if pe.type in naa:
                if cur_naa:
                    if not cur_naa in self.pes_by_naa:
                        self.pes_by_naa[cur_naa] = []
                    self.pes_by_naa[cur_naa].append(cur_naa_list)
                cur_naa = pe.type
                cur_naa_list = []
            cur_naa_list.append(pe)
        # append the final one
        if cur_naa and len(cur_naa_list):
            if not cur_naa in self.pes_by_naa:
                self.pes_by_naa[cur_naa] = []
            self.pes_by_naa[cur_naa].append(cur_naa_list)

    @classmethod
    def from_der(cls, der: bytes) -> 'ProfileElementSequence':
        """Construct an instance from given raw, DER encoded bytes."""
        inst = cls()
        inst.parse_der(der)
        return inst

    def to_der(self) -> bytes:
        """Build an encoded DER representation of the instance."""
        out = b''
        for pe in self.pe_list:
            out += pe.to_der()
        return out

    def __repr__(self):
        return "PESequence(%s)" % ', '.join([str(x) for x in self.pe_list])

    def __iter__(self):
        yield from self.pe_list
