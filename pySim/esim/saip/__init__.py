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
import io
from typing import Tuple, List, Optional, Dict, Union

import asn1tools

from pySim.utils import bertlv_parse_tag, bertlv_parse_len
from pySim.ts_102_221 import FileDescriptor
from pySim.construct import build_construct
from pySim.esim import compile_asn1_subdir
from pySim.esim.saip import templates

asn1 = compile_asn1_subdir('saip')

class File:
    """Internal representation of a file in a profile filesystem.

    Parameters:
        pename: Name string of the profile element
        l: List of tuples [fileDescriptor, fillFileContent, fillFileOffset profile elements]
        template: Applicable FileTemplate describing defaults as per SAIP spec
    """
    def __init__(self, pename: str, l: Optional[List[Tuple]] = None, template: Optional[templates.FileTemplate] = None):
        self.pe_name = pename
        self.template = template
        self.fileDescriptor = {}
        self.stream = None
        # apply some defaults from profile
        if self.template:
            self.from_template(self.template)
        print("after template: %s" % repr(self))
        if l:
            self.from_tuples(l)

    def from_template(self, template: templates.FileTemplate):
        """Determine defaults for file based on given FileTemplate."""
        fdb_dec = {}
        self.rec_len = None
        if template.fid:
            self.fileDescriptor['fileID'] = template.fid.to_bytes(2, 'big')
        if template.sfi:
            self.fileDescriptor['shortEFID'] = bytes([template.sfi])
        if template.arr:
            self.fileDescriptor['securityAttributesReferenced'] = bytes([template.arr])
        # All the files defined in the templates shall have, by default, shareable/not-shareable bit in the file descriptor set to "shareable".
        fdb_dec['shareable'] = True
        if template.file_type in ['LF', 'CY']:
            fdb_dec['file_type'] = 'working_ef'
            if template.rec_len:
                self.record_len = template.rec_len
            if template.nb_rec and template.rec_len:
                self.fileDescriptor['efFileSize'] = (template.nb_rec * template.rec_len).to_bytes(2, 'big') # FIXME
            if template.file_type == 'LF':
                fdb_dec['structure'] = 'linear_fixed'
            elif template.file_type == 'CY':
                fdb_dec['structure'] = 'cyclic'
        elif template.file_type in ['TR', 'BT']:
            fdb_dec['file_type'] = 'working_ef'
            if template.file_size:
                self.fileDescriptor['efFileSize'] = template.file_size.to_bytes(2, 'big') # FIXME
            if template.file_type == 'BT':
                fdb_dec['structure'] = 'ber_tlv'
            elif template.file_type == 'TR':
                fdb_dec['structure'] = 'transparent'
        elif template.file_type in ['MF', 'DF', 'ADF']:
            fdb_dec['file_type'] = 'df'
            fdb_dec['structure'] = 'no_info_given'
        # build file descriptor based on above input data
        fd_dict = {'file_descriptor_byte': fdb_dec}
        if self.rec_len:
            fd_dict['record_len'] = self.rec_len
        self.fileDescriptor['fileDescriptor'] = build_construct(FileDescriptor._construct, fd_dict)
        # FIXME: default_val
        # FIXME: high_update
        # FIXME: params?

    def from_tuples(self, l:List[Tuple]):
        """Parse a list of fileDescriptor, fillFileContent, fillFileOffset tuples into this instance."""
        def get_fileDescriptor(l:List[Tuple]):
            for k, v in l:
                if k == 'fileDescriptor':
                    return v
        fd = get_fileDescriptor(l)
        if not fd:
            raise ValueError("No fileDescriptor found")
        self.fileDescriptor.update(dict(fd))
        self.stream = self.linearize_file_content(l)

    def to_tuples(self) -> List[Tuple]:
        """Generate a list of fileDescriptor, fillFileContent, fillFileOffset tuples into this instance."""
        raise NotImplementedError

    @staticmethod
    def linearize_file_content(l: List[Tuple]) -> Optional[io.BytesIO]:
        """linearize a list of fillFileContent / fillFileOffset tuples into a stream of bytes."""
        stream = io.BytesIO()
        for k, v in l:
            if k == 'doNotCreate':
                return None
            if k == 'fileDescriptor':
                pass
            elif k == 'fillFileOffset':
                stream.write(b'\xff' * v)
            elif k == 'fillFileContent':
                stream.write(v)
            else:
                return ValueError("Unknown key '%s' in tuple list" % k)
        return stream

    def __str__(self) -> str:
        return "File(%s)" % self.pe_name

    def __repr__(self) -> str:
        return "File(%s): %s" % (self.pe_name, self.fileDescriptor)

class ProfileElement:
    """Class representing a Profile Element (PE) within a SAIP Profile."""
    FILE_BEARING = ['mf', 'cd', 'telecom', 'usim', 'opt-usim', 'isim', 'opt-isim', 'phonebook', 'gsm-access',
                    'csim', 'opt-csim', 'eap', 'df-5gs', 'df-saip', 'df-snpn', 'df-5gprose', 'iot', 'opt-iot']
    def _fixup_sqnInit_dec(self) -> None:
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

    def _fixup_sqnInit_enc(self) -> None:
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

    def parse_der(self, der: bytes) -> None:
        """Parse a sequence of PE and store the result in instance attributes."""
        self.type, self.decoded = asn1.decode('ProfileElement', der)
        # work around asn1tools bug regarding DEFAULT for a SEQUENCE OF
        self._fixup_sqnInit_dec()

    @property
    def header_name(self) -> str:
        """Return the name of the header field within the profile element."""
        # unneccessarry compliaction by inconsistent naming :(
        if self.type.startswith('opt-'):
            return self.type.replace('-','') + '-header'
        return self.type + '-header'

    @property
    def header(self):
        """Return the decoded ProfileHeader."""
        return self.decoded.get(self.header_name, None)

    @property
    def templateID(self):
        """Return the decoded templateID used by this profile element (if any)."""
        return self.decoded.get('templateID', None)

    @property
    def files(self):
        """Return dict of decoded 'File' ASN.1 items."""
        if not self.type in self.FILE_BEARING:
            return {}
        return {k:v for (k,v) in self.decoded.items() if k not in ['templateID', self.header_name]}

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

    def __str__(self) -> str:
        return self.type


def bertlv_first_segment(binary: bytes) -> Tuple[bytes, bytes]:
    """obtain the first segment of a binary concatenation of BER-TLV objects.
        Returns: tuple of first TLV and remainder."""
    _tagdict, remainder = bertlv_parse_tag(binary)
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
        """Return list of profile elements present for given profile element type."""
        return self.pe_by_type.get(tname, [])

    def get_pe_for_type(self, tname: str) -> Optional[ProfileElement]:
        """Return a single profile element for given profile element type. Works only for
        types of which there is only a signle instance in the PE Sequence!"""
        l = self.get_pes_for_type(tname)
        if len(l) == 0:
            return None
        assert len(l) == 1
        return l[0]

    def parse_der(self, der: bytes) -> None:
        """Parse a sequence of PE and store the result in self.pe_list."""
        self.pe_list = []
        remainder = der
        while len(remainder):
            first_tlv, remainder = bertlv_first_segment(remainder)
            self.pe_list.append(ProfileElement.from_der(first_tlv))
        self._process_pelist()

    def _process_pelist(self) -> None:
        self._rebuild_pe_by_type()
        self._rebuild_pes_by_naa()

    def _rebuild_pe_by_type(self) -> None:
        self.pe_by_type = {}
        # build a dict {pe_type: [pe, pe, pe]}
        for pe in self.pe_list:
            if pe.type in self.pe_by_type:
                self.pe_by_type[pe.type].append(pe)
            else:
                self.pe_by_type[pe.type] = [pe]

    def _rebuild_pes_by_naa(self) -> None:
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
        if cur_naa and len(cur_naa_list) > 0:
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

    def __repr__(self) -> str:
        return "PESequence(%s)" % ', '.join([str(x) for x in self.pe_list])

    def __iter__(self) -> str:
        yield from self.pe_list
