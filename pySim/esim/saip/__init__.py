"""Implementation of SimAlliance/TCA Interoperable Profile handling"""

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

import logging
import abc
import io
import os
from typing import Tuple, List, Optional, Dict, Union
from collections import OrderedDict
import asn1tools
import zipfile
from pySim import javacard
from osmocom.utils import b2h, h2b, Hexstr
from osmocom.tlv import BER_TLV_IE, bertlv_parse_tag, bertlv_parse_len
from osmocom.construct import build_construct, parse_construct, GreedyInteger, GreedyBytes, StripHeaderAdapter

from pySim import ts_102_222
from pySim.utils import dec_imsi
from pySim.ts_102_221 import FileDescriptor
from pySim.filesystem import CardADF, Path
from pySim.ts_31_102 import ADF_USIM
from pySim.ts_31_103 import ADF_ISIM
from pySim.esim import compile_asn1_subdir
from pySim.esim.saip import templates
from pySim.esim.saip import oid
from pySim.global_platform import KeyType, KeyUsageQualifier
from pySim.global_platform.uicc import UiccSdInstallParams

asn1 = compile_asn1_subdir('saip')

logger = logging.getLogger(__name__)

class Naa:
    """A class defining a Network Access Application (NAA)"""
    name = None
    # AID prefix, as used for ADF and EF.DIR
    aid = None
    # the ProfileElement types used specifically in this NAA
    pe_types = []
    # we only use the base DN of each OID; there may be subsequent versions underneath it
    templates = []
    mandatory_services = []
    adf: CardADF = None

    @classmethod
    def adf_name(cls):
        return 'adf-' + cls.mandatory_services[0]

class NaaCsim(Naa):
    """A class representing the CSIM (CDMA) Network Access Application (NAA)"""
    name = "csim"
    aid = h2b("")
    mandatory_services = ["csim"]
    pe_types = ["csim", "opt-csim", "cdmaParameter"]
    templates = [oid.ADF_CSIM_by_default, oid.ADF_CSIMopt_not_by_default]

class NaaUsim(Naa):
    """A class representing the USIM Network Access Application (NAA)"""
    name = "usim"
    aid = h2b("a0000000871002")
    mandatory_services = ["usim"]
    pe_types = ["usim", "opt-usim", "phonebook", "gsm-access", "eap", "df-5gs", "df-saip",
                "df-snpn", "df-5gprose"]
    templates = [oid.ADF_USIM_by_default, oid.ADF_USIMopt_not_by_default,
                 oid.DF_PHONEBOOK_ADF_USIM, oid.DF_GSM_ACCESS_ADF_USIM,
                 oid.DF_EAP, oid.DF_5GS, oid.DF_SAIP, oid.DF_SNPN,
                 oid.DF_5GProSe]
    adf = ADF_USIM()

class NaaIsim(Naa):
    """A class representing the ISIM Network Access Application (NAA)"""
    name = "isim"
    aid = h2b("a0000000871004")
    mandatory_services = ["isim"]
    pe_types = ["isim", "opt-isim"]
    templates = [oid.ADF_ISIM_by_default, oid.ADF_ISIMopt_not_by_default]
    adf = ADF_ISIM()

NAAs = {
    NaaCsim.name: NaaCsim,
    NaaUsim.name: NaaUsim,
    NaaIsim.name: NaaIsim,
}

class File:
    """Internal representation of a file in a profile filesystem.

    Args:
        pename: Name string of the profile element
        l: List of tuples [fileDescriptor, fillFileContent, fillFileOffset profile elements]
        template: Applicable FileTemplate describing defaults as per SAIP spec
        name: Human-readable name like EF.IMSI, DF.TELECOM, ADF.USIM, ...
    """
    def __init__(self, pename: str, l: Optional[List[Tuple]] = None, template:
                 Optional[templates.FileTemplate] = None, name: Optional[str] = None):
        self._template_derived = False
        self.pe_name = pename
        self._name = name
        self.template = template
        self._body: Optional[bytes] = None
        self.node: Optional['FsNode'] = None
        self.file_type = None
        self.fid: Optional[int] = None
        self.sfi: Optional[int] = None
        self.arr = None
        self.rec_len: Optional[int] = None
        self.nb_rec: Optional[int] = None
        self._file_size = 0
        self.high_update: bool = False
        self.read_and_update_when_deact: bool = False
        self.shareable: bool = True
        self.df_name = None
        self.fill_pattern = None
        self.fill_pattern_repeat = False
        # apply some defaults from profile
        if self.template:
            self.from_template(self.template)
        if l:
            self.from_tuples(l)

    @property
    def name(self) -> Optional[str]:
        if self._name:
            return self._name
        if self.template:
            return self.template.name
        return None

    @property
    def file_size(self) -> Optional[int]:
        """Return the size of the file in bytes."""
        if self.file_type in ['LF', 'CY']:
            return self.nb_rec * self.rec_len
        elif self.file_type in ['TR', 'BT']:
            return self._file_size
        else:
            return None

    @staticmethod
    def get_tuplelist_item(l: List[Tuple], key: str):
        """get the [first] value matching given key from a list of (key, value) tuples."""
        for k, v in l:
            if k == key:
                return v

    @staticmethod
    def _encode_file_size(size: int) -> bytes:
        """Encode the integer file size into bytes, as needed by the asn1tools encoder."""
        if False: # TODO: some way to know for which version of SAIP we should encode
            # A V2.0 eUICC may expect file size to be encoded on at least 2 bytes, as specified in
            # ETSI TS 102 222 [102 222], and may reject the encoding without the leading byte.
            return size.to_bytes(2, 'big')
        else:
            # > v2.0 case where it must be encoded on the minimum number of octets possible
            c = GreedyInteger()
            return c.build(size)

    @staticmethod
    def _decode_file_size(size: bytes) -> int:
        """Decode the file size from asn1tools-bytes to integer."""
        c = GreedyInteger()
        return c.parse(size)

    def from_template(self, template: templates.FileTemplate):
        """Determine defaults for file based on given FileTemplate."""
        if self._template_derived:
            raise ValueError('This file already has been initialized by a template before')
        # copy various bits from template
        self.file_type = template.file_type
        self.fid = template.fid
        self.sfi = template.sfi
        self.arr = template.arr.to_bytes(1)
        if hasattr(template, 'rec_len'):
            self.rec_len = template.rec_len
        else:
            self.rec_len = None
        if hasattr(template, 'nb_rec'):
            self.nb_rec = template.nb_rec
        else:
            self.nb_rec = None
        self.high_update = template.high_update
        # All the files defined in the templates shall have, by default, shareable/not-shareable bit in the file descriptor set to "shareable".
        self.shareable = True
        self._template_derived = True
        if hasattr(template, 'file_size'):
            self._file_size = template.file_size

    def _recompute_size(self):
        """recompute the file size, if needed (body larger than current size)"""
        body_size = len(self.body)
        if self.file_size == None or self.file_size < body_size:
            self._file_size = body_size

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, value: bytes):
        self._body = value
        # we need to potentially update the file size after changing the body [size]
        self._recompute_size()

    def to_fileDescriptor(self) -> dict:
        """Convert from internal representation to 'fileDescriptor' as used by asn1tools for SAIP"""
        fileDescriptor = {}
        fdb_dec = {}
        pefi = {}
        spfi = 0
        if self.fid and self.fid != self.template.fid:
            fileDescriptor['fileID'] = self.fid.to_bytes(2, 'big')
        if self.sfi and self.sfi != self.template.sfi:
            fileDescriptor['shortEFID'] = bytes([self.sfi])
        if self.df_name:
            fileDescriptor['dfName'] = self.df_name
        if self.arr and self.arr != self.template.arr.to_bytes(1):
            fileDescriptor['securityAttributesReferenced'] = self.arr
        if self.file_type in ['LF', 'CY']:
            fdb_dec['file_type'] = 'working_ef'
            if self.nb_rec and self.rec_len:
                fileDescriptor['efFileSize'] = self._encode_file_size(self.file_size)
            if self.file_type == 'LF':
                fdb_dec['structure'] = 'linear_fixed'
            elif self.file_type == 'CY':
                fdb_dec['structure'] = 'cyclic'
        elif self.file_type == 'BT':
            fdb_dec['file_type'] = 'working_ef'
            fdb_dec['structure'] = 'ber_tlv'
            if self.file_size:
                pefi['maximumFileSize'] = self._encode_file_size(self.file_size)
        elif self.file_type == 'TR':
            fdb_dec['file_type'] = 'working_ef'
            fdb_dec['structure'] = 'transparent'
            if self.file_size:
                fileDescriptor['efFileSize'] = self._encode_file_size(self.file_size)
        elif self.file_type in ['MF', 'DF', 'ADF']:
            fdb_dec['file_type'] = 'df'
            fdb_dec['structure'] = 'no_info_given'
        # build file descriptor based on above input data
        fd_dict = {}
        if len(fdb_dec):
            fdb_dec['shareable'] = self.shareable
            fd_dict['file_descriptor_byte'] = fdb_dec
        if self.rec_len:
            fd_dict['record_len'] = self.rec_len
        if len(fd_dict):
            fileDescriptor['fileDescriptor'] = build_construct(FileDescriptor._construct, fd_dict)
        if self.high_update:
            spfi |= 0x80 # TS 102 222 Table 5
        if self.read_and_update_when_deact:
            spfi |= 0x40 # TS 102 222 Table 5
        if spfi != 0x00:
            pefi['specialFileInformation'] = spfi.to_bytes(1)
        if self.fill_pattern:
            if not self.fill_pattern_repeat:
                pefi['fillPattern'] = self.fill_pattern
            else:
                pefi['repeatPattern'] = self.fill_pattern
        if len(pefi.keys()):
            # TODO: When overwriting the default "proprietaryEFInfo" for a template EF for which a
            # default fill or repeat pattern is defined; it is hence recommended to provide the
            # desired fill or repeat pattern in the "proprietaryEFInfo" element for the EF in Profiles
            # downloaded to a V2.2 or earlier eUICC.
            fileDescriptor['proprietaryEFInfo'] = pefi
        logger.debug("%s: to_fileDescriptor(%s)" % (self, fileDescriptor))
        return fileDescriptor

    def from_fileDescriptor(self, fileDescriptor: dict):
        """Convert from 'fileDescriptor' as used by asn1tools for SAIP to internal representation"""
        logger.debug("%s: from_fileDescriptor(%s)" % (self, fileDescriptor))
        fileID = fileDescriptor.get('fileID', None)
        if fileID:
            self.fid = int.from_bytes(fileID, 'big')
        shortEFID = fileDescriptor.get('shortEFID', None)
        if shortEFID:
            self.sfi = shortEFID[0]
        dfName = fileDescriptor.get('dfName', None)
        if dfName:
            self.df_name = dfName
        pefi = fileDescriptor.get('proprietaryEFInfo', {})
        securityAttributesReferenced = fileDescriptor.get('securityAttributesReferenced', None)
        if securityAttributesReferenced:
            self.arr = securityAttributesReferenced
        if 'fileDescriptor' in fileDescriptor:
            fd_dec = parse_construct(FileDescriptor._construct, fileDescriptor['fileDescriptor'])
            fdb_dec = fd_dec['file_descriptor_byte']
            self.shareable = fdb_dec['shareable']
            if fdb_dec['file_type'] == 'working_ef':
                efFileSize = fileDescriptor.get('efFileSize', None)
                if fd_dec['num_of_rec']:
                    self.nb_rec = fd_dec['num_of_rec']
                if fd_dec['record_len']:
                    self.rec_len = fd_dec['record_len']
                if efFileSize:
                    self._file_size = self._decode_file_size(efFileSize)
                    if self.rec_len and self.nb_rec == None:
                        # compute the number of records from file size and record length
                        self.nb_rec = self._file_size // self.rec_len
                if fdb_dec['structure'] == 'linear_fixed':
                    self.file_type = 'LF'
                elif fdb_dec['structure'] == 'cyclic':
                    self.file_type = 'CY'
                elif fdb_dec['structure'] == 'transparent':
                    self.file_type = 'TR'
                elif fdb_dec['structure'] == 'ber_tlv':
                    self.file_type = 'BT'
                    if 'maximumFileSize' in pefi:
                        self._file_size = self._decode_file_size(pefi['maximumFileSize'])
                specialFileInformation = pefi.get('specialFileInformation', None)
                if specialFileInformation:
                    # TS 102 222 Table 5
                    if specialFileInformation[0] & 0x80:
                        self.high_update = True
                    if specialFileInformation[0] & 0x40:
                        self.read_and_update_when_deact = True
                if 'repeatPattern' in pefi:
                    self.fill_pattern = pefi['repeatPattern']
                    self.fill_pattern_repeat = True
                if 'fillPattern' in pefi:
                    self.fill_pattern = pefi['fillPattern']
                    self.fill_pattern_repeat = False
            elif fdb_dec['file_type'] == 'df':
                # only set it, if an earlier call to from_template() didn't alrady set it, as
                # the template can differentiate between MF, DF and ADF (unlike FDB)
                if not self.file_type:
                    self.file_type = 'DF'
        else:
            if not self._template_derived:
                # FIXME: this shouldn't happen? How can this be? But I see it in real profiles
                #raise ValueError("%s: from_fileDescriptor without nested 'fileDescriptor'" % self)
                pass

        logger.debug("\t%s" % repr(self))

    def from_tuples(self, l:List[Tuple]):
        """Parse a list of fileDescriptor, fillFileContent, fillFileOffset tuples into this instance."""
        # fileDescriptor
        fd = self.get_tuplelist_item(l, 'fileDescriptor')
        if not fd and not self._template_derived:
            raise ValueError("%s: No fileDescriptor found in tuple, and none set by template before" % self)
        if fd:
            self.from_fileDescriptor(dict(fd))
        # BODY
        self._body = self.file_content_from_tuples(l)

    @staticmethod
    def path_from_gfm(bin_path: bytes):
        """convert from byte-array of 16bit FIDs to list of integers"""
        return [int.from_bytes(bin_path[i:i+2], 'big') for i in range(0, len(bin_path), 2)]

    @staticmethod
    def path_to_gfm(path: List[int]) -> bytes:
        """convert from list of 16bit integers to byte-array"""
        return b''.join([x.to_bytes(2, 'big') for x in path])

    def to_tuples(self) -> List[Tuple]:
        """Generate a list of fileDescriptor, fillFileContent, fillFileOffset tuples into this instance."""
        return [('fileDescriptor', self.to_fileDescriptor())] + self.file_content_to_tuples()

    def to_gfm(self) -> List[Tuple]:
        """Generate a list of filePath, createFCP, fillFileContent, fillFileOffset tuples into this instance."""
        ret = [('filePath', self.path_to_gfm(self.path)), ('createFCP', self.to_fileDescriptor())]
        ret += self.file_content_to_tuples()
        return ret

    def expand_fill_pattern(self) -> bytes:
        """Expand the fill/repeat pattern as per TS 102 222 Section 6.3.2.2.2"""
        return ts_102_222.expand_pattern(self.fill_pattern, self.fill_pattern_repeat, self.file_size)

    def file_content_from_tuples(self, l: List[Tuple]) -> Optional[bytes]:
        """linearize a list of fillFileContent / fillFileOffset tuples into a stream of bytes."""
        stream = io.BytesIO()
        # Providing file content within "fillFileContent" / "fillFileOffset" shall have the same effect as
        # creating a file with a fill/repeat pattern and thereafter updating the content via Update.
        # Step 1: Fill with pattern from Fcp or Template
        if self.fill_pattern:
            stream.write(self.expand_fill_pattern())
        elif self.template and self.template.default_val:
            stream.write(self.template.expand_default_value_pattern(self.file_size))
        stream.seek(0)
        # then process the fillFileContent/fillFileOffset
        for k, v in l:
            if k == 'doNotCreate':
                return None
            if k == 'fileDescriptor':
                pass
            elif k == 'fillFileOffset':
                stream.seek(v, os.SEEK_CUR)
            elif k == 'fillFileContent':
                stream.write(v)
            else:
                return ValueError("Unknown key '%s' in tuple list" % k)
        return stream.getvalue()

    def file_content_to_tuples(self) -> List[Tuple]:
        # FIXME: simplistic approach. needs optimization. We should first check if the content
        # matches the expanded default value from the template. If it does, return empty list.
        # Next, we should compute the diff between the default value and self.body, and encode
        # that as a sequence of fillFileOffset and fillFileContent tuples.
        return [('fillFileContent', self.body)]

    def __str__(self) -> str:
        return "File(%s)" % self.pe_name

    def __repr__(self) -> str:
        return "File(%s, %s, %04X, SFI=%s)" % (self.pe_name, self.file_type, self.fid or 0, self.sfi)

    def check_template_modification_rules(self):
        """Check template modification rules as per SAIP section 8.3.3."""
        if not self.template:
            return None


class ProfileElement:
    """Generic Class representing a Profile Element (PE) within a SAIP Profile. This may be used directly,
    but ist more likely sub-classed with a specific class for the specific profile element type, like e.g
    ProfileElementHeader, ProfileElementMF, ...
    """
    FILE_BEARING = ['mf', 'cd', 'telecom', 'usim', 'opt-usim', 'isim', 'opt-isim', 'phonebook', 'gsm-access',
                    'csim', 'opt-csim', 'eap', 'df-5gs', 'df-saip', 'df-snpn', 'df-5gprose', 'iot', 'opt-iot']
    # in their infinite wisdom the spec authors used inconsistent/irregular naming of PE type vs. hedaer field
    # names, so we have to manually translate the exceptions here...
    header_name_translation_dict = {
        'header':                   None,
        'end':                      'end-header',
        'genericFileManagement':    'gfm-header',
        'akaParameter':             'aka-header',
        'cdmaParameter':            'cdma-header',
        # note how they couldn't even consistently captialize the 'header' suffix :(
        'application':              'app-Header',
        'pukCodes':                 'puk-Header',
        'pinCodes':                 'pin-Header',
        'securityDomain':           'sd-Header',
        'df-5gprose':               'df-5g-prose-header',
        }

    def __init__(self, decoded = None, mandated: bool = True,
                 pe_sequence: Optional['ProfileElementSequence'] = None):
        """
        Instantiate a new ProfileElement.  This is usually either called with the 'decoded' argument after
        reading a SAIP-DER-encoded PE.  Alternatively, when constructing a PE from scratch, decoded is None,
        and a minimal PE-Header is generated.

        Args:
            decoded: asn1tools-generated decoded structure for this PE
            mandated: Whether or not the PE-Header should contain the mandated attribute
            pe_sequence: back-reference to the PE-Sequence of which we're part of
        """
        self.pe_sequence = pe_sequence
        if decoded:
            self.decoded = decoded
        else:
            self.decoded = OrderedDict()
            if self.header_name:
                self.decoded[self.header_name] = { 'identification': None}
                if mandated:
                    self.decoded[self.header_name] = { 'mandated': None}

    @property
    def header_name(self) -> str:
        """Return the name of the header field within the profile element."""
        # unnecessary complication by inconsistent naming :(
        if self.type.startswith('opt-'):
            return self.type.replace('-','') + '-header'
        if self.type in self.header_name_translation_dict:
            return self.header_name_translation_dict[self.type]
        return self.type + '-header'

    @property
    def header(self):
        """The decoded ProfileHeader."""
        return self.decoded.get(self.header_name, None)

    @property
    def identification(self):
        """The identification value: An unique number for the PE within the PE-Sequence."""
        if self.header:
            return self.header['identification']
        else:
            return None

    @property
    def templateID(self):
        """Return the decoded templateID used by this profile element (if any)."""
        return self.decoded.get('templateID', None)

    @classmethod
    def class_for_petype(cls, pe_type: str) -> Optional['ProfileElement']:
        """Return the subclass implementing the given pe-type string."""
        class4petype = {
            # use same order as ASN.1 source definition of "ProfileElement ::= CHOICE {"
            'header': ProfileElementHeader,
            'genericFileManagement': ProfileElementGFM,
            'pinCodes': ProfileElementPin,
            'pukCodes': ProfileElementPuk,
            'akaParameter': ProfileElementAKA,
            # TODO: cdmaParameter
            'securityDomain': ProfileElementSD,
            'rfm': ProfileElementRFM,
            'application': ProfileElementApplication,
            # TODO: nonStandard
            'end': ProfileElementEnd,
            'mf': ProfileElementMF,
            'cd': ProfileElementCD,
            'telecom': ProfileElementTelecom,
            'usim': ProfileElementUSIM,
            'opt-usim': ProfileElementOptUSIM,
            'isim': ProfileElementISIM,
            'opt-isim': ProfileElementOptISIM,
            'phonebook': ProfileElementPhonebook,
            'gsm-access': ProfileElementGsmAccess,
            # TODO: csim
            # TODO: opt-csim
            'eap': ProfileElementEAP,
            'df-5gs': ProfileElementDf5GS,
            'df-saip': ProfileElementDfSAIP,
            'df-snpn': ProfileElementDfSNPN,
            'df-5gprose': ProfileElementDf5GProSe,
            }
        if pe_type in class4petype:
            return class4petype[pe_type]
        else:
            return None

    @classmethod
    def from_der(cls, der: bytes,
                 pe_sequence: Optional['ProfileElementSequence'] = None) -> 'ProfileElement':
        """Construct an instance from given raw, DER encoded bytes.

        Args:
            der: raw, DER-encoded bytes of a single PE
            pe_sequence: back-reference to the PE-Sequence of which this PE is part of
        """
        pe_type, decoded = asn1.decode('ProfileElement', der)
        pe_cls = cls.class_for_petype(pe_type)
        if pe_cls:
            inst = pe_cls(decoded, pe_sequence=pe_sequence)
        else:
            inst = ProfileElement(decoded, pe_sequence=pe_sequence)
            inst.type = pe_type
        # run any post-decoder a derived class may have
        if hasattr(inst, '_post_decode'):
            inst._post_decode()
        return inst

    def to_der(self) -> bytes:
        """Build an encoded DER representation of the instance."""
        # run any pre-encoder a derived class may have
        if hasattr(self, '_pre_encode'):
            self._pre_encode()
        return asn1.encode('ProfileElement', (self.type, self.decoded))

    def __str__(self) -> str:
        return self.type

class FsProfileElement(ProfileElement):
    """A file-system bearing profile element, like MF, USIM, ....

    We keep two major representations of the data:
    * The "decoded" member, as introduced by our parent class, containing asn1tools syntax
    * the "files" dict, consisting of File values indexed by PE-name strings

    The methods pe2files and files2pe convert between those two representations.
    """
    def __init__(self, decoded = None, mandated: bool = True, **kwargs):
        super().__init__(decoded, mandated, **kwargs)
        # indexed by PE-Name
        self.files = {}
        # resolve ASN.1 type definition; needed to e.g. iterate field names (for file pe-names)
        self.tdef = asn1.types['ProfileElement'].type.name_to_member[self.type]

    def file_template_for_path(self, path: Path, adf: Optional[str] = None) -> Optional[templates.FileTemplate]:
        """Resolve the FileTemplate for given path, if we have any matching.

        Args:
            path: the path for which we would like to resolve the FileTemplate
            adf: string name of the ADF which might be used with this PE
        """
        template = templates.ProfileTemplateRegistry.get_by_oid(self.templateID)
        for f in template.files:
            if f.path == path:
                return f
            # optionally prefix with ADF name of NAA
            if adf and Path(adf) + f.path == path:
                return f

    def supports_file_for_path(self, path: Path, adf: Optional[str] = None) -> bool:
        """Does this ProfileElement support a file of given path?"""
        return self.file_template_for_path(path) != None

    def add_file(self, file: File):
        """Add a File to the ProfileElement."""
        logger.debug("%s.add_file: %s" % (self.__class__.__name__, repr(file)))
        template = templates.ProfileTemplateRegistry.get_by_oid(self.templateID)
        if file.pe_name in self.files:
            raise KeyError('Cannot add file: %s already exists' % file.pename)
        self.files[file.pe_name] = file
        if self.pe_sequence:
            if file.pe_name == 'mf': #file.fid == 0x3f00:
                if self.pe_sequence.mf:
                    raise ValueError("PE Sequence already has MF, cannot add another one")
                file.node = FsNodeMF(file)
                self.pe_sequence.mf = file.node
                self.pe_sequence.cur_df = file.node
            else:
                if not template.extends and file.pe_name != template.base_df().pe_name:
                    # FsNodeDF of the first [A]DF of the PE
                    pe_df = self.files[template.base_df().pe_name].node
                    if file.template:
                        for d in file.template.ppath: # TODO: revert list?
                            pe_df = pe_df[d]
                    self.pe_sequence.cur_df = pe_df
                elif template.parent:
                    # this is a template that belongs into the [A]DF of another template
                    # 1) find the PE for the referenced template
                    parent_pe = self.pe_sequence.get_closest_prev_pe_for_templateID(self, template.parent.oid)
                    # 2) resolve te [A]DF that forms the base of that parent PE
                    pe_df = parent_pe.files[template.parent.base_df().pe_name].node
                    self.pe_sequence.cur_df = pe_df
                self.pe_sequence.cur_df = self.pe_sequence.cur_df.add_file(file)

    def files2pe(self):
        """Update the "decoded" member with the contents of the "files" member."""
        for k, f in self.files.items():
            self.decoded[k] = f.to_tuples()

    def pe2files(self):
        """Update the "files" member with the contents of the "decoded" member."""
        logger.debug("%s.pe2files(%s)" % (self.__class__.__name__, self.type))
        tdict = {x.name: x for x in self.tdef.root_members}
        template = templates.ProfileTemplateRegistry.get_by_oid(self.templateID)
        for k, v in self.decoded.items():
            if tdict[k].type_name == 'File':
                file = File(k, v, template.files_by_pename.get(k, None))
                self.add_file(file)

    def create_file(self, pename: str) -> File:
        """Programatically create a file by its PE-Name."""
        template = templates.ProfileTemplateRegistry.get_by_oid(self.templateID)
        file = File(pename, None, template.files_by_pename.get(pename, None))
        self.add_file(file)
        self.decoded[pename] = []
        return file

    def _post_decode(self):
        # not entirely sure about doing this this automatism
        self.pe2files()

    def _pre_encode(self):
        # should we do self.pe2files()?  I don't think so
        #self.files2pe()
        pass

class ProfileElementGFM(ProfileElement):
    type = 'genericFileManagement'

    @staticmethod
    def path_str(path: List[int]) -> str:
        return '/'.join(['%04X' % x for x in path])

    def __init__(self, decoded = None, mandated: bool = True, **kwargs):
        super().__init__(decoded, mandated, **kwargs)
        # indexed by PE-Name
        self.files = {}
        self.tdef = asn1.types['ProfileElement'].type.name_to_member[self.type]
        if decoded:
            return
        self.decoded['fileManagementCMD'] = []

    def supports_file_for_path(self, path: Path, adf: Optional[str] = None) -> bool:
        """Does this ProfileElement support a file of given path?"""
        # GFM supports all files in all paths...
        return True

    def add_file(self, file: File, path: Path):
        logger.debug("%s.add_file(path=%s, %s)" % (self.__class__.__name__, path, repr(file)))
        if hasattr(self.pe_sequence, 'mf'):
            if isinstance(path, Path):
                parent = self.pe_sequence.mf.lookup_by_path(Path(path[:-1]))
            else:
                parent = self.pe_sequence.mf.lookup_by_fidpath(path[:-1])

            path_str = self.path_str(parent.fid_path + [file.fid])
        else:
            path_str = str(path)
        if path_str in self.files:
            raise KeyError('Cannot add file: %s already exists' % path_str)
        self.files[path_str] = file
        if hasattr(self.pe_sequence, 'mf'):
            self.pe_sequence.cur_df = parent.add_file(file)

    def pe2files(self):
        """Update the "files" member with the contents of the "decoded" member."""
        def perform(self, path: List[int], file_elements):
            if len(file_elements):
                if self.pe_sequence:
                    self.pe_sequence.cd(path)
                file = File(None, file_elements)
                file.path = path
                file.pe_name = self.path_str(path + [file.fid])
                self.add_file(file, path + [file.fid])

        logger.debug("="*70 + " " + self.type)
        #logger.debug(self.decoded)
        path = [0x3f00] # current DF at start of PE: MF
        file_elements = []
        # looks like TCA added one level too much in the ASN.1 hierarchy here
        for fmc in self.decoded['fileManagementCMD']:
            for fmc2 in fmc:
                if fmc2[0] == 'filePath':
                    # selecting a new path means we're done with the previous file
                    perform(self, path, file_elements)
                    file_elements = []
                    if fmc2[1] == b'':
                        path = [0x3f00]
                    else:
                        path = [0x3f00] + File.path_from_gfm(fmc2[1])
                    #logger.debug("filePath %s -> path=%s" % (fmc2[1], path))
                elif fmc2[0] == 'createFCP':
                    # new FCP means new file; perform the old one
                    perform(self, path, file_elements)
                    file_elements = [('fileDescriptor', fmc2[1])]
                elif fmc2[0] == 'fillFileOffset' or fmc2[0] == 'fillFileContent':
                    file_elements.append(fmc2)
                else:
                    raise ValueError("Unknown GFM choice '%s'" % fmc2[0])
        # add the last file, if we still have any pending data in file_elements
        perform(self, path, file_elements)

    def files2pe(self):
        """Update the "decoded" member from the "files" member."""
        # FIXME: implement this
        # sort / iterate by path; issue filePath, createFCP and fillFile{Offset,Content} elements


    def _post_decode(self):
        # not entirely sure about this automatism
        self.pe2files()


class ProfileElementMF(FsProfileElement):
    """Class representing the ProfileElement for the MF (Master File)"""
    type = 'mf'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.MF)
        for fname in ['mf', 'ef-iccid', 'ef-dir', 'ef-arr']:
            self.decoded[fname] = []
        # TODO: resize EF.DIR?

class ProfileElementPuk(ProfileElement):
    """Class representing the ProfileElement for a PUK (PIN Unblocking Code)"""
    type = 'pukCodes'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['pukCodes'] = []
        self.add_puk(0x01, b'11111111')
        self.add_puk(0x81, b'22222222')

    def add_puk(self, key_ref: int, puk_value: bytes, max_attempts:int = 10, retries_left:int = 10):
        """Add a PUK to the pukCodes ProfileElement"""
        if key_ref < 0 or key_ref > 0xff:
            raise ValueError('key_ref must be uint8')
        if len(puk_value) != 8:
            raise ValueError('puk_value must be 8 bytes long')
        if max_attempts < 0 or max_attempts > 0xf:
            raise ValueError('max_attempts must be 4 bit')
        if retries_left < 0 or max_attempts > 0xf:
            raise ValueError('retries_left must be 4 bit')
        puk = {
            'keyReference': key_ref,
            'pukValue': puk_value,
            'maxNumOfAttemps-retryNumLeft': (max_attempts << 4) | retries_left,
        }
        self.decoded['pukCodes'].append(puk)


class ProfileElementPin(ProfileElement):
    """Class representing the ProfileElement for a PIN (Personal Identification Number)"""
    type = 'pinCodes'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['pinCodes'] = ('pinconfig', [])
        self.add_pin(0x01, b'0000\xff\xff\xff\xff', unblock_ref=1, pin_attrib=6)
        self.add_pin(0x10, b'11111111', pin_attrib=3)

    def add_pin(self, key_ref: int, pin_value: bytes, max_attempts : int = 3, retries_left : int = 3,
                unblock_ref: Optional[int] = None, pin_attrib: int = 7):
        """Add a PIN to the pinCodes ProfileElement"""
        if key_ref < 0 or key_ref > 0xff:
            raise ValueError('key_ref must be uint8')
        if pin_attrib < 0 or pin_attrib > 0xff:
            raise ValueError('pin_attrib must be uint8')
        if len(pin_value) != 8:
            raise ValueError('pin_value must be 8 bytes long')
        if max_attempts < 0 or max_attempts > 0xf:
            raise ValueError('max_attempts must be 4 bit')
        if retries_left < 0 or max_attempts > 0xf:
            raise ValueError('retries_left must be 4 bit')
        pin = {
            'keyReference': key_ref,
            'pinValue': pin_value,
            'maxNumOfAttemps-retryNumLeft': (max_attempts << 4) | retries_left,
            'pinAttributes': pin_attrib,
        }
        if unblock_ref:
            pin['unblockingPINReference'] = unblock_ref
        self.decoded['pinCodes'][1].append(pin)


class ProfileElementTelecom(FsProfileElement):
    """Class representing the ProfileElement for DF.TELECOM"""
    type = 'telecom'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.DF_TELECOM_v2)
        for fname in ['df-telecom', 'ef-arr']:
            self.decoded[fname] = []

class ProfileElementCD(FsProfileElement):
    """Class representing the ProfileElement for DF.CD"""
    type = 'cd'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.DF_CD)
        for fname in ['df-cd']:
            self.decoded[fname] = []

class ProfileElementPhonebook(FsProfileElement):
    """Class representing the ProfileElement for DF.PHONEBOOK"""
    type = 'phonebook'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_PHONEBOOK_ADF_USIM)
        for fname in ['df-phonebook']:
            self.decoded[fname] = []

class ProfileElementGsmAccess(FsProfileElement):
    """Class representing the ProfileElement for ADF.USIM/DF.GSM-ACCESS"""
    type = 'gsm-access'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_GSM_ACCESS_ADF_USIM)
        for fname in ['df-gsm-access']:
            self.decoded[fname] = []

class ProfileElementDf5GS(FsProfileElement):
    """Class representing the ProfileElement for ADF.USIM/DF.5GS"""
    type = 'df-5gs'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_5GS_v3)
        for fname in ['df-df-5gs']:
            self.decoded[fname] = []

class ProfileElementEAP(FsProfileElement):
    """Class representing the ProfileElement for DF.EAP"""
    type = 'eap'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_EAP)
        for fname in ['df-eap', 'ef-eapstatus']:
            self.decoded[fname] = []

class ProfileElementDfSAIP(FsProfileElement):
    """Class representing the ProfileElement for DF.SAIP"""
    type = 'df-saip'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_SAIP)
        for fname in ['df-df-saip']:
            self.decoded[fname] = []

class ProfileElementDfSNPN(FsProfileElement):
    """Class representing the ProfileElement for DF.SNPN"""
    type = 'df-snpn'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_SNPN)
        for fname in ['df-df-snpn']:
            self.decoded[fname] = []

class ProfileElementDf5GProSe(FsProfileElement):
    """Class representing the ProfileElement for DF.5GProSe"""
    type = 'df-5gprose'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_5GProSe)
        for fname in ['df-df-5g-prose']:
            self.decoded[fname] = []


class SecurityDomainKeyComponent:
    """Representation of a key-component of a key for a security domain."""
    def __init__(self, key_type: str, key_data: bytes, mac_length: int = 8):
        self.key_type = key_type
        self.key_data = key_data
        self.mac_length = mac_length

    def __repr__(self) -> str:
        return 'SdKeyComp(type=%s, mac_len=%u, data=%s)' % (self.key_type, self.mac_length,
                                                            b2h(self.key_data))


    @classmethod
    def from_saip_dict(cls, saip: dict) -> 'SecurityDomainKeyComponent':
        """Construct instance from the dict as generated by SAIP asn.1 decoder."""
        return cls(KeyType.parse(saip['keyType']), saip['keyData'], saip['macLength'])

    def to_saip_dict(self) -> dict:
        """Express instance in the dict format required by SAIP asn.1 encoder."""
        return {'keyType': KeyType.build(self.key_type),
                'keyData': self.key_data,
                'macLength': self.mac_length}

class SecurityDomainKey:
    """Representation of a key used for SCP access to a security domain."""
    def __init__(self, key_version_number: int, key_id: int, key_usage_qualifier: dict,
                 key_components: List[SecurityDomainKeyComponent]):
        self.key_usage_qualifier = key_usage_qualifier
        self.key_identifier = key_id
        self.key_version_number = key_version_number
        self.key_components = key_components

    def __repr__(self) -> str:
        return 'SdKey(KVN=0x%02x, ID=0x%02x, Usage=%s, Comp=%s)' % (self.key_version_number,
                                                                    self.key_identifier,
                                                                    self.key_usage_qualifier,
                                                                    repr(self.key_components))

    @classmethod
    def from_saip_dict(cls, saip: dict) -> 'SecurityDomainKey':
        """Construct instance from the dict as generated by SAIP asn.1 decoder."""
        inst = cls(int.from_bytes(saip['keyVersionNumber'], "big"),
                   int.from_bytes(saip['keyIdentifier'], "big"),
                   KeyUsageQualifier.parse(saip['keyUsageQualifier']),
                   [SecurityDomainKeyComponent.from_saip_dict(x) for x in saip['keyComponents']])
        return inst

    def to_saip_dict(self) -> dict:
        """Express instance in the dict format required by SAIP asn.1 encoder."""
        return {'keyUsageQualifier': KeyUsageQualifier.build(self.key_usage_qualifier),
                'keyIdentifier': bytes([self.key_identifier]),
                'keyVersionNumber': bytes([self.key_version_number]),
                'keyComponents': [k.to_saip_dict() for k in self.key_components]}

class ProfileElementSD(ProfileElement):
    """Class representing a securityDomain ProfileElement."""
    type = 'securityDomain'

    # TODO: New parameters "openPersoData" and "catTpParameters" have been defined for Security
    # Domains in v2.2. A V2.0 or V2.1 eUICC may reject these new options; it is hence recommended to
    # avoid using such parameters in Profiles downloaded to a V2.0 or V2.1 eUICC.

    class C9(BER_TLV_IE, tag=0xC9, nested=UiccSdInstallParams):
        pass

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['instance'] = {
                'applicationLoadPackageAID': h2b('A0000001515350'),
                'classAID':                  h2b('A000000251535041'),
                'instanceAID':               h2b('A000000151000000'),
                # Optional: extraditeSecurityDomainAID
                'applicationPrivileges': h2b('82FC80'),
                # Optioal: lifeCycleState
                'applicationSpecificParametersC9': h2b('8201f09301f08701f0'), # we assume user uses add_scp()
                # Optional: systemSpecificParameters
                'applicationParameters': {
                        # TAR: B20100, MSL: 12
                        'uiccToolkitApplicationSpecificParametersField': h2b('0100000100000002011203B2010000'),
                    },
                # Optional: processData
                # Optional: controlReferenceTemplate
            }
        self.decoded['keyList'] = [] # we assume user uses add_key() method for all keys
        # Optional: sdPersoData
        # Optional: openPersoData
        # Optional: catTpParameters
        self._post_decode()

    def _post_decode(self):
        self.usip = self.C9()
        self.usip.from_bytes(self.decoded['instance']['applicationSpecificParametersC9'])
        self.keys = [SecurityDomainKey.from_saip_dict(x) for x in self.decoded['keyList']]

    def _pre_encode(self):
        self.decoded['keyList'] = [x.to_saip_dict() for x in self.keys]
        self.decoded['instance']['applicationSpecificParametersC9'] = self.usip.to_bytes()

    def has_scp(self, scp: int) -> bool:
        """Determine if SD Installation parameters already specify given SCP."""
        return self.usip.nested_collection.has_scp(scp)

    def add_scp(self, scp: int, i: int):
        """Add given SCP (and i parameter) to list of SCP of the Security Domain Install Params.
        Example: add_scp(0x03, 0x70) for SCP03, or add_scp(0x02, 0x55) for SCP02."""
        self.usip.nested_collection.add_scp(scp, i)
        self._pre_encode()

    def remove_scp(self, scp: int):
        """Remove given SCP from list of SCP of the Security Domain Install Params."""
        self.usip.nested_collection.remove_scp(scp)
        self._pre_encode()

    def find_key(self, key_version_number: int, key_id: int) -> Optional[SecurityDomainKey]:
        """Find and return (if any) the SecurityDomainKey for given KVN + KID."""
        for k in self.keys:
            if k.key_version_number == key_version_number and k.key_identifier == key_id:
                return k
        return None

    def add_key(self, key: SecurityDomainKey):
        """Add a given SecurityDomainKey to the keyList of the securityDomain."""
        if self.find_key(key.key_version_number, key.key_identifier):
            raise ValueError('Key for KVN=0x%02x / KID=0x%02x already exists' % (key.key_version_number,
                                                                                 key.key_identifier))
        self.keys.append(key)
        self._pre_encode()

    def remove_key(self, key_version_number: int, key_id: int):
        key = self.find_key(key_version_number, key_id)
        if not key:
            raise ValueError('No key for KVN=0x%02x / KID=0x%02x found' % (key_version_number, key_id))
        self.keys.remove(key)
        self._pre_encode()

class ProfileElementSSD(ProfileElementSD):
    """Class representing a securityDomain ProfileElement for a SSD."""
    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # defaults [overriding ProfileElementSD) taken from SAIP v2.3.1 Section 11.2.12
        self.decoded['instance']['instanceAID'] = h2b('A00000055910100102736456616C7565')
        self.decoded['instance']['applicationPrivileges'] = h2b('808000')
        self.decoded['instance']['applicationParameters'] = {
                # TAR: 6C7565, MSL: 12
                'uiccToolkitApplicationSpecificParametersField': h2b('01000001000000020112036C756500'),
            }

class ProfileElementApplication(ProfileElement):
    """Class representing an application ProfileElement."""
    type = 'application'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)

    @classmethod
    def from_file(cls,
                  filename:str,
                  aid:Hexstr,
                  sd_aid:Hexstr = None,
                  non_volatile_code_limit:int = None,
                  volatile_data_limit:int = None,
                  non_volatile_data_limit:int = None,
                  hash_value:Hexstr = None) -> 'ProfileElementApplication':
        """Fill contents of application ProfileElement from a .cap file."""

        inst = cls()
        Construct_data_limit = StripHeaderAdapter(GreedyBytes, 4, steps = [2,4])

        if filename.lower().endswith('.cap'):
            cap = javacard.CapFile(filename)
            load_block_object = cap.get_loadfile()
        elif filename.lower().endswith('.ijc'):
            fd = open(filename, 'rb')
            load_block_object = fd.read()
        else:
            raise ValueError('Invalid file type, file must either .cap or .ijc')

        # Mandatory
        inst.decoded['loadBlock'] = {
            'loadPackageAID': h2b(aid),
            'loadBlockObject': load_block_object
        }

        # Optional
        if sd_aid:
            inst.decoded['loadBlock']['securityDomainAID'] = h2b(sd_aid)
        if non_volatile_code_limit:
            inst.decoded['loadBlock']['nonVolatileCodeLimitC6'] = Construct_data_limit.build(non_volatile_code_limit)
        if volatile_data_limit:
            inst.decoded['loadBlock']['volatileDataLimitC7'] = Construct_data_limit.build(volatile_data_limit)
        if non_volatile_data_limit:
            inst.decoded['loadBlock']['nonVolatileDataLimitC8'] = Construct_data_limit.build(non_volatile_data_limit)
        if hash_value:
            inst.decoded['loadBlock']['hashValue'] = h2b(hash_value)

        return inst

    def to_file(self, filename:str):
        """Write loadBlockObject contents of application ProfileElement to a .cap or .ijc file."""

        load_package_aid = b2h(self.decoded['loadBlock']['loadPackageAID'])
        load_block_object = self.decoded['loadBlock']['loadBlockObject']

        if filename.lower().endswith('.cap'):
            with io.BytesIO(load_block_object) as f, zipfile.ZipFile(filename, 'w') as z:
                javacard.ijc_to_cap(f, z, load_package_aid)
        elif filename.lower().endswith('.ijc'):
            with open(filename, 'wb') as f:
                f.write(load_block_object)
        else:
            raise ValueError('Invalid file type, file must either .cap or .ijc')

    def add_instance(self,
                     aid:Hexstr,
                     class_aid:Hexstr,
                     inst_aid:Hexstr,
                     app_privileges:Hexstr,
                     app_spec_pars:Hexstr,
                     uicc_toolkit_app_spec_pars:Hexstr = None,
                     uicc_access_app_spec_pars:Hexstr = None,
                     uicc_adm_access_app_spec_pars:Hexstr = None,
                     volatile_memory_quota:Hexstr = None,
                     non_volatile_memory_quota:Hexstr = None,
                     process_data:list[Hexstr] = None):
        """Create a new instance and add it to the instanceList"""

        # Mandatory
        inst = {'applicationLoadPackageAID': h2b(aid),
                'classAID': h2b(class_aid),
                'instanceAID': h2b(inst_aid),
                'applicationPrivileges': h2b(app_privileges),
                'applicationSpecificParametersC9': h2b(app_spec_pars)}

        # Optional
        if uicc_toolkit_app_spec_pars or uicc_access_app_spec_pars or uicc_adm_access_app_spec_pars:
            inst['applicationParameters'] = {}
            if uicc_toolkit_app_spec_pars:
                inst['applicationParameters']['uiccToolkitApplicationSpecificParametersField'] = \
                    h2b(uicc_toolkit_app_spec_pars)
            if uicc_access_app_spec_pars:
                inst['applicationParameters']['uiccAccessApplicationSpecificParametersField'] = \
                    h2b(uicc_access_app_spec_pars)
            if uicc_adm_access_app_spec_pars:
                inst['applicationParameters']['uiccAdministrativeAccessApplicationSpecificParametersField'] = \
                    h2b(uicc_adm_access_app_spec_pars)
        if volatile_memory_quota is not None or non_volatile_memory_quota is not None:
            inst['systemSpecificParameters'] = {}
            Construct_data_limit = StripHeaderAdapter(GreedyBytes, 4, steps = [2,4])
            if volatile_memory_quota is not None:
                inst['systemSpecificParameters']['volatileMemoryQuotaC7'] = \
                    Construct_data_limit.build(volatile_memory_quota)
            if non_volatile_memory_quota is not None:
                inst['systemSpecificParameters']['nonVolatileMemoryQuotaC8'] = \
                    Construct_data_limit.build(non_volatile_memory_quota)
        if len(process_data) > 0:
            inst['processData'] = []
        for proc in process_data:
            inst['processData'].append(h2b(proc))

        # Append created instance to instance list
        if 'instanceList' not in self.decoded.keys():
            self.decoded['instanceList'] = []
        self.decoded['instanceList'].append(inst)

    def remove_instance(self, inst_aid:Hexstr):
        """Remove an instance from the instanceList"""
        inst_list = self.decoded.get('instanceList', [])
        for inst in enumerate(inst_list):
            if b2h(inst[1].get('instanceAID', None)) == inst_aid:
                inst_list.pop(inst[0])
                return
        raise ValueError("instance AID: '%s' not present in instanceList, cannot remove instance" % inst[1])



class ProfileElementRFM(ProfileElement):
    """Class representing the ProfileElement for RFM (Remote File Management)."""
    type = 'rfm'

    def __init__(self, decoded: Optional[dict] = None,
                 inst_aid: Optional[bytes] = None, sd_aid: Optional[bytes] = None,
                 adf_aid: Optional[bytes] = None,
                 tar_list: Optional[List[bytes]] = [], msl: Optional[int] = 0x06, **kwargs):
        super().__init__(decoded, **kwargs)
        ADM1_ACCESS = h2b('02000100')
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['instanceAID'] = inst_aid
        self.decoded['securityDomainAID'] = sd_aid
        self.decoded['tarList'] = tar_list
        self.decoded['minimumSecurityLevel'] = bytes([msl])
        self.decoded['uiccAccessDomain'] = ADM1_ACCESS
        self.decoded['uiccAdminAccessDomain'] = ADM1_ACCESS
        if adf_aid:
            self.decoded['adfRFMAccess'] = {
                    'adfAID': adf_aid,
                    'adfAccessDomain': ADM1_ACCESS,
                    'adfAdminAccessDomain': ADM1_ACCESS,
                }

class ProfileElementUSIM(FsProfileElement):
    """Class representing the ProfileElement for ADF.USIM Mandatory Files"""
    type = 'usim'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.ADF_USIM_by_default_v2)
        for fname in ['adf-usim', 'ef-imsi', 'ef-arr', 'ef-ust', 'ef-spn', 'ef-est', 'ef-acc', 'ef-ecc']:
            self.decoded[fname] = []

    @property
    def adf_name(self) -> str:
        return b2h(self.decoded['adf-usim'][0][1]['dfName'])

    @property
    def imsi(self) -> Optional[str]:
        template = templates.ProfileTemplateRegistry.get_by_oid(self.templateID)
        f = File('ef-imsi', self.decoded['ef-imsi'], template.files_by_pename.get('ef-imsi', None))
        return dec_imsi(b2h(f.body))

class ProfileElementOptUSIM(FsProfileElement):
    """Class representing the ProfileElement for ADF.USIM Optional Files"""
    type = 'opt-usim'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.ADF_USIMopt_not_by_default_v2)

class ProfileElementISIM(FsProfileElement):
    """Class representing the ProfileElement for ADF.ISIM Mandatory Files"""
    type = 'isim'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.ADF_ISIM_by_default)
        for fname in ['adf-isim', 'ef-impi', 'ef-impu', 'ef-domain', 'ef-ist', 'ef-arr']:
            self.decoded[fname] = []

    @property
    def adf_name(self) -> str:
        return b2h(self.decoded['adf-isim'][0][1]['dfName'])

class ProfileElementOptISIM(FsProfileElement):
    """Class representing the ProfileElement for ADF.ISIM Optional Files"""
    type = 'opt-isim'

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.ADF_ISIMopt_not_by_default_v2)


class ProfileElementAKA(ProfileElement):
    """Class representing the ProfileElement for Authentication and Key Agreement (AKA)."""
    type = 'akaParameter'
    # TODO: RES size for USIM test algorithm can be set to 32, 64 or 128 bits. This value was
    # previously limited to 128 bits.  Recommendation: Avoid using RES size 32 or 64 in Profiles
    # downloaded to V2.1 eUICCs.

    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.set_milenage(b'\x00'*16, b'\x00'*16)

    def _fixup_sqnInit_dec(self) -> None:
        """asn1tools has a bug when working with SEQUENCE OF that have DEFAULT values. Let's work around
        this."""
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
        sqn_init = self.decoded.get('sqnInit', None)
        if not sqn_init:
            return
        for s in sqn_init:
            if any(s):
                return
        # none of the fields were initialized with a non-default (non-zero) value, so we can skip it
        del self.decoded['sqnInit']

    def _post_decode(self):
        # work around asn1tools bug regarding DEFAULT for a SEQUENCE OF
        self._fixup_sqnInit_dec()

    def _pre_encode(self):
        # work around asn1tools bug regarding DEFAULT for a SEQUENCE OF
        self._fixup_sqnInit_enc()

    def set_milenage(self, k: bytes, opc: bytes):
        """Configure akaParametes for MILENAGE."""
        self.decoded['algoConfiguration'] = ('algoParameter', {
            'algorithmID': 1,
            'algorithmOptions': b'\x00', # not relevant for milenage
            'key': k,
            'opc': opc,
        })

    def set_xor3g(self, k: bytes):
        """Configure akaParametes for XOR-3G."""
        self.decoded['algoConfiguration'] = ('algoParameter', {
            'algorithmID': 3,
            'algorithmOptions': b'\x00', # not relevant for milenage
            'key': k,
            'opc': b'', # not used for MILENAGE
        })

    def set_tuak(self, k: bytes, topc: bytes, num_of_keccak: int = 1):
        """Configure akaParametes for TUAK."""
        self.decoded['algoConfiguration'] = ('algoParameter', {
            'algorithmID': 2,
            'algorithmOptions': b'\x00', # not relevant for milenage
            'key': k,
            'opc': topc,
            'numberOfKeccak': bytes([num_of_keccak]),
        })

    def set_mapping(self, aid: bytes, options: int = 6):
        """Configure akaParametes for a mapping from another AID."""
        self.decoded['algoConfiguration'] = ('mappingParameter', {
            'mappingOptions': bytes([options]),
            'mappingSource': aid,
        })

class ProfileElementHeader(ProfileElement):
    """Class representing the ProfileElement for the Header of the PE-Sequence."""
    type = 'header'
    def __init__(self, decoded: Optional[dict] = None,
                 ver_major: Optional[int] = 2, ver_minor: Optional[int] = 3,
                 iccid: Optional[Hexstr] = '0'*20, profile_type: Optional[str] = None,
                 **kwargs):
        """You would usually initialize an instance either with a "decoded" argument (as read from
        a DER-encoded SAIP file via asn1tools), or [some of] the othe arguments in case you're
        constructing a Profile Header from scratch.

        Args:
            decoded: asn1tools-generated decoded structure for this PE
            ver_major: Major SAIP version
            ver_minor: Minor SAIP version
            iccid: ICCID of the profile
            profile_type: operational, testing or bootstrap
        """
        super().__init__(decoded, **kwargs)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded = {
            'major-version': ver_major,
            'minor-version': ver_minor,
            'iccid': h2b(iccid),
            'eUICC-Mandatory-services': {}, # needs to be recomputed at the end
            'eUICC-Mandatory-GFSTEList': [], # needs to be recomputed at the end
        }
        if profile_type:
            self.decoded['profileType'] = profile_type

    def mandatory_service_add(self, service_name):
        self.decoded['eUICC-Mandatory-services'][service_name] = None

    def mandatory_service_remove(self, service_name):
        if service_name in self.decoded['eUICC-Mandatory-services'].keys():
            del self.decoded['eUICC-Mandatory-services'][service_name]
        else:
            raise ValueError("service not in eUICC-Mandatory-services list, cannot remove")

class ProfileElementEnd(ProfileElement):
    """Class representing the ProfileElement for the End of the PE-Sequence."""
    type = 'end'
    def __init__(self, decoded: Optional[dict] = None, **kwargs):
        super().__init__(decoded, **kwargs)

def bertlv_first_segment(binary: bytes) -> Tuple[bytes, bytes]:
    """obtain the first segment of a binary concatenation of BER-TLV objects.
        Returns: tuple of first TLV and remainder."""
    _tagdict, remainder = bertlv_parse_tag(binary)
    length, remainder = bertlv_parse_len(remainder)
    tl_length = len(binary) - len(remainder)
    tlv_length = tl_length + length
    return binary[:tlv_length], binary[tlv_length:]

class ProfileElementSequence:
    """A sequence of ProfileElement objects, which is the overall representation of an eSIM profile.

    This primarily contains a list of PEs (pe_list member) as well as a number of convenience indexes
    like the pe_by_type and pes_by_naa dicts that allow easier access to individual PEs within the
    sequence."""
    def __init__(self):
        """After calling the constructor, you have to further initialize the instance by either
        calling the parse_der() method, or by manually adding individual PEs, including the header and
        end PEs."""
        self.pe_list: List[ProfileElement] = []
        self.pe_by_type: Dict = {}
        self.pes_by_naa: Dict = {}
        self.mf: Optional[FsNodeMF] = None
        self._cur_df: Optional[FsNodeDF] = None # current DF while adding files from FS-templates

    @property
    def cur_df(self) -> Optional['FsNodeDF']:
        """Current DF; this is where the next files are created."""
        return self._cur_df

    @cur_df.setter
    def cur_df(self, new_df: 'FsNodeDF'):
        if self._cur_df == new_df:
            return
        self._cur_df = new_df

    def add_hdr_and_end(self):
        """Initialize the PE Sequence with a header and end PE."""
        if len(self.pe_list):
            raise ValueError("Cannot add header + end PE to a non-empty PE-Sequence")
        # start with a minimal/empty sequence of header + end
        self.append(ProfileElementHeader())
        self.append(ProfileElementEnd())

    def append(self, pe: ProfileElement):
        """Append a given PE to the end of the PE Sequence"""
        self.pe_list.append(pe)
        self._process_pelist()
        self.renumber_identification()

    def get_pes_for_type(self, tname: str) -> List[ProfileElement]:
        """Return list of profile elements present for given profile element type."""
        return self.pe_by_type.get(tname, [])

    def get_pe_for_type(self, tname: str) -> Optional[ProfileElement]:
        """Return a single profile element for given profile element type. Works only for
        types of which there is only a single instance in the PE Sequence!"""
        l = self.get_pes_for_type(tname)
        if len(l) == 0:
            return None
        assert len(l) == 1
        return l[0]

    def get_pes_for_templateID(self, tid: oid.OID) -> List[ProfileElement]:
        """Return list of profile elements present for given profile element type."""
        res = []
        for pe in self.pe_list:
            if not pe.templateID:
                continue
            if tid.prefix_match(pe.templateID):
                res.append(pe)
        return res

    def get_closest_prev_pe_for_templateID(self, cur: ProfileElement, tid: oid.OID) -> Optional[ProfileElement]:
        """Return the PE of given templateID that is the closest PE prior to the given PE in the
        PE-Sequence."""
        try:
            cur_idx = self.pe_list.index(cur)
        except ValueError:
            # we must be building the pe_list and cur is not yet part: scan from end of list
            cur_idx = len(self.pe_list)
        for i in reversed(range(cur_idx)):
            pe = self.pe_list[i]
            if not pe.templateID:
                continue
            if tid.prefix_match(pe.templateID):
                return pe

    def parse_der(self, der: bytes) -> None:
        """Parse a sequence of PE from SAIP DER format and store the result in self.pe_list."""
        self.pe_list = []
        remainder = der
        while len(remainder):
            first_tlv, remainder = bertlv_first_segment(remainder)
            self.pe_list.append(ProfileElement.from_der(first_tlv, pe_sequence=self))
        self._process_pelist()

    def _process_pelist(self) -> None:
        """Post-process the PE-list; update convenience accessor dicts."""
        self._rebuild_pe_by_type()
        self._rebuild_pes_by_naa()

    def _rebuild_pe_by_type(self) -> None:
        """Re-build the self.pe_by_type convenience accessor dict."""
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

    def rebuild_mandatory_services(self):
        """(Re-)build the eUICC Mandatory services list of the ProfileHeader based on what's in the
        PE-Sequence.  You would normally call this at the very end, before encoding a PE-Sequence
        to its DER format."""
        @staticmethod
        def file_type_walker(node: 'FsNode', **kwargs):
            return node.file.file_type
        # services that we cannot auto-determine and which must hence be manually specified
        manual_services = ['contactless', 'mbms', 'cat-tp', 'suciCalculatorApi', 'dns-resolution',
                           'scp11ac', 'scp11c-authorization-mechanism', 's16mode', 'eaka']
        svc_set = set()
        # rebuild mandatory NAAs
        for naa in self.pes_by_naa.keys():
            if naa not in ['usim', 'isim', 'csim']:
                continue
            # see if any of the instances is mandatory
            for inst in self.pes_by_naa[naa]:
                if 'mandated' in inst[0].header:
                    svc_set.add(naa)
        # rebuild algorithms of all mandatory akaParameters
        for aka in self.get_pes_for_type('akaParameter'):
            if 'mandated' in aka.header:
                if aka.decoded['algoConfiguration'][0] == 'algoParameter':
                    algo_par = aka.decoded['algoConfiguration'][1]
                    algo_id = algo_par['algorithmID']
                    if algo_id == 1:
                        svc_set.add('milenage')
                    elif algo_id == 2:
                        if len(algo_par['key']) == 32:
                            svc_set.add('tuak256')
                        else:
                            svc_set.add('tuak128')
                    elif algo_id == 3:
                        svc_set.add('usim-test-algorithm')
        # rebuild algorithms of all mandatory cdmaParameter
        for cdma in self.get_pes_for_type('cdmaParameter'):
            if 'mandated' in cdma.header:
                svc_set.add('cave')
        # TODO: gba-{usim,isim} (determine from EF.GBA* ?)
        # determine if EAP is mandatory
        for eap in self.get_pes_for_type('eap'):
            if 'mandated' in eap.header:
                svc_set.add('eap')
        # determine if javacard is mandatory
        for app in self.get_pes_for_type('application'):
            if 'mandated' in app.header:
                # javacard / multos distinction is not automatically possible, but multos is hypothetical
                svc_set.add('javacard')
        # recompute multiple-{usim,isim,csim}
        for naa_name in ['usim','isim','csim']:
            if naa_name in self.pes_by_naa[naa]:
                if len(self.pes_by_naa[naa]) > 1:
                    svc_set.add('multiple-' + naa_name)
        # BER-TLV (recursively scan all files for related type)
        ftype_list = self.mf.walk(file_type_walker)
        if 'BT' in ftype_list:
            svc_set.add('ber-tlv')
        # FIXME:dfLinked files (scan all files, check for non-empty Fcp.linkPath presence of DFs)
        # TODO: 5G related bits (derive from EF.UST or file presence?)
        hdr_pe = self.get_pe_for_type('header')
        # patch in the 'manual' services from the existing list:
        for old_svc in hdr_pe.decoded['eUICC-Mandatory-services'].keys():
            if old_svc in manual_services:
                svc_set.add(old_svc)
        hdr_pe.decoded['eUICC-Mandatory-services'] = {x: None for x in svc_set}

    def rebuild_mandatory_gfstelist(self):
        """(Re-)build the eUICC Mandatory GFSTEList of the ProfileHeader based on what's in the
        PE-Sequence.  You would normally call this at the very end, before encoding a PE-Sequence
        to its DER format."""
        template_set = set()
        for pe in self.pe_list:
            if pe.header and 'mandated' in pe.header:
                if 'templateID' in pe.decoded:
                    template_set.add(pe.decoded['templateID'])
        hdr_pe = self.get_pe_for_type('header')
        hdr_pe.decoded['eUICC-Mandatory-GFSTEList'] = list(template_set)

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

    def renumber_identification(self):
        """Re-generate the 'identification' numbering of all PE headers."""
        i = 1
        for pe in self.pe_list:
            hdr = pe.header
            if not hdr:
                continue
            pe.header['identification'] = i
            i += 1

    def get_index_by_pe(self, pe: ProfileElement) -> int:
        """Return a list with the indicies of all instances of PEs of petype."""
        ret = []
        i = 0
        for cur in self.pe_list:
            if cur == pe:
                return i
            i += 1
        raise ValueError('PE %s is not part of PE Sequence' % (pe))

    def insert_at_index(self, idx: int, pe: ProfileElement) -> None:
        """Insert a given [new] ProfileElement at given index into the PE Sequence."""
        self.pe_list.insert(idx, pe)
        self._process_pelist()
        self.renumber_identification()

    def insert_after_pe(self, pe_before: ProfileElement, pe_new: ProfileElement) -> None:
        """Insert a given [new] ProfileElement after a given [existing] PE in the PE Sequence."""
        idx = self.get_index_by_pe(pe_before)
        self.insert_at_index(idx+1, pe_new)

    def get_index_by_type(self, petype: str) -> List[int]:
        """Return a list with the indicies of all instances of PEs of petype."""
        ret = []
        i = 0
        for pe in self.pe_list:
            if pe.type == petype:
                ret.append(i)
            i += 1
        return ret

    def add_ssd(self, ssd: ProfileElementSSD):
        """Add a SSD (Supplementary Security Domain) After MNO-SD/ISD-P."""
        # find MNO-SD index
        idx = self.get_index_by_type('securityDomain')[0]
        # insert _after_ MNO-SD
        self.insert_at_index(idx+1, ssd)

    def remove_naas_of_type(self, naa: Naa) -> None:
        """Remove all instances of NAAs of given type. This can be used, for example,
        to remove all CSIM NAAs from a profile.  Will not just remove the PEs, but also
        any records in 'eUICC-Mandatory-services' or 'eUICC-Mandatory-GFSTEList'."""
        hdr = self.pe_by_type['header'][0]
        # remove any associated mandatory services
        for service in naa.mandatory_services:
            if service in hdr.decoded['eUICC-Mandatory-services']:
                del hdr.decoded['eUICC-Mandatory-services'][service]
        # remove any associaed mandatory filesystem templates
        for template in naa.templates:
            if template in hdr.decoded['eUICC-Mandatory-GFSTEList']:
                hdr.decoded['eUICC-Mandatory-GFSTEList'] = [x for x in hdr.decoded['eUICC-Mandatory-GFSTEList'] if not template.prefix_match(x)]
        # determine the ADF names (AIDs) of all NAA ADFs
        naa_adf_names = []
        if naa.pe_types[0] in self.pe_by_type:
            for pe in self.pe_by_type[naa.pe_types[0]]:
                adf_name = naa.adf_name()
                adf = File(adf_name, pe.decoded[adf_name])
                naa_adf_names.append(adf.df_name)
        # remove PEs of each NAA instance
        if naa.name in self.pes_by_naa:
            for inst in self.pes_by_naa[naa.name]:
                # delete all the PEs of the NAA
                self.pe_list = [pe for pe in self.pe_list if pe not in inst]
        self._process_pelist()
        # remove any RFM PEs for the just-removed ADFs
        if 'rfm' in self.pe_by_type:
            to_delete_pes = []
            for rfm_pe in self.pe_by_type['rfm']:
                if 'adfRFMAccess' in rfm_pe.decoded:
                    if rfm_pe.decoded['adfRFMAccess']['adfAID'] in naa_adf_names:
                        to_delete_pes.append(rfm_pe)
            self.pe_list = [pe for pe in self.pe_list if pe not in to_delete_pes]
        self._process_pelist()
        # TODO: remove any records related to the ADFs from EF.DIR

    @staticmethod
    def naa_for_path(path: Path) -> Optional[Naa]:
        """determine the NAA for the given path"""
        rel_path = path.relative_to_mf()
        if len(rel_path) == 0:
            # this is the MF itself
            return None
        df = rel_path[0]
        if df == 'ADF.USIM':
            return NaaUsim
        elif df == 'ADF.ISIM':
            return NaaIsim
        elif df == 'ADF.CSIM':
            return NaaCsim
        else:
            return None

    @staticmethod
    def peclass_for_path(path: Path) -> Optional[ProfileElement]:
        """Return the ProfileElement class that can contain a file with given path."""
        naa = ProfileElementSequence.naa_for_path(path)
        if naa:
            # TODO: find specific PE within Naa
            for pet_name in naa.pe_types:
                pe_cls = ProfileElement.class_for_petype(pet_name)
                ft = pe_cls().file_template_for_path(path.relative_to_mf(), adf='ADF.'+naa.name.upper())
                if ft:
                    return pe_cls, ft
        else:
            rel_path  = path.relative_to_mf()
            if len(rel_path) == 0:
                ft = ProfileElementMF().file_template_for_path(Path(['MF']))
                return ProfileElementMF, ft
            f = rel_path[0]
            if f.startswith('EF') or len(path) == 1 and path[0] == 'MF':
                ft = ProfileElementMF().file_template_for_path(path)
                if not ft:
                    return ProfileElementGFM, None
                return ProfileElementMF, ft
            if f == 'DF.CD':
                ft = ProfileElementCD().file_template_for_path(rel_path)
                if not ft:
                    return ProfileElementGFM, None
                return ProfileElementCD, ft
            if f == 'DF.TELECOM':
                ft = ProfileElementTelecom().file_template_for_path(rel_path)
                if not ft:
                    return ProfileElementGFM, None
                return ProfileElementTelecom, ft
        return ProfileElementGFM, None

    def pe_for_path(self, path: Path) -> Optional[ProfileElement]:
        """Return the ProfileElement instance that can contain a file with matching path. This will
        either be an existing PE within the sequence, or it will be a newly-allocated PE that is
        inserted into the sequence."""
        pe_class, ft = ProfileElementSequence.peclass_for_path(path)
        logger.debug("peclass_for_path(%s): %s, %s" % (path, pe_class, repr(ft)))
        if not pe_class:
            raise NotImplementedError('No support for GenericFileManagement yet')
        # check if we already have an instance
        # TODO: this assumes we only have one instance of each PE; exception will be raised if not
        pe = self.get_pe_for_type(pe_class.type)
        if not pe:
            # create a new instance
            pe = pe_class(pe_sequence=self)
            # FIXME: add it at the right location in the pe_sequence
            self.append(pe)
        return pe, ft

    def add_file_at_path(self, path: Path, l: List):
        """Add a file at given path.  This assumes that there's only one instance of USIM/ISIM/CSIM
        inside the profile, as otherwise the path name would not be globally unique."""
        pe, ft = self.pe_for_path(path)
        logger.debug("pe_for_path(%s): %s, %s" % (path, pe, ft))
        pe_name = ft.pe_name if ft else None
        file = File(pe_name, l, template=ft, name=path[-1])
        if isinstance(pe, ProfileElementGFM):
            pe.add_file(file, path)
        else:
            pe.add_file(file)
        return file

    def __repr__(self) -> str:
        return "PESequence(%s: %s)" % (self.iccid, ', '.join([str(x) for x in self.pe_list]))

    def __iter__(self) -> str:
        yield from self.pe_list

    @property
    def iccid(self) -> Optional[str]:
        """The ICCID of the profile."""
        if not 'header' in self.pe_by_type:
            return None
        if len(self.pe_by_type['header']) < 1:
            return None
        pe_hdr_dec = self.pe_by_type['header'][0].decoded
        if not 'iccid' in pe_hdr_dec:
            return None
        return b2h(pe_hdr_dec['iccid'])

    def cd(self, path: List[int]):
        """Change the current directory to the [absolute] "path"."""
        path = list(path) # make a copy before pop below
        # remove the leading MF, in case it's specified explicitly
        while len(path) and path[0] == 0x3f00:
            path.pop(0)
        df = self.mf
        for p in path:
            if not p in df.children:
                raise ValueError("%s doesn't contain child %04X" % (df, p))
            df = df.children[p]
            if not isinstance(df, FsNodeDF):
                raise ValueError("%s is not a DF, cannot change into it" % (df))
        self.cur_df = df


class FsNode:
    """A node in the filesystem hierarchy."""
    def __init__(self, fid: int, parent: Optional['FsNode'], file: Optional[File] = None,
                 name: Optional[str] = None):
        self.fid = fid
        self.file = file
        self.parent = None
        self._name = name
        if not self._name and self.file and self.file.name:
            self._name = self.file.name
        if parent:
            parent.add_child(self)

    def __str__(self):
        return '%s(%s)' % (self.__class__.__name__, self.fid_path_str)

    def __repr__(self):
        return '%s(%s, %s)' % (self.__class__.__name__, self.fid_path_str, self.name_path_str)

    @property
    def name(self) -> str:
        return self._name or '%04X' % self.fid

    @property
    def fid_path(self) -> List[int]:
        """Return the path of the node as list of integers."""
        if self.parent and self.parent != self:
            return self.parent.fid_path + [self.fid]
        else:
            return [self.fid]

    @property
    def name_path(self) -> List[str]:
        """Return the path of the node as list of integers."""
        if self.parent and self.parent != self:
            return self.parent.name_path + [self.name]
        else:
            return [self.name]

    @property
    def fid_path_str(self) -> str:
        return "/".join(['%04X' % x for x in self.fid_path])

    @property
    def name_path_str(self) -> str:
        return "/".join([x for x in self.name_path])

    @property
    def mf(self) -> 'FsNodeMF':
        """Return the MF (root) of the hierarchy."""
        x = self
        while x.parent != x:
            x = x.parent
        return x

    def walk(self, fn, **kwargs):
        """call 'fn(self, **kwargs) for the File."""
        return [fn(self, **kwargs)]

class FsNodeEF(FsNode):
    """An EF (Entry File) in the filesystem hierarchy."""

    def print_tree(self, indent: int = 0):
        print("%s%s: %s" % (' '*indent, self, repr(self.file)))

class FsNodeDF(FsNode):
    """A DF (Dedicated File) in the filesystem hierarchy."""
    def __init__(self, fid: int, parent: 'FsNodeDf', file: Optional[File] = None,
                 name: Optional[str] = None):
        super().__init__(fid, parent, file, name)
        self.children = {}
        self.children_by_name = {}

    def __iter__(self) -> FsNode:
        """Iterator over the children of this DF."""
        yield from self.children.values()

    def __getitem__(self, fid: Union[int, str]) -> FsNode:
        """Access child-nodes via dict-like lookup syntax."""
        if fid in self.children_by_name:
            return self.children_by_name[fid]
        else:
            return self.children[fid]

    def add_child(self, child: FsNode):
        """Add a child to the list of children of this DF."""
        if child.parent:
            raise ValueError('%s already has parent: %s' % (child, child.parent))
        if child.fid in self.children:
            #raise ValueError('%s already contains %s' % (self, self.children[child.fid]))
            pass
        if child.name in self.children_by_name:
            #raise ValueError('%s already contains %s' % (self, self.children_by_name[child.name]))
            pass
        self.children[child.fid] = child
        self.children_by_name[child.name] = child
        child.parent = self

    def add_file(self, file: File) -> 'FsNodeDF':
        """Create and link an appropriate FsNode for the given 'file' and insert it.
        Returns the new current DF (it might have changed)."""
        cur_df = self
        if file.node:
            raise ValueError('File %s already has a node!' % file)
        elif file.file_type in ['TR', 'LF', 'CY', 'BT']:
            file.node = FsNodeEF(file.fid, cur_df, file)
        elif file.file_type == 'DF':
            file.node = FsNodeDF(file.fid, cur_df, file)
            cur_df = file.node
        elif file.file_type == 'ADF':
            # implicit "cd /"
            file.node = FsNodeADF(file.df_name, file.fid, cur_df.mf, file)
            cur_df = file.node
        else:
            raise ValueError("Cannot add %s of unknown file_type %s to tree" % (file, file.file_type))
        logger.debug("%s.add_file(%s) -> return cur_df=%s" % (self, file, cur_df))
        return cur_df

    def print_tree(self, indent: int = 0):
        print("%s%s: %s" % (' '*indent, self, repr(self.file)))
        for c in self: # using the __iter__ method above
            c.print_tree(indent+1)

    def lookup_by_path(self, path: Path) -> FsNode:
        """Look-up a FsNode based on the [name based] given (absolute) path."""
        rel_path = path.relative_to_mf()
        cur = self.mf
        for d in rel_path:
            if not d in cur.children_by_name:
                raise KeyError('Could not find %s in %s while looking up %s from %s' % (d, cur, path, self))
            cur = cur.children_by_name[d]
        return cur

    def lookup_by_fidpath(self, path: List[int]) -> FsNode:
        """Look-up a FsNode based on the [fid baesd] given (absolute) path."""
        path = list(path) # make a copy before modification
        while len(path) and path[0] == 0x3f00:
            path.pop(0)
        cur = self.mf
        for d in path:
            if not d in cur.children:
                raise KeyError('Could not find %s in %s while looking up %s from %s' % (d, cur, path, self))
            cur = cur.children[d]
        return cur

    def walk(self, fn, **kwargs):
        """call 'fn(self, **kwargs) for the DF and recursively for all children."""
        ret = super().walk(fn, **kwargs)
        for c in self.children.values():
            ret += c.walk(fn, **kwargs)
        return ret

class FsNodeADF(FsNodeDF):
    """An ADF (Application Dedicated File) in the filesystem hierarchy."""
    def __init__(self, df_name: Hexstr, fid: Optional[int] = None, parent: Optional[FsNodeDF] = None,
                 file: Optional[File] = None, name: Optional[str] = None):
        self.df_name = df_name
        super().__init__(fid, parent, file, name)

    def __str__(self):
        return '%s(%s)' % (self.__class__.__name__, b2h(self.df_name))

class FsNodeMF(FsNodeDF):
    """The MF (Master File) in the filesystem hierarchy."""
    def __init__(self, file: Optional[File] = None):
        super().__init__(0x3f00, parent=None, file=file, name='MF')
        self.parent = self
