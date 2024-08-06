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
from collections import OrderedDict

import asn1tools

from pySim.utils import bertlv_parse_tag, bertlv_parse_len, b2h, h2b, dec_imsi, Hexstr
from pySim.ts_102_221 import FileDescriptor
from pySim.filesystem import CardADF
from pySim.ts_31_102 import ADF_USIM
from pySim.ts_31_103 import ADF_ISIM
from pySim.construct import build_construct
from pySim.esim import compile_asn1_subdir
from pySim.esim.saip import templates
from pySim.esim.saip import oid
from pySim.tlv import BER_TLV_IE
from pySim.global_platform import KeyType, KeyUsageQualifier
from pySim.global_platform.uicc import UiccSdInstallParams

asn1 = compile_asn1_subdir('saip')

class Naa:
    """A class defining a Network Access Application (NAA)."""
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
    name = "csim"
    aid = h2b("")
    mandatory_services = ["csim"]
    pe_types = ["csim", "opt-csim", "cdmaParameter"]
    templates = [oid.ADF_CSIM_by_default, oid.ADF_CSIMopt_not_by_default]

class NaaUsim(Naa):
    name = "usim"
    aid = h2b("a0000000871002")
    mandatory_services = ["usim"]
    pe_types = ["usim", "opt-usim"]
    templates = [oid.ADF_USIM_by_default, oid.ADF_USIMopt_not_by_default,
                 oid.DF_PHONEBOOK_ADF_USIM, oid.DF_GSM_ACCESS_ADF_USIM,
                 oid.DF_EAP, oid.DF_5GS, oid.DF_SAIP, oid.DF_SNPN,
                 oid.DF_5GProSe]
    adf = ADF_USIM()

class NaaIsim(Naa):
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
        if l:
            self.from_tuples(l)

    def _encode_file_size(self, size: int) -> bytes:
        # FIXME: handle > v2.0 case where it must be encoded on the minimum number of octets possible
        return size.to_bytes(2, 'big')

    def from_template(self, template: templates.FileTemplate):
        """Determine defaults for file based on given FileTemplate."""
        fdb_dec = {}
        pefi = {}
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
                self.fileDescriptor['efFileSize'] = self._encode_file_size(template.nb_rec * template.rec_len)
            if template.file_type == 'LF':
                fdb_dec['structure'] = 'linear_fixed'
            elif template.file_type == 'CY':
                fdb_dec['structure'] = 'cyclic'
        elif template.file_type == 'BT':
            fdb_dec['file_type'] = 'working_ef'
            fdb_dec['structure'] = 'ber_tlv'
            if template.file_size:
                pefi['maximumFileSize'] = self._encode_file_size(template.file_size)
        elif template.file_type == 'TR':
            fdb_dec['file_type'] = 'working_ef'
            fdb_dec['structure'] = 'transparent'
            if template.file_size:
                self.fileDescriptor['efFileSize'] = self._encode_file_size(template.file_size)
        elif template.file_type in ['MF', 'DF', 'ADF']:
            fdb_dec['file_type'] = 'df'
            fdb_dec['structure'] = 'no_info_given'
        # build file descriptor based on above input data
        fd_dict = {'file_descriptor_byte': fdb_dec}
        if self.rec_len:
            fd_dict['record_len'] = self.rec_len
        self.fileDescriptor['fileDescriptor'] = build_construct(FileDescriptor._construct, fd_dict)
        if template.high_update:
            pefi['specialFileInformation'] = b'\x80' # TS 102 222 Table 5
        try:
            if template.default_val_repeat:
                pefi['repeatPattern'] = template.expand_default_value_pattern()
            elif template.default_val:
                pefi['fillPattern'] = template.expand_default_value_pattern()
        except ValueError:
            # ignore this here as without a file or record length we cannot do this
            pass
        if len(pefi.keys()):
            self.fileDescriptor['proprietaryEFInfo'] = pefi

    def from_tuples(self, l:List[Tuple]):
        """Parse a list of fileDescriptor, fillFileContent, fillFileOffset tuples into this instance."""
        def get_fileDescriptor(l:List[Tuple]):
            for k, v in l:
                if k == 'fileDescriptor':
                    return v
        fd = get_fileDescriptor(l)
        if not fd and not self.fileDescriptor:
            raise ValueError("No fileDescriptor found in tuple, and none set by template before")
        if fd:
            self.fileDescriptor.update(dict(fd))
        self.stream = self.linearize_file_content(l)

    def from_gfm(self, d: Dict):
        print(d)
        # FIXME

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
        }

    def __init__(self, decoded = None, mandated: bool = True):
        if decoded:
            self.decoded = decoded
        else:
            self.decoded = OrderedDict()
            if self.header_name:
                self.decoded[self.header_name] = { 'identification': None}
                if mandated:
                    self.decoded[self.header_name] = { 'mandated': None}

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

    @property
    def header_name(self) -> str:
        """Return the name of the header field within the profile element."""
        # unneccessarry compliaction by inconsistent naming :(
        if self.type.startswith('opt-'):
            return self.type.replace('-','') + '-header'
        if self.type in self.header_name_translation_dict:
            return self.header_name_translation_dict[self.type]
        return self.type + '-header'

    @property
    def header(self):
        """Return the decoded ProfileHeader."""
        return self.decoded.get(self.header_name, None)

    @property
    def identification(self):
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
            # TODO: rfm
            # TODO: application
            # TODO: nonStandard
            'end': ProfileElementEnd,
            'mf': ProfileElementMF,
            # TODO: cd
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
    def from_der(cls, der: bytes) -> 'ProfileElement':
        """Construct an instance from given raw, DER encoded bytes."""
        pe_type, decoded = asn1.decode('ProfileElement', der)
        pe_cls = cls.class_for_petype(pe_type)
        if pe_cls:
            inst = pe_cls(decoded)
        else:
            inst = ProfileElement(decoded)
            inst.type = pe_type
        # work around asn1tools bug regarding DEFAULT for a SEQUENCE OF
        inst._fixup_sqnInit_dec()
        # run any post-decoder a derived class may have
        if hasattr(inst, '_post_decode'):
            inst._post_decode()
        return inst

    def to_der(self) -> bytes:
        """Build an encoded DER representation of the instance."""
        # run any pre-encoder a derived class may have
        if hasattr(self, '_pre_encode'):
            self._pre_encode()
        # work around asn1tools bug regarding DEFAULT for a SEQUENCE OF
        self._fixup_sqnInit_enc()
        return asn1.encode('ProfileElement', (self.type, self.decoded))

    def __str__(self) -> str:
        return self.type

class FsProfileElement(ProfileElement):
    """A file-system bearing profile element, like MF, USIM, ...."""

    def __init__(self, decoded = None, mandated: bool = True):
        super().__init__(decoded, mandated)
        # indexed by PE-Name
        self.files = {}
        self.tdef = asn1.types['ProfileElement'].type.name_to_member[self.type]

    def add_file(self, file: File):
        """Add a File to the ProfileElement."""
        if file.pe_name in self.files:
            raise KeyError('Cannot add file: %s already exists' % file.pename)
        self.files[file.pe_name] = file

    def files2pe(self):
        """Update the "decoded" member with the contents of the files member."""
        for f in self.files:
            self.decoded[f.pename] = f.to_tuples()

    def pe2files(self):
        """Update the "files" member with the contents of the "decoded" member."""
        tdict = {x.name: x for x in self.tdef.root_members}
        template = templates.ProfileTemplateRegistry.get_by_oid(self.templateID)
        for k, v in self.decoded.items():
            if tdict[k].type_name == 'File':
                self.add_file(File(k, v, template.files_by_pename.get(k, None)))

    def _post_decode(self):
        # not entirely sure about this automatism
        self.pe2files()

    def _pre_encode(self):
        # should we do self.pe2files()?  I don't think so
        #self.files2pe()
        pass

class ProfileElementGFM(ProfileElement):
    type = 'genericFileManagement'

    def __init__(self, decoded = None, mandated: bool = True):
        super().__init__(decoded, mandated)
        # indexed by PE-Name
        self.files = {}
        self.tdef = asn1.types['ProfileElement'].type.name_to_member[self.type]

    def add_file(self, path, file: File):
        # FIXME: proper FS hiearchy
        #if path in self.files:
        #    raise KeyError('Cannot add file: path %s already exists' % path)
        self.files[path] = file

    def pe2files(self):
        """Update the "files" member with the contents of the "decoded" member."""
        def perform(self, path, file_elements):
            if len(file_elements):
                file = File('', file_elements)
                self.add_file(path, file)

        path = "3f00" # current DF: MF
        file_elements = []
        # looks like TCA added one level too much in the ASN.1 hierarchy here
        for fmc in self.decoded['fileManagementCMD']:
            for fmc2 in fmc:
                if fmc2[0] == 'filePath':
                    # selecting a new path means we're done with the previous file
                    perform(self, path, file_elements)
                    if fmc2[1] == "":
                        path = "3f00"
                    else:
                        # FIXME
                        pass
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

    def _post_decode(self):
        # not entirely sure about this automatism
        self.pe2files()


class ProfileElementMF(FsProfileElement):
    type = 'mf'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.MF)
        for fname in ['mf', 'ef-iccid', 'ef-dir', 'ef-arr']:
            self.decoded[fname] = []
        # TODO: resize EF.DIR?

class ProfileElementPuk(ProfileElement):
    type = 'pukCodes'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
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
    type = 'pinCodes'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
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
    type = 'telecom'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.DF_TELECOM_v2)
        for fname in ['df-telecom', 'ef-arr']:
            self.decoded[fname] = []

class ProfileElementPhonebook(FsProfileElement):
    type = 'phonebook'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_PHONEBOOK_ADF_USIM)
        for fname in ['df-phonebook']:
            self.decoded[fname] = []

class ProfileElementGsmAccess(FsProfileElement):
    type = 'gsm-access'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_GSM_ACCESS_ADF_USIM)
        for fname in ['df-gsm-access']:
            self.decoded[fname] = []

class ProfileElementDf5GS(FsProfileElement):
    type = 'df-5gs'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_5GS_v3)
        for fname in ['df-5gs']:
            self.decoded[fname] = []

class ProfileElementEAP(FsProfileElement):
    type = 'eap'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_EAP)
        for fname in ['df-eap', 'ef-eapstatus']:
            self.decoded[fname] = []

class ProfileElementDfSAIP(FsProfileElement):
    type = 'df-saip'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_SAIP)
        for fname in ['df-saip']:
            self.decoded[fname] = []

class ProfileElementDfSNPN(FsProfileElement):
    type = 'df-snpn'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults
        self.decoded['templateID'] = str(oid.DF_SNPN)
        for fname in ['df-snpn']:
            self.decoded[fname] = []

class ProfileElementDf5GProSe(FsProfileElement):
    type = 'df-5gprose'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
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
    """Represenation of a key used for SCP access to a security domain."""
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

    class C9(BER_TLV_IE, tag=0xC9, nested=UiccSdInstallParams):
        pass

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
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
    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # defaults [overriding ProfileElementSD) taken from SAIP v2.3.1 Section 11.2.12
        self.decoded['instance']['instanceAID'] = h2b('A00000055910100102736456616C7565')
        self.decoded['instance']['applicationPrivileges'] = h2b('808000')
        self.decoded['instance']['applicationParameters'] = {
                # TAR: 6C7565, MSL: 12
                'uiccToolkitApplicationSpecificParametersField': h2b('01000001000000020112036C756500'),
            }

class ProfileElementRFM(ProfileElement):
    type = 'rfm'

    def __init__(self, decoded: Optional[dict] = None,
                 inst_aid: Optional[bytes] = None, sd_aid: Optional[bytes] = None,
                 adf_aid: Optional[bytes] = None,
                 tar_list: Optional[List[bytes]] = [], msl: Optional[int] = 0x06):
        super().__init__(decoded)
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
    type = 'usim'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
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
        f = File('ef-imsi', self.decoded['ef-imsi'])
        return dec_imsi(b2h(f.stream.getvalue()))

class ProfileElementOptUSIM(FsProfileElement):
    type = 'opt-usim'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.ADF_USIMopt_not_by_default_v2)

class ProfileElementISIM(FsProfileElement):
    type = 'isim'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
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
    type = 'opt-isim'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.decoded['templateID'] = str(oid.ADF_ISIMopt_not_by_default_v2)


class ProfileElementAKA(ProfileElement):
    type = 'akaParameter'

    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)
        if decoded:
            return
        # provide some reasonable defaults for a MNO-SD
        self.set_milenage(b'\x00'*16, b'\x00'*16)

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
        self.decoded['algoConfiguration'] = ('mappingParamete', {
            'mappingOptions': bytes([options]),
            'mappingSource': aid,
        })

class ProfileElementHeader(ProfileElement):
    type = 'header'
    def __init__(self, decoded: Optional[dict] = None,
                 ver_major: Optional[int] = 2, ver_minor: Optional[int] = 3,
                 iccid: Optional[Hexstr] = '0'*20, profile_type: Optional[str] = None):
        super().__init__(decoded)
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

class ProfileElementEnd(ProfileElement):
    type = 'end'
    def __init__(self, decoded: Optional[dict] = None):
        super().__init__(decoded)

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
        self.pe_list: List[ProfileElement] = []
        self.pe_by_type: Dict = {}
        self.pes_by_naa: Dict = {}

    def append(self, pe: ProfileElement):
        """Append a PE to the PE Sequence"""
        self.pe_list.append(pe)
        self._process_pelist()
        self.renumber_identification()

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

    def rebuild_mandatory_services(self):
        """(Re-)build the eUICC Mandatory services list of the ProfileHeader based on what's in the
        PE-Sequence."""
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
        # TODO: BER-TLV (scan all files for related type?)
        # TODO: dfLinked files (scan all files, check for non-empty Fcp.linkPath presence of DFs)
        # TODO: 5G related bits (derive from EF.UST or file presence?)
        hdr_pe = self.get_pe_for_type('header')
        # patch in the 'manual' services from the existing list:
        for old_svc in hdr_pe.decoded['eUICC-Mandatory-services'].keys():
            if old_svc in manual_services:
                svc_set.add(old_svc)
        hdr_pe.decoded['eUICC-Mandatory-services'] = {x: None for x in svc_set}

    def rebuild_mandatory_gfstelist(self):
        """(Re-)build the eUICC Mandatory GFSTEList of the ProfileHeader based on what's in the
        PE-Sequence."""
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
        self.pe_list.insert(idx+1, ssd)
        self._process_pelist()
        self.renumber_identification()

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
                naa_adf_names.append(adf.fileDescriptor['dfName'])
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
