# -*- coding: utf-8 -*-

"""
Various constants from 3GPP TS 31.103 V16.1.0
"""

#
# Copyright (C) 2020 Supreeth Herle <herlesupreeth@gmail.com>
# Copyright (C) 2021 Harald Welte <laforge@osmocom.org>
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
#

from pySim.filesystem import *
from pySim.utils import *
from pySim.tlv import *
from pySim.ts_51_011 import EF_AD, EF_SMS, EF_SMSS, EF_SMSR, EF_SMSP
from pySim.ts_31_102 import ADF_USIM, EF_FromPreferred
from pySim.ts_31_102_telecom import EF_UServiceTable
import pySim.ts_102_221
from pySim.ts_102_221 import EF_ARR

# Mapping between ISIM Service Number and its description
EF_IST_map = {
    1: 'P-CSCF address',
    2: 'Generic Bootstrapping Architecture (GBA)',
    3: 'HTTP Digest',
    4: 'GBA-based Local Key Establishment Mechanism',
    5: 'Support of P-CSCF discovery for IMS Local Break Out',
    6: 'Short Message Storage (SMS)',
    7: 'Short Message Status Reports (SMSR)',
    8: 'Support for SM-over-IP including data download via SMS-PP as defined in TS 31.111 [31]',
    9: 'Communication Control for IMS by ISIM',
    10: 'Support of UICC access to IMS',
    11: 'URI support by UICC',
    12: 'Media Type support',
    13: 'IMS call disconnection cause',
    14: 'URI support for MO SHORT MESSAGE CONTROL',
    15: 'MCPTT',
    16: 'URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111 [31]',
    17: 'From Preferred',
    18: 'IMS configuration data',
    19: 'XCAP Configuration Data',
    20: 'WebRTC URI',
    21: 'MuD and MiD configuration data',
}

EF_ISIM_ADF_map = {
    'IST': '6F07',
    'IMPI': '6F02',
    'DOMAIN': '6F03',
    'IMPU': '6F04',
    'AD': '6FAD',
    'ARR': '6F06',
    'PCSCF': '6F09',
    'GBAP': '6FD5',
    'GBANL': '6FD7',
    'NAFKCA': '6FDD',
    'UICCIARI': '6FE7',
    'SMS': '6F3C',
    'SMSS': '6F43',
    'SMSR': '6F47',
    'SMSP': '6F42',
    'FromPreferred': '6FF7',
    'IMSConfigData': '6FF8',
    'XCAPConfigData': '6FFC',
    'WebRTCURI': '6FFA'
}

# TS 31.103 Section 4.2.2
class EF_IMPI(TransparentEF):
    class nai(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")

    def __init__(self, fid='6f02', sfid=0x02, name='EF.IMPI', desc='IMS private user identity', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_IMPI.nai

# TS 31.103 Section 4.2.3
class EF_DOMAIN(TransparentEF):
    class domain(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")

    def __init__(self, fid='6f03', sfid=0x05, name='EF.DOMAIN', desc='Home Network Domain Name', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_DOMAIN.domain

# TS 31.103 Section 4.2.4
class EF_IMPU(LinFixedEF):
    class impu(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")

    def __init__(self, fid='6f04', sfid=0x04, name='EF.IMPU', desc='IMS public user identity', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_IMPU.impu

# TS 31.103 Section 4.2.7
class EF_IST(EF_UServiceTable):
    def __init__(self, **kwargs):
        super().__init__('6f07', 0x07, 'EF.IST', 'ISIM Service Table', (1, None), EF_IST_map)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [self.AddlShellCommands()]

    @with_default_category('File-Specific Commands')
    class AddlShellCommands(CommandSet):
        def __init__(self):
            super().__init__()

        def do_ist_service_activate(self, arg):
            """Activate a service within EF.IST"""
            self._cmd.card.update_ist(int(arg), 1)

        def do_ist_service_deactivate(self, arg):
            """Deactivate a service within EF.IST"""
            self._cmd.card.update_ist(int(arg), 0)

        def do_ist_service_check(self, arg):
            """Check consistency between services of this file and files present/activated.

            Many services determine if one or multiple files shall be present/activated or if they shall be
            absent/deactivated.  This performs a consistency check to ensure that no services are activated
            for files that are not - and vice-versa, no files are activated for services that are not.  Error
            messages are printed for every inconsistency found."""
            selected_file = self._cmd.lchan.selected_file
            num_problems = selected_file.ust_service_check(self._cmd)
            self._cmd.poutput("===> %u service / file inconsistencies detected" % num_problems)


# TS 31.103 Section 4.2.8
class EF_PCSCF(LinFixedEF):
    def __init__(self, fid='6f09', sfid=None, name='EF.P-CSCF', desc='P-CSCF Address', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)

    def _decode_record_hex(self, raw_hex):
        addr, addr_type = dec_addr_tlv(raw_hex)
        return {"addr": addr, "addr_type": addr_type}

    def _encode_record_hex(self, json_in):
        addr = json_in['addr']
        addr_type = json_in['addr_type']
        return enc_addr_tlv(addr, addr_type)

# TS 31.103 Section 4.2.9
class EF_GBABP(TransparentEF):
    def __init__(self, fid='6fd5', sfid=None, name='EF.GBABP', desc='GBA Bootstrapping', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)

# TS 31.103 Section 4.2.10
class EF_GBANL(LinFixedEF):
    def __init__(self, fid='6fd7', sfid=None, name='EF.GBANL', desc='GBA NAF List', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)

# TS 31.103 Section 4.2.11
class EF_NAFKCA(LinFixedEF):
    def __init__(self, fid='6fdd', sfid=None, name='EF.NAFKCA', desc='NAF Key Centre Address', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)

# TS 31.103 Section 4.2.16
class EF_UICCIARI(LinFixedEF):
    class iari(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")

    def __init__(self, fid='6fe7', sfid=None, name='EF.UICCIARI', desc='UICC IARI', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_UICCIARI.iari

# TS 31.103 Section 4.2.18
class EF_IMSConfigData(BerTlvEF):
    class ImsConfigDataEncoding(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(Bytes(1))
    class ImsConfigData(BER_TLV_IE, tag=0x81):
        _construct = GreedyString
    # pylint: disable=undefined-variable
    class ImsConfigDataCollection(TLV_IE_Collection, nested=[ImsConfigDataEncoding, ImsConfigData]):
        pass
    def __init__(self, fid='6ff8', sfid=None, name='EF.IMSConfigData', desc='IMS Configuration Data', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_IMSConfigData.ImsConfigDataCollection

# TS 31.103 Section 4.2.19
class EF_XCAPConfigData(BerTlvEF):
    class Access(BER_TLV_IE, tag=0x81):
        pass
    class ApplicationName(BER_TLV_IE, tag=0x82):
        pass
    class ProviderID(BER_TLV_IE, tag=0x83):
        pass
    class URI(BER_TLV_IE, tag=0x84):
        pass
    class XcapAuthenticationUserName(BER_TLV_IE, tag=0x85):
        pass
    class XcapAuthenticationPassword(BER_TLV_IE, tag=0x86):
        pass
    class XcapAuthenticationType(BER_TLV_IE, tag=0x87):
        pass
    class AddressType(BER_TLV_IE, tag=0x88):
        pass
    class Address(BER_TLV_IE, tag=0x89):
        pass
    class PDPAuthenticationType(BER_TLV_IE, tag=0x8a):
        pass
    class PDPAuthenticationName(BER_TLV_IE, tag=0x8b):
        pass
    class PDPAuthenticationSecret(BER_TLV_IE, tag=0x8c):
        pass

    class AccessForXCAP(BER_TLV_IE, tag=0x81):
        pass
    class NumberOfXcapConnParPolicy(BER_TLV_IE, tag=0x82):
        _construct = Int8ub
    # pylint: disable=undefined-variable
    class XcapConnParamsPolicyPart(BER_TLV_IE, tag=0xa1, nested=[Access, ApplicationName, ProviderID, URI,
                                 XcapAuthenticationUserName, XcapAuthenticationPassword,
                                 XcapAuthenticationType, AddressType, Address, PDPAuthenticationType,
                                 PDPAuthenticationName, PDPAuthenticationSecret]):
        pass
    class XcapConnParamsPolicy(BER_TLV_IE, tag=0xa0, nested=[AccessForXCAP, NumberOfXcapConnParPolicy, XcapConnParamsPolicyPart]):
        pass
    class XcapConnParamsPolicyDO(BER_TLV_IE, tag=0x80, nested=[XcapConnParamsPolicy]):
        pass
    def __init__(self, fid='6ffc', sfid=None, name='EF.XCAPConfigData', desc='XCAP Configuration Data', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_XCAPConfigData.XcapConnParamsPolicy

# TS 31.103 Section 4.2.20
class EF_WebRTCURI(TransparentEF):
    class uri(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")

    def __init__(self, fid='6ffa', sfid=None, name='EF.WebRTCURI', desc='WebRTC URI', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_WebRTCURI.uri

# TS 31.103 Section 4.2.21
class EF_MuDMiDConfigData(BerTlvEF):
    class MudMidConfigDataEncoding(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(Bytes(1))
    class MudMidConfigData(BER_TLV_IE, tag=0x81):
        _construct = GreedyString
    # pylint: disable=undefined-variable
    class MudMidConfigDataCollection(TLV_IE_Collection, nested=[MudMidConfigDataEncoding, MudMidConfigData]):
        pass
    def __init__(self, fid='6ffe', sfid=None, name='EF.MuDMiDConfigData',
                 desc='MuD and MiD Configuration Data', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_MuDMiDConfigData.MudMidConfigDataCollection


class ADF_ISIM(CardADF):
    def __init__(self, aid='a0000000871004', name='ADF.ISIM', fid=None, sfid=None,
                 desc='ISIM Application'):
        super().__init__(aid=aid, fid=fid, sfid=sfid, name=name, desc=desc)

        files = [
            EF_IMPI(),
            EF_DOMAIN(),
            EF_IMPU(),
            EF_AD(),
            EF_ARR('6f06', 0x06),
            EF_IST(),
            EF_PCSCF(service=5),
            EF_GBABP(service=2),
            EF_GBANL(service=2),
            EF_NAFKCA(service=2),
            EF_SMS(service=(6,8)),
            EF_SMSS(service=(6,8)),
            EF_SMSR(service=(7,8)),
            EF_SMSP(service=8),
            EF_UICCIARI(service=10),
            EF_FromPreferred(service=17),
            EF_IMSConfigData(service=18),
            EF_XCAPConfigData(service=19),
            EF_WebRTCURI(service=20),
            EF_MuDMiDConfigData(service=21),
        ]
        self.add_files(files)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [ADF_USIM.AddlShellCommands()]

    def decode_select_response(self, data_hex):
        return pySim.ts_102_221.CardProfileUICC.decode_select_response(data_hex)


# TS 31.103 Section 7.1
sw_isim = {
    'Security management': {
        '9862': 'Authentication error, incorrect MAC',
        '9864': 'Authentication error, security context not supported',
    }
}


class CardApplicationISIM(CardApplication):
    def __init__(self):
        super().__init__('ISIM', adf=ADF_ISIM(), sw=sw_isim)
