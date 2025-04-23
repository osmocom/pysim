# -*- coding: utf-8 -*-

"""
Various constants from 3GPP TS 31.103 V18.1.0
"""

#
# Copyright (C) 2020 Supreeth Herle <herlesupreeth@gmail.com>
# Copyright (C) 2021-2024 Harald Welte <laforge@osmocom.org>
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

from construct import Struct, Switch, this, GreedyString
from osmocom.utils import *
from osmocom.tlv import *
from osmocom.construct import *
from pySim.filesystem import *
from pySim.ts_51_011 import EF_AD, EF_SMS, EF_SMSS, EF_SMSR, EF_SMSP
from pySim.ts_31_102 import ADF_USIM, EF_FromPreferred
from pySim.ts_31_102_telecom import EF_UServiceTable
from pySim.ts_31_103_shared import *
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
    22: 'IMS Data Channel indication',
}

# TS 31.103 Section 4.2.2
class EF_IMPI(TransparentEF):
    _test_de_encode = [
        ( '803137333830303630303030303031303140696d732e6d6e633030302e6d63633733382e336770706e6574776f726b2e6f7267',
          { "nai": "738006000000101@ims.mnc000.mcc738.3gppnetwork.org" } ),
    ]

    class nai(BER_TLV_IE, tag=0x80):
        _construct = Utf8Adapter(GreedyBytes)

    def __init__(self, fid='6f02', sfid=0x02, name='EF.IMPI', desc='IMS private user identity', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_IMPI.nai

# TS 31.103 Section 4.2.3
class EF_DOMAIN(TransparentEF):
    _test_de_encode = [
        ( '8021696d732e6d6e633030302e6d63633733382e336770706e6574776f726b2e6f7267',
          { "domain": "ims.mnc000.mcc738.3gppnetwork.org" } ),
    ]
    class domain(BER_TLV_IE, tag=0x80):
        _construct = Utf8Adapter(GreedyBytes)

    def __init__(self, fid='6f03', sfid=0x05, name='EF.DOMAIN', desc='Home Network Domain Name', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_DOMAIN.domain

# TS 31.103 Section 4.2.4
class EF_IMPU(LinFixedEF):
    _test_de_encode = [
        ( '80357369703a37333830303630303030303031303140696d732e6d6e633030302e6d63633733382e336770706e6574776f726b2e6f7267',
          { "impu": "sip:738006000000101@ims.mnc000.mcc738.3gppnetwork.org" } ),
    ]
    class impu(BER_TLV_IE, tag=0x80):
        _construct = Utf8Adapter(GreedyBytes)

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
            selected_file = self._cmd.lchan.selected_file
            selected_file.ust_update(self._cmd, [int(arg)], [])

        def do_ist_service_deactivate(self, arg):
            """Deactivate a service within EF.IST"""
            selected_file = self._cmd.lchan.selected_file
            selected_file.ust_update(self._cmd, [], [int(arg)])

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
    _test_de_encode = [
        ( '802c0070637363662e696d732e6d6e633030302e6d63633733382e7075622e336770706e6574776f726b2e6f7267',
          {'pcscf_address': { "address": "pcscf.ims.mnc000.mcc738.pub.3gppnetwork.org", "type_of_address": "FQDN" } } ),
        ( '800501c0a80c22',
          {'pcscf_address': { "address": "192.168.12.34", "type_of_address": "IPv4" } } ),
        ( '801102fe800000000000000042d7fffe530335',
          {'pcscf_address': { "address": "fe80::42:d7ff:fe53:335", "type_of_address": "IPv6" } } ),
    ]
    class PcscfAddress(BER_TLV_IE, tag=0x80):
        _construct = Struct('type_of_address'/Enum(Byte, FQDN=0, IPv4=1, IPv6=2),
                            'address'/Switch(this.type_of_address,
                                             {'FQDN': Utf8Adapter(GreedyBytes),
                                              'IPv4': Ipv4Adapter(GreedyBytes),
                                              'IPv6': Ipv6Adapter(GreedyBytes)}))

    def __init__(self, fid='6f09', sfid=None, name='EF.P-CSCF', desc='P-CSCF Address', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_PCSCF.PcscfAddress

# TS 31.103 Section 4.2.9
class EF_GBABP(TransparentEF):
    def __init__(self, fid='6fd5', sfid=None, name='EF.GBABP', desc='GBA Bootstrapping', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._construct = Struct('rand'/LV,
                                 'b_tid'/LV,
                                 'key_lifetime'/LV)

# TS 31.103 Section 4.2.10
class EF_GBANL(LinFixedEF):
    class NAF_ID(BER_TLV_IE, tag=0x80):
        _construct = Struct('fqdn'/Utf8Adapter(Bytes(this._.total_len-5)),
                            'ua_spi'/HexAdapter(Bytes(5)))
    class B_TID(BER_TLV_IE, tag=0x81):
        _construct = Utf8Adapter(GreedyBytes)
    # pylint: disable=undefined-variable
    class GbaNlCollection(TLV_IE_Collection, nested=[NAF_ID, B_TID]):
        pass
    def __init__(self, fid='6fd7', sfid=None, name='EF.GBANL', desc='GBA NAF List', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_GBANL.GbaNlCollection

# TS 31.103 Section 4.2.11
class EF_NAFKCA(LinFixedEF):
    _test_de_encode = [
        ( '80296273662e696d732e6d6e633030302e6d63633733382e7075622e336770706e6574776f726b2e6f7267',
          { 'naf_key_centre_address': 'bsf.ims.mnc000.mcc738.pub.3gppnetwork.org' } ),
        ( '8030656e65746e61667830312e696d732e6d6e633030302e6d63633733382e7075622e336770706e6574776f726b2e6f7267',
          { 'naf_key_centre_address': 'enetnafx01.ims.mnc000.mcc738.pub.3gppnetwork.org' }),
    ]
    class NafKeyCentreAddress(BER_TLV_IE, tag=0x80):
        _construct = Utf8Adapter(GreedyBytes)
    def __init__(self, fid='6fdd', sfid=None, name='EF.NAFKCA', desc='NAF Key Centre Address', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_NAFKCA.NafKeyCentreAddress


class ADF_ISIM(CardADF):
    def __init__(self, aid='a0000000871004', has_fs=True, name='ADF.ISIM', fid=None, sfid=None,
                 desc='ISIM Application'):
        super().__init__(aid=aid, has_fs=has_fs, fid=fid, sfid=sfid, name=name, desc=desc)

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
            EF_AC_GBAUAPI(service=2),
            EF_IMSDCI(service=22),
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
