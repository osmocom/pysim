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
    def __init__(self, fid='6f02', sfid=0x02, name='EF.IMPI', desc='IMS private user identity'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)
        self._tlv = EF_IMPI.nai

# TS 31.103 Section 4.2.3
class EF_DOMAIN(TransparentEF):
    class domain(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")
    def __init__(self, fid='6f05', sfid=0x05, name='EF.DOMAIN', desc='Home Network Domain Name'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)
        self._tlv = EF_DOMAIN.domain

# TS 31.103 Section 4.2.4
class EF_IMPU(LinFixedEF):
    class impu(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")
    def __init__(self, fid='6f04', sfid=0x04, name='EF.IMPU', desc='IMS public user identity'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)
        self._tlv = EF_IMPU.impu

# TS 31.103 Section 4.2.7
class EF_IST(TransparentEF):
    def __init__(self, fid='6f07', sfid=0x07, name='EF.IST', desc='ISIM Service Table'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, size={1,4})
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

# TS 31.103 Section 4.2.8
class EF_PCSCF(LinFixedEF):
    def __init__(self, fid='6f09', sfid=None, name='EF.P-CSCF', desc='P-CSCF Address'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)
    def _decode_record_hex(self, raw_hex):
        addr, addr_type = dec_addr_tlv(raw_hex)
        return {"addr": addr, "addr_type": addr_type}
    def _encode_record_hex(self, json_in):
        addr = json_in['addr']
        addr_type = json_in['addr_type']
        return enc_addr_tlv(addr, addr_type)

# TS 31.103 Section 4.2.9
class EF_GBABP(TransparentEF):
    def __init__(self, fid='6fd5', sfid=None, name='EF.GBABP', desc='GBA Bootstrapping'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)

# TS 31.103 Section 4.2.10
class EF_GBANL(LinFixedEF):
    def __init__(self, fid='6fd7', sfid=None, name='EF.GBANL', desc='GBA NAF List'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)

# TS 31.103 Section 4.2.11
class EF_NAFKCA(LinFixedEF):
    def __init__(self, fid='6fdd', sfid=None, name='EF.NAFKCA', desc='NAF Key Centre Address'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)

# TS 31.103 Section 4.2.16
class EF_UICCIARI(LinFixedEF):
    class iari(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")
    def __init__(self, fid='6fe7', sfid=None, name='EF.UICCIARI', desc='UICC IARI'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)
        self._tlv = EF_UICCIARI.iari

# TS 31.103 Section 4.2.18
class EF_IMSConfigData(BerTlvEF):
    def __init__(self, fid='6ff8', sfid=None, name='EF.IMSConfigData', desc='IMS Configuration Data'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)

# TS 31.103 Section 4.2.19
class EF_XCAPConfigData(BerTlvEF):
    def __init__(self, fid='6ffc', sfid=None, name='EF.XCAPConfigData', desc='XCAP Configuration Data'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)

# TS 31.103 Section 4.2.20
class EF_WebRTCURI(TransparentEF):
    class uri(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")
    def __init__(self, fid='6ffa', sfid=None, name='EF.WebRTCURI', desc='WebRTC URI'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)
        self._tlv = EF_WebRTCURI.uri

# TS 31.103 Section 4.2.21
class EF_MuDMiDConfigData(BerTlvEF):
    def __init__(self, fid='6ffe', sfid=None, name='EF.MuDMiDConfigData',
                 desc='MuD and MiD Configuration Data'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc)


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
            EF_PCSCF(),
            EF_GBABP(),
            EF_GBANL(),
            EF_NAFKCA(),
            EF_SMS(),
            EF_SMSS(),
            EF_SMSR(),
            EF_SMSP(),
            EF_UICCIARI(),
            EF_FromPreferred(),
            EF_IMSConfigData(),
            EF_XCAPConfigData(),
            EF_WebRTCURI(),
            EF_MuDMiDConfigData(),
          ]
        self.add_files(files)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [ADF_USIM.AddlShellCommands()]

    def decode_select_response(self, data_hex):
        return pySim.ts_102_221.decode_select_response(data_hex)

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
