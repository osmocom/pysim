# -*- coding: utf-8 -*-

# without this, pylint will fail when inner classes are used
# within the 'nested' kwarg of our TlvMeta metaclass on python 3.7 :(
# pylint: disable=undefined-variable

""" Various constants from ETSI TS 151.011 +
Representation of the GSM SIM/USIM/ISIM filesystem hierarchy.

The File (and its derived classes) uses the classes of pySim.filesystem in
order to describe the files specified in the relevant ETSI + 3GPP specifications.
"""

#
# Copyright (C) 2017 Alexander.Chemeris <Alexander.Chemeris@gmail.com>
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

import enum
from struct import pack, unpack
from typing import Tuple

from construct import Optional as COptional
from construct import *
from osmocom.tlv import *
from osmocom.utils import *
from osmocom.construct import *

from pySim.utils import dec_iccid, enc_iccid, dec_imsi, enc_imsi, dec_plmn, enc_plmn, dec_xplmn_w_act
from pySim.profile import CardProfile, CardProfileAddon
from pySim.filesystem import *
from pySim.ts_31_102_telecom import DF_PHONEBOOK, DF_MULTIMEDIA, DF_MCS, DF_V2X
from pySim.gsm_r import AddonGSMR

# Mapping between SIM Service Number and its description
EF_SST_map = {
    1: 'CHV1 disable function',
    2: 'Abbreviated Dialling Numbers (ADN)',
    3: 'Fixed Dialling Numbers (FDN)',
    4: 'Short Message Storage (SMS)',
    5: 'Advice of Charge (AoC)',
    6: 'Capability Configuration Parameters (CCP)',
    7: 'PLMN selector',
    8: 'RFU',
    9: 'MSISDN',
    10: 'Extension1',
    11: 'Extension2',
    12: 'SMS Parameters',
    13: 'Last Number Dialled (LND)',
    14: 'Cell Broadcast Message Identifier',
    15: 'Group Identifier Level 1',
    16: 'Group Identifier Level 2',
    17: 'Service Provider Name',
    18: 'Service Dialling Numbers (SDN)',
    19: 'Extension3',
    20: 'RFU',
    21: 'VGCS Group Identifier List (EFVGCS and EFVGCSS)',
    22: 'VBS Group Identifier List (EFVBS and EFVBSS)',
    23: 'enhanced Multi-Level Precedence and Pre-emption Service',
    24: 'Automatic Answer for eMLPP',
    25: 'Data download via SMS-CB',
    26: 'Data download via SMS-PP',
    27: 'Menu selection',
    28: 'Call control',
    29: 'Proactive SIM',
    30: 'Cell Broadcast Message Identifier Ranges',
    31: 'Barred Dialling Numbers (BDN)',
    32: 'Extension4',
    33: 'De-personalization Control Keys',
    34: 'Co-operative Network List',
    35: 'Short Message Status Reports',
    36: 'Network\'s indication of alerting in the MS',
    37: 'Mobile Originated Short Message control by SIM',
    38: 'GPRS',
    39: 'Image (IMG)',
    40: 'SoLSA (Support of Local Service Area)',
    41: 'USSD string data object supported in Call Control',
    42: 'RUN AT COMMAND command',
    43: 'User controlled PLMN Selector with Access Technology',
    44: 'Operator controlled PLMN Selector with Access Technology',
    45: 'HPLMN Selector with Access Technology',
    46: 'CPBCCH Information',
    47: 'Investigation Scan',
    48: 'Extended Capability Configuration Parameters',
    49: 'MExE',
    50: 'Reserved and shall be ignored',
    51: 'PLMN Network Name',
    52: 'Operator PLMN List',
    53: 'Mailbox Dialling Numbers',
    54: 'Message Waiting Indication Status',
    55: 'Call Forwarding Indication Status',
    56: 'Service Provider Display Information',
    57: 'Multimedia Messaging Service (MMS)',
    58: 'Extension 8',
    59: 'MMS User Connectivity Parameters',
}


######################################################################
# DF.TELECOM
######################################################################


# TS 51.011 Section 10.5.1 / Table 12
class ExtendedBcdAdapter(Adapter):
    """Replace some hex-characters with other ASCII characters"""
    # we only translate a=* / b=# as they habe a clear representation
    # in terms of USSD / SS service codes
    def _decode(self, obj, context, path):
        if not isinstance(obj, str):
            return obj
        return obj.lower().replace("a","*").replace("b","#")

    def _encode(self, obj, context, path):
        if not isinstance(obj, str):
            return obj
        return obj.replace("*","a").replace("#","b")

# TS 51.011 Section 10.5.1
class EF_ADN(LinFixedEF):
    _test_de_encode = [
            ( '42204841203120536963FFFFFFFFFFFF06810628560810FFFFFFFFFFFFFF',
              { "alpha_id": "B HA 1 Sic", "len_of_bcd": 6, "ton_npi": { "ext": True, "type_of_number":
                                                                       "unknown", "numbering_plan_id":
                                                                       "isdn_e164" }, "dialing_nr":
               "6082658001", "cap_conf_id": 255, "ext1_record_id": 255 }),
            ( '4B756E64656E626574726575756E67FF0791947112122721ffffffffffff',
              {"alpha_id": "Kundenbetreuung", "len_of_bcd": 7, "ton_npi": {"ext": True, "type_of_number":
                                                                           "international",
                                                                           "numbering_plan_id": "isdn_e164"},
               "dialing_nr": "491721217212", "cap_conf_id": 255, "ext1_record_id": 255} )
        ]
    _test_no_pad = True

    def __init__(self, fid='6f3a', sfid=None, name='EF.ADN', desc='Abbreviated Dialing Numbers', ext=1, **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=(14, 30), **kwargs)
        ext_name = 'ext%u_record_id' % ext
        self._construct = Struct('alpha_id'/COptional(GsmOrUcs2Adapter(Rpad(Bytes(this._.total_len-14)))),
                                 'len_of_bcd'/Int8ub,
                                 'ton_npi'/TonNpi,
                                 'dialing_nr'/ExtendedBcdAdapter(BcdAdapter(Rpad(Bytes(10)))),
                                 'cap_conf_id'/Int8ub,
                                 ext_name/Int8ub)

# TS 51.011 Section 10.5.5
class EF_SMS(LinFixedEF):
    def __init__(self, fid='6f3c', sfid=None, name='EF.SMS', desc='Short messages', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=(176, 176), **kwargs)

    def _decode_record_bin(self, raw_bin_data, **kwargs):
        def decode_status(status):
            if status & 0x01 == 0x00:
                return (None, 'free_space')
            elif status & 0x07 == 0x01:
                return ('mt', 'message_read')
            elif status & 0x07 == 0x03:
                return ('mt', 'message_to_be_read')
            elif status & 0x07 == 0x07:
                return ('mo', 'message_to_be_sent')
            elif status & 0x1f == 0x05:
                return ('mo', 'sent_status_not_requested')
            elif status & 0x1f == 0x0d:
                return ('mo', 'sent_status_req_but_not_received')
            elif status & 0x1f == 0x15:
                return ('mo', 'sent_status_req_rx_not_stored_smsr')
            elif status & 0x1f == 0x1d:
                return ('mo', 'sent_status_req_rx_stored_smsr')
            else:
                return (None, 'rfu')

        status = decode_status(raw_bin_data[0])
        remainder = raw_bin_data[1:]
        return {'direction': status[0], 'status': status[1], 'remainder': b2h(remainder)}


# TS 51.011 Section 10.5.5
class EF_MSISDN(LinFixedEF):
    _test_de_encode = [
        ( 'ffffffffffffffffffffffffffffffffffffffff04b12143f5ffffffffffffffffff',
            {"alpha_id": "", "len_of_bcd": 4, "ton_npi": {"ext": True, "type_of_number": "network_specific",
                                                          "numbering_plan_id": "isdn_e164"},
             "dialing_nr": "12345f"}),
        ( '456967656e65205275666e756d6d6572ffffffff0891947172199181f3ffffffffff',
            {"alpha_id": "Eigene Rufnummer", "len_of_bcd": 8, "ton_npi": {"ext": True, "type_of_number": "international",
                                                                          "numbering_plan_id": "isdn_e164"},
             "dialing_nr": "4917279119183f"}),
    ]

    # Ensure deprecated representations still work
    _test_encode = [
        ( 'ffffffffffffffffffffffffffffffffffffffff05b1716662f6ffffffffffffffff',
            {"msisdn": [ 1, 3, "1766266"]}),
        ( 'ffffffffffffffffffffffffffffffffffffffff06b121436587f9ffffffffffffff',
            {"msisdn": "123456789"}),
    ]

    _test_no_pad = True

    def __init__(self, fid='6f40', sfid=None, name='EF.MSISDN', desc='MSISDN', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=(15, 34), leftpad=True, **kwargs)
        self._construct = Struct('alpha_id'/COptional(GsmOrUcs2Adapter(Rpad(Bytes(this._.total_len-14)))),
                                 'len_of_bcd'/Int8ub,
                                 'ton_npi'/TonNpi,
                                 'dialing_nr'/ExtendedBcdAdapter(BcdAdapter(Rpad(Bytes(10)))),
                                  Padding(2, pattern=b'\xff'))

    # Maintain compatibility with deprecated representations
    def encode_record_hex(self, abstract_data: dict, record_nr: int, total_len: int = None) -> str:
        if 'msisdn' in abstract_data:
            msisdn = abstract_data['msisdn']
            if type(msisdn) == str:
                npi = 'isdn_e164'
                ton = 'network_specific'
                dialing_nr = msisdn + len(msisdn) % 2 * "f"
            else:
                npi = msisdn[0]
                ton = msisdn[1]
                dialing_nr = msisdn[2] + len(msisdn[2]) % 2 * "f"
            abstract_data = {'alpha_id' : "",
                             'len_of_bcd' : len(dialing_nr) // 2 + 1,
                             'ton_npi' : {'ext' : True,
                                          'type_of_number' : ton,
                                          'numbering_plan_id' : npi},
                             'dialing_nr' : dialing_nr}
        return super().encode_record_hex(abstract_data, record_nr, total_len)

# TS 51.011 Section 10.5.6
class EF_SMSP(LinFixedEF):
    # FIXME: re-encode fails / missing alpha_id at start of output
    _test_decode = [
        ( '454e6574776f726b73fffffffffffffff1ffffffffffffffffffffffffffffffffffffffffffffffff0000a7',
          { "alpha_id": "ENetworks", "parameter_indicators": { "tp_dest_addr": False, "tp_sc_addr": True,
                                                               "tp_pid": True, "tp_dcs": True, "tp_vp": True },
            "tp_dest_addr": { "length": 255, "ton_npi": { "ext": True, "type_of_number": "reserved_for_extension",
                                                          "numbering_plan_id": "reserved_for_extension" },
                              "call_number": "" },
            "tp_sc_addr": { "length": 255, "ton_npi": { "ext": True, "type_of_number": "reserved_for_extension",
                                                        "numbering_plan_id": "reserved_for_extension" },
                            "call_number": "" },
            "tp_pid": "00", "tp_dcs": "00", "tp_vp_minutes": 1440 } ),
    ]
    _test_no_pad = True
    class ValidityPeriodAdapter(Adapter):
        def _decode(self, obj, context, path):
            if obj <= 143:
                return obj + 1 * 5
            elif obj <= 167:
                return 12 * 60 + ((obj - 143) * 30)
            elif obj <= 196:
                return (obj - 166) * (24 * 60)
            elif obj <= 255:
                return (obj - 192) * (7 * 24 * 60)
            else:
                raise ValueError
        def _encode(self, obj, context, path):
            if obj <= 12*60:
                return obj/5 - 1
            elif obj <= 24*60:
                return 143 + ((obj - (12 * 60)) // 30)
            elif obj <= 30 * 24 * 60:
                return 166 + (obj / (24 * 60))
            elif obj <= 63 * 7 * 24 * 60:
                return 192 + (obj // (7 * 24 * 60))
            else:
                raise ValueError

    def __init__(self, fid='6f42', sfid=None, name='EF.SMSP', desc='Short message service parameters', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=(28, None), **kwargs)
        ScAddr = Struct('length'/Int8ub, 'ton_npi'/TonNpi, 'call_number'/BcdAdapter(Rpad(Bytes(10))))
        self._construct = Struct('alpha_id'/COptional(GsmStringAdapter(Rpad(Bytes(this._.total_len-28)))),
                                 'parameter_indicators'/InvertAdapter(FlagsEnum(Byte, tp_dest_addr=1, tp_sc_addr=2,
                                                                                tp_pid=3, tp_dcs=4, tp_vp=5)),
                                 'tp_dest_addr'/ScAddr,
                                 'tp_sc_addr'/ScAddr,

                                 'tp_pid'/HexAdapter(Bytes(1)),
                                 'tp_dcs'/HexAdapter(Bytes(1)),
                                 'tp_vp_minutes'/EF_SMSP.ValidityPeriodAdapter(Byte))

# TS 51.011 Section 10.5.7
class EF_SMSS(TransparentEF):
    class MemCapAdapter(Adapter):
        def _decode(self, obj, context, path):
            return False if obj & 1 else True

        def _encode(self, obj, context, path):
            return 0 if obj else 1

    def __init__(self, fid='6f43', sfid=None, name='EF.SMSS', desc='SMS status', size=(2, 8), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct(
            'last_used_tpmr'/Int8ub, 'memory_capacity_exceeded'/self.MemCapAdapter(Int8ub))

# TS 51.011 Section 10.5.8
class EF_SMSR(LinFixedEF):
    def __init__(self, fid='6f47', sfid=None, name='EF.SMSR', desc='SMS status reports', rec_len=(30, 30), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct(
            'sms_record_id'/Int8ub, 'sms_status_report'/HexAdapter(Bytes(29)))


class EF_EXT(LinFixedEF):
    def __init__(self, fid, sfid=None, name='EF.EXT', desc='Extension', rec_len=(13, 13), **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct(
            'record_type'/Int8ub, 'extension_data'/HexAdapter(Bytes(11)), 'identifier'/Int8ub)

# TS 51.011 Section 10.5.16
class EF_CMI(LinFixedEF):
    def __init__(self, fid='6f58', sfid=None, name='EF.CMI', rec_len=(2, 21),
                 desc='Comparison Method Information', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct(
            'alpha_id'/GsmStringAdapter(Rpad(Bytes(this._.total_len-1))), 'comparison_method_id'/Int8ub)


class DF_TELECOM(CardDF):
    def __init__(self, fid='7f10', name='DF.TELECOM', desc=None, **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, **kwargs)
        files = [
            EF_ADN(),
            EF_ADN(fid='6f3b', name='EF.FDN', desc='Fixed dialling numbers', ext=2),
            EF_SMS(),
            LinFixedEF(fid='6f3d', name='EF.CCP',
                       desc='Capability Configuration Parameters', rec_len=(14, 14)),
            LinFixedEF(fid='6f4f', name='EF.ECCP',
                       desc='Extended Capability Configuration Parameters', rec_len=(15, 32)),
            EF_MSISDN(),
            EF_SMSP(),
            EF_SMSS(),
            EF_ADN('6f44', None, 'EF.LND', 'Last Number Dialled', ext=1),
            EF_ADN('6f49', None, 'EF.SDN', 'Service Dialling Numbers', ext=3),
            EF_EXT('6f4a', None, 'EF.EXT1', 'Extension1 (ADN/SSC)'),
            EF_EXT('6f4b', None, 'EF.EXT2', 'Extension2 (FDN/SSC)'),
            EF_EXT('6f4c', None, 'EF.EXT3', 'Extension3 (SDN)'),
            EF_ADN(fid='6f4d', name='EF.BDN', desc='Barred Dialling Numbers'),
            EF_EXT('6f4e', None, 'EF.EXT4', 'Extension4 (BDN/SSC)'),
            EF_SMSR(),
            EF_CMI(),
            # not really part of 51.011 but something that TS 31.102 specifies may exist here.
            DF_PHONEBOOK(),
            DF_MULTIMEDIA(),
            DF_MCS(),
            DF_V2X(),
        ]
        self.add_files(files)

######################################################################
# DF.GSM
######################################################################

# TS 51.011 Section 10.3.1
class EF_LP(TransRecEF):
    _test_de_encode = [
            ( "24", "24"),
        ]
    def __init__(self, fid='6f05', sfid=None, name='EF.LP', size=(1, None), rec_len=1,
                 desc='Language Preference'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)

    def _decode_record_bin(self, in_bin, **kwargs):
        return b2h(in_bin)

    def _encode_record_bin(self, in_json, **kwargs):
        return h2b(in_json)

# TS 51.011 Section 10.3.2
class EF_IMSI(TransparentEF):
    _test_de_encode = [
            ( "082982608200002080", { "imsi": "228062800000208" } ),
            ( "082926101160845740", { "imsi": "262011106487504" } ),
        ]
    def __init__(self, fid='6f07', sfid=None, name='EF.IMSI', desc='IMSI', size=(9, 9)):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [self.AddlShellCommands(self)]

    def _decode_hex(self, raw_hex):
        return {'imsi': dec_imsi(raw_hex)}

    def _encode_hex(self, abstract, **kwargs):
        return enc_imsi(abstract['imsi'])

    @with_default_category('File-Specific Commands')
    class AddlShellCommands(CommandSet):
        def __init__(self, ef: TransparentEF):
            super().__init__()
            self._ef = ef

        def do_update_imsi_plmn(self, arg: str):
            """Change the plmn part of the IMSI"""
            plmn = arg.strip()
            if len(plmn) == 5 or len(plmn) == 6:
                (data, sw) = self._cmd.lchan.read_binary_dec()
                if sw == '9000' and len(data['imsi'])-len(plmn) == 10:
                    imsi = data['imsi']
                    msin = imsi[len(plmn):]
                    (data, sw) = self._cmd.lchan.update_binary_dec(
                        {'imsi': plmn+msin})
                    if sw == '9000' and data:
                        self._cmd.poutput_json(
                            self._cmd.lchan.selected_file.decode_hex(data))
                else:
                    raise ValueError("PLMN length does not match IMSI length")
            else:
                raise ValueError("PLMN has wrong length!")


# TS 51.011 Section 10.3.4
class EF_PLMNsel(TransRecEF):
    _test_de_encode = [
            ( "22F860",  { "mcc": "228", "mnc": "06" } ),
            ( "330420",  { "mcc": "334", "mnc": "020" } ),
        ]
    def __init__(self, fid='6f30', sfid=None, name='EF.PLMNsel', desc='PLMN selector',
                 size=(24, None), rec_len=3, **kwargs):
        super().__init__(fid, name=name, sfid=sfid, desc=desc, size=size, rec_len=rec_len, **kwargs)

    def _decode_record_hex(self, in_hex, **kwargs):
        if in_hex[:6] == "ffffff":
            return None
        else:
            return dec_plmn(in_hex)

    def _encode_record_hex(self, in_json, **kwargs):
        if in_json == None:
            return "ffffff"
        else:
            return enc_plmn(in_json['mcc'], in_json['mnc'])

# TS 51.011 Section 10.3.6
class EF_ACMmax(TransparentEF):
    _test_de_encode = [
            ( "000000", { "acm_max": 0 } ),
        ]
    def __init__(self, fid='6f37', sfid=None, name='EF.ACMmax', size=(3, 3),
                 desc='ACM maximum value', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct('acm_max'/Int24ub)

# TS 51.011 Section 10.3.7
class EF_ServiceTable(TransparentEF):
    def __init__(self, fid, sfid, name, desc, size, table):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self.table = table
        self.shell_commands += [self.AddlShellCommands()]

    @staticmethod
    def _bit_byte_offset_for_service(service: int) -> Tuple[int, int]:
        i = service - 1
        byte_offset = i//4
        bit_offset = (i % 4) * 2
        return (byte_offset, bit_offset)

    def _decode_bin(self, raw_bin):
        ret = {}
        for i in range(0, len(raw_bin)*4):
            service_nr = i+1
            byte = int(raw_bin[i//4])
            bit_offset = (i % 4) * 2
            bits = (byte >> bit_offset) & 3
            ret[service_nr] = {
                'description': self.table[service_nr] if service_nr in self.table else None,
                'allocated': True if bits & 1 else False,
                'activated': True if bits & 2 else False,
            }
        return ret

    def _encode_bin(self, in_json, **kwargs):
        # compute the required binary size
        bin_len = 0
        for srv in in_json.keys():
            service_nr = int(srv)
            (byte_offset, bit_offset) = self._bit_byte_offset_for_service(service_nr)
            if byte_offset >= bin_len:
                bin_len = byte_offset+1
        # encode the actual data
        out = bytearray(b'\x00' * bin_len)
        for srv in in_json.keys():
            service_nr = int(srv)
            (byte_offset, bit_offset) = self._bit_byte_offset_for_service(service_nr)
            bits = 0
            if in_json[srv]['allocated'] == True:
                bits |= 1
            if in_json[srv]['activated'] == True:
                bits |= 2
            out[byte_offset] |= ((bits & 3) << bit_offset)
        return out

    @with_default_category('File-Specific Commands')
    class AddlShellCommands(CommandSet):
        def _adjust_service(self, service_nr: int, allocate: Optional[bool] = None, activate : Optional[bool] = None):
            (byte_offset, bit_offset) = EF_ServiceTable._bit_byte_offset_for_service(service_nr)
            hex_data, sw = self._cmd.lchan.read_binary(length=1, offset=byte_offset)
            data = h2b(hex_data)
            if allocate is not None:
                if allocate:
                    data[0] |= (1 << bit_offset)
                else:
                    data[0] &= ~(1 << bit_offset)
            if activate is not None:
                if activate:
                    data[0] |= (2 << bit_offset)
                else:
                    data[0] &= ~(2 << bit_offset)
            total_data, sw = self._cmd.lchan.update_binary(b2h(data), offset=byte_offset)
            return sw

        def do_sst_service_allocate(self, arg):
            """Allocate a service within EF.SST"""
            self._adjust_service(int(arg), allocate = True)

        def do_sst_service_deallocate(self, arg):
            """Deallocate a service within EF.SST"""
            self._adjust_service(int(arg), allocate = False)

        def do_sst_service_activate(self, arg):
            """Activate a service within EF.SST"""
            self._adjust_service(int(arg), activate = True)

        def do_sst_service_deactivate(self, arg):
            """Deactivate a service within EF.SST"""
            self._adjust_service(int(arg), activate = False)


# TS 51.011 Section 10.3.11
class EF_SPN(TransparentEF):
    _test_de_encode = [
            ( "0147534d2d52204348ffffffffffffffff",
              { "rfu": 0, "hide_in_oplmn": False, "show_in_hplmn": True, "spn": "GSM-R CH" } ),
        ]

    def __init__(self, fid='6f46', sfid=None, name='EF.SPN',
                 desc='Service Provider Name', size=(17, 17), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = BitStruct(
            # Byte 1
            'rfu'/BitsRFU(6),
            'hide_in_oplmn'/Flag,
            'show_in_hplmn'/Flag,
            # Bytes 2..17
            'spn'/Bytewise(GsmOrUcs2String(16))
        )

# TS 51.011 Section 10.3.13
class EF_CBMI(TransRecEF):
    # TODO: Test vectors
    def __init__(self, fid='6f45', sfid=None, name='EF.CBMI', size=(2, None), rec_len=2,
                 desc='Cell Broadcast message identifier selection', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
        self._construct = GreedyRange(Int16ub)

# TS 51.011 Section 10.3.15
class EF_ACC(TransparentEF):
    # example: acc_list(15) will produce a dict with only ACC15 being True
    # example: acc_list(2, 4) will produce a dict with ACC2 and ACC4 being True
    # example: acc_list() will produce a dict with all ACCs being False
    acc_list = lambda *active: {'ACC{}'.format(c) : c in active for c in range(16)}

    _test_de_encode = [
            ( "0000", acc_list() ),
            ( "0001", acc_list(0) ),
            ( "0002", acc_list(1) ),
            ( "0100", acc_list(8) ),
            ( "8000", acc_list(15) ),
            ( "802b", acc_list(0,1,3,5,15) ),
        ]
    def __init__(self, fid='6f78', sfid=None, name='EF.ACC',
                 desc='Access Control Class', size=(2, 2), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        # LSB of octet 2 is ACC=0 ... MSB of octet 1 is ACC=15
        flags = ['ACC{}'.format(c) / Flag for c in range(16)]
        self._construct = ByteSwapped(BitsSwapped(BitStruct(*flags)))

# TS 51.011 Section 10.3.16
class EF_LOCI(TransparentEF):
    _test_de_encode = [
            ( "7802570222f81009780000",
              { "tmsi": "78025702", "lai": "22f8100978", "tmsi_time": 0, "lu_status": "updated" } ),
        ]
    def __init__(self, fid='6f7e', sfid=None, name='EF.LOCI', desc='Location Information', size=(11, 11)):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('tmsi'/HexAdapter(Bytes(4)), 'lai'/HexAdapter(Bytes(5)), 'tmsi_time'/Int8ub,
                                 'lu_status'/Enum(Byte, updated=0, not_updated=1, plmn_not_allowed=2,
                                                  location_area_not_allowed=3))

# TS 51.011 Section 10.3.18
class EF_AD(TransparentEF):
    _test_de_encode = [
            ( "00ffff",
              { "ms_operation_mode": "normal", "rfu1": 255, "rfu2": 127, "ofm": True, "extensions": None } ),
        ]
    _test_no_pad = True

    class OP_MODE(enum.IntEnum):
        normal = 0x00
        type_approval = 0x80
        normal_and_specific_facilities = 0x01
        type_approval_and_specific_facilities = 0x81
        maintenance_off_line = 0x02
        cell_test = 0x04
    #OP_MODE_DICT = {int(v) : str(v) for v in EF_AD.OP_MODE}
    #OP_MODE_DICT_REVERSED = {str(v) : int(v) for v in EF_AD.OP_MODE}

    def __init__(self, fid='6fad', sfid=None, name='EF.AD', desc='Administrative Data', size=(3, 4)):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = BitStruct(
            # Byte 1
            'ms_operation_mode'/Bytewise(Enum(Byte, EF_AD.OP_MODE)),
            # Byte 2
            'rfu1'/Bytewise(ByteRFU),
            # Byte 3
            'rfu2'/BitsRFU(7),
            'ofm'/Flag,
            # Byte 4 (optional),
            'extensions'/COptional(Struct(
                'rfu3'/BitsRFU(4),
                'mnc_len'/BitsInteger(4),
                # Byte 5..N-4 (optional, RFU)
                'extensions'/Bytewise(GreedyBytesRFU)
            ))
        )

# TS 51.011 Section 10.3.20 / 10.3.22
class EF_VGCS(TransRecEF):
    _test_de_encode = [
            ( "92f9ffff", "299fffff" ),
        ]
    def __init__(self, fid='6fb1', sfid=None, name='EF.VGCS', size=(4, 200), rec_len=4,
                 desc='Voice Group Call Service', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
        self._construct = BcdAdapter(Bytes(4))

# TS 51.011 Section 10.3.21 / 10.3.23
class EF_VGCSS(TransparentEF):
    _test_decode = [
        ( "010000004540fc",
          { "flags": [ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0 ] }
        ),
    ]
    def __init__(self, fid='6fb2', sfid=None, name='EF.VGCSS', size=(7, 7),
                 desc='Voice Group Call Service Status', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = BitsSwapped(BitStruct(
            'flags'/Bit[50], Padding(6, pattern=b'\xff')))

# TS 51.011 Section 10.3.24
class EF_eMLPP(TransparentEF):
    _test_de_encode = [
        ( "7c04", { "levels": { "A": False, "B": False, "zero": True, "one": True,
                                "two": True, "three": True, "four": True },
                    "fast_call_setup_cond": { "A": False, "B": False, "zero": True, "one": False,
                                              "two": False, "three": False, "four": False }
                  }),
    ]
    def __init__(self, fid='6fb5', sfid=None, name='EF.eMLPP', size=(2, 2),
                 desc='enhanced Multi Level Pre-emption and Priority', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        FlagsConstruct = FlagsEnum(
            Byte, A=1, B=2, zero=4, one=8, two=16, three=32, four=64)
        self._construct = Struct(
            'levels'/FlagsConstruct, 'fast_call_setup_cond'/FlagsConstruct)

# TS 51.011 Section 10.3.25
class EF_AAeM(TransparentEF):
    _test_de_encode = [
        ( "3c", { "auto_answer_prio_levels": { "A": False, "B": False, "zero": True, "one": True,
                                               "two": True, "three": True, "four": False } } ),
    ]
    def __init__(self, fid='6fb6', sfid=None, name='EF.AAeM', size=(1, 1),
                 desc='Automatic Answer for eMLPP Service', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        FlagsConstruct = FlagsEnum(
            Byte, A=1, B=2, zero=4, one=8, two=16, three=32, four=64)
        self._construct = Struct('auto_answer_prio_levels'/FlagsConstruct)

# TS 51.011 Section 10.3.26
class EF_CBMID(EF_CBMI):
    def __init__(self, fid='6f48', sfid=None, name='EF.CBMID', size=(2, None), rec_len=2,
                 desc='Cell Broadcast Message Identifier for Data Download', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
        self._construct = GreedyRange(Int16ub)

# TS 51.011 Section 10.3.27
class EF_ECC(TransRecEF):
    def __init__(self, fid='6fb7', sfid=None, name='EF.ECC', size=(3, 15), rec_len=3,
                 desc='Emergency Call Codes', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
        self._construct = GreedyRange(BcdAdapter(Bytes(3)))

# TS 51.011 Section 10.3.28
class EF_CBMIR(TransRecEF):
    def __init__(self, fid='6f50', sfid=None, name='EF.CBMIR', size=(4, None), rec_len=4,
                 desc='Cell Broadcast message identifier range selection', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
        self._construct = GreedyRange(Struct('lower'/Int16ub, 'upper'/Int16ub))

# TS 51.011 Section 10.3.29
class EF_DCK(TransparentEF):
    def __init__(self, fid='6f2c', sfid=None, name='EF.DCK', size=(16, 16),
                 desc='Depersonalisation Control Keys', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct('network'/BcdAdapter(Bytes(4)),
                                 'network_subset'/BcdAdapter(Bytes(4)),
                                 'service_provider'/BcdAdapter(Bytes(4)),
                                 'corporate'/BcdAdapter(Bytes(4)))
# TS 51.011 Section 10.3.30
class EF_CNL(TransRecEF):
    def __init__(self, fid='6f32', sfid=None, name='EF.CNL', size=(6, None), rec_len=6,
                 desc='Co-operative Network List', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)

    def _decode_record_hex(self, in_hex, **kwargs):
        (in_plmn, sub, svp, corp) = unpack('!3sBBB', h2b(in_hex))
        res = dec_plmn(b2h(in_plmn))
        res['network_subset'] = sub
        res['service_provider_id'] = svp
        res['corporate_id'] = corp
        return res

    def _encode_record_hex(self, in_json, **kwargs):
        plmn = enc_plmn(in_json['mcc'], in_json['mnc'])
        return b2h(pack('!3sBBB',
                        h2b(plmn),
                        in_json['network_subset'],
                        in_json['service_provider_id'],
                        in_json['corporate_id']))

# TS 51.011 Section 10.3.31
class EF_NIA(LinFixedEF):
    def __init__(self, fid='6f51', sfid=None, name='EF.NIA', rec_len=(1, 32),
                 desc='Network\'s Indication of Alerting', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct(
            'alerting_category'/Int8ub, 'category'/GreedyBytes)

# TS 51.011 Section 10.3.32
class EF_Kc(TransparentEF):
    _test_de_encode = [
        ( "837d783609a3858f05", { "kc": "837d783609a3858f", "cksn": 5 } ),
    ]
    def __init__(self, fid='6f20', sfid=None, name='EF.Kc', desc='Ciphering key Kc', size=(9, 9), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct('kc'/HexAdapter(Bytes(8)), 'cksn'/Int8ub)

# TS 51.011 Section 10.3.33
class EF_LOCIGPRS(TransparentEF):
    _test_de_encode = [
        ( "ffffffffffffff22f8990000ff01",
          { "ptmsi": "ffffffff", "ptmsi_sig": "ffffff", "rai": "22f8990000ff", "rau_status": "not_updated" } ),
    ]
    def __init__(self, fid='6f53', sfid=None, name='EF.LOCIGPRS', desc='GPRS Location Information', size=(14, 14)):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('ptmsi'/HexAdapter(Bytes(4)), 'ptmsi_sig'/HexAdapter(Bytes(3)),
                                 'rai'/HexAdapter(Bytes(6)),
                                 'rau_status'/Enum(Byte, updated=0, not_updated=1, plmn_not_allowed=2,
                                                   routing_area_not_allowed=3))

# TS 51.011 Section 10.3.35..37
class EF_xPLMNwAcT(TransRecEF):
    _test_de_encode = [
        ( '62F2104000', { "mcc": "262", "mnc": "01", "act": [ "E-UTRAN NB-S1", "E-UTRAN WB-S1" ] } ),
        ( '62F2108000', { "mcc": "262", "mnc": "01", "act": [ "UTRAN" ] } ),
        ( '62F220488C', { "mcc": "262", "mnc": "02", "act": ['E-UTRAN NB-S1', 'E-UTRAN WB-S1', 'EC-GSM-IoT', 'GSM', 'NG-RAN'] } ),
    ]
    def __init__(self, fid='1234', sfid=None, name=None, desc=None, size=(40, None), rec_len=5, **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)

    def _decode_record_hex(self, in_hex, **kwargs):
        if in_hex[:6] == "ffffff":
            return None
        else:
            return dec_xplmn_w_act(in_hex)

    def _encode_record_hex(self, in_json, **kwargs):
        if in_json == None:
            return "ffffff0000"
        else:
            hplmn = enc_plmn(in_json['mcc'], in_json['mnc'])
            act = self.enc_act(in_json['act'])
            return hplmn + act

    @staticmethod
    def enc_act(in_list):
        u16 = 0
        # first the simple ones
        if 'UTRAN' in in_list:
            u16 |= 0x8000
        if 'NG-RAN' in in_list:
            u16 |= 0x0800
        if 'GSM COMPACT' in in_list:
            u16 |= 0x0040
        if 'cdma2000 HRPD' in in_list:
            u16 |= 0x0020
        if 'cdma2000 1xRTT' in in_list:
            u16 |= 0x0010
        # E-UTRAN
        if 'E-UTRAN WB-S1' in in_list and 'E-UTRAN NB-S1' in in_list:
            u16 |= 0x4000
        elif 'E-UTRAN WB-S1' in in_list:
            u16 |= 0x6000
        elif 'E-UTRAN NB-S1' in in_list:
            u16 |= 0x5000
        # GSM mess
        if 'GSM' in in_list and 'EC-GSM-IoT' in in_list:
            u16 |= 0x008C
        elif 'GSM' in in_list:
            u16 |= 0x0084
        elif 'EC-GSM-IoT' in in_list:
            u16 |= 0x0088
        return '%04X' % (u16)

# TS 51.011 Section 10.3.38
class EF_CPBCCH(TransRecEF):
    def __init__(self, fid='6f63', sfid=None, name='EF.CPBCCH', size=(2, 14), rec_len=2,
                 desc='CPBCCH Information', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
        self._construct = Struct('cpbcch'/Int16ub)

# TS 51.011 Section 10.3.39
class EF_InvScan(TransparentEF):
    def __init__(self, fid='6f64', sfid=None, name='EF.InvScan', size=(1, 1),
                 desc='IOnvestigation Scan', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = FlagsEnum(
            Byte, in_limited_service_mode=1, after_successful_plmn_selection=2)

# TS 51.011 Section 10.3.46
class EF_CFIS(LinFixedEF):
    _test_de_encode = [
        ( '0100ffffffffffffffffffffffffffff',
          {"msp_number": 1, "cfu_indicator_status": { "voice": False, "fax": False, "data": False, "rfu": 0 },
                                                      "len_of_bcd": 255, "ton_npi": {"ext": True,
                                                                                     "type_of_number": "reserved_for_extension",
                                                                                     "numbering_plan_id": "reserved_for_extension"},
                                                      "dialing_nr": "", "cap_conf_id": 255, "ext7_record_id": 255} ),
    ]
    def __init__(self, fid='6fcb', sfid=None, name='EF.CFIS', desc='Call Forwarding Indication Status', ext=7, **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=(16, 30), **kwargs)
        ext_name = 'ext%u_record_id' % ext
        self._construct = Struct('msp_number'/Int8ub,
                                 'cfu_indicator_status'/BitStruct('voice'/Flag, 'fax'/Flag, 'data'/Flag, 'rfu'/BitsRFU(5)),
                                 'len_of_bcd'/Int8ub,
                                 'ton_npi'/TonNpi,
                                 'dialing_nr'/ExtendedBcdAdapter(BcdAdapter(Rpad(Bytes(10)))),
                                 'cap_conf_id'/Int8ub,
                                 ext_name/Int8ub)

# TS 51.011 Section 4.2.58
class EF_PNN(LinFixedEF):
    # TODO: 430a82d432bbbc7eb75de432450a82d432bbbc7eb75de432ffffffff
    # TODO: 430a82c596b34cbfbfe5eb39ffffffffffffffffffffffffffffffffffff
    class FullNameForNetwork(BER_TLV_IE, tag=0x43):
        # TS 24.008 10.5.3.5a
        # TODO: proper decode
        _construct = HexAdapter(GreedyBytes)

    class ShortNameForNetwork(BER_TLV_IE, tag=0x45):
        # TS 24.008 10.5.3.5a
        # TODO: proper decode
        _construct = HexAdapter(GreedyBytes)

    class NetworkNameCollection(TLV_IE_Collection, nested=[FullNameForNetwork, ShortNameForNetwork]):
        pass

    def __init__(self, fid='6fc5', sfid=None, name='EF.PNN', desc='PLMN Network Name', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_PNN.NetworkNameCollection

# TS 51.011 Section 10.3.42
class EF_OPL(LinFixedEF):
    _test_de_encode = [
        ( '62f2100000fffe01',
          { "lai": { "mcc_mnc": "262-01", "lac_min": "0000", "lac_max": "fffe" }, "pnn_record_id": 1 } ),
    ]
    def __init__(self, fid='6fc6', sfid=None, name='EF.OPL', rec_len=(8, 8), desc='Operator PLMN List', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct('lai'/Struct('mcc_mnc'/PlmnAdapter(Bytes(3)),
                                 'lac_min'/HexAdapter(Bytes(2)), 'lac_max'/HexAdapter(Bytes(2))), 'pnn_record_id'/Int8ub)

# TS 51.011 Section 10.3.44 + TS 31.102 4.2.62
class EF_MBI(LinFixedEF):
    _test_de_encode = [
        ( '0100000000',
          { "mbi_voicemail": 1, "mbi_fax": 0, "mbi_email": 0, "mbi_other": 0, "mbi_videocall": 0 } ),
    ]
    def __init__(self, fid='6fc9', sfid=None, name='EF.MBI', rec_len=(4, 5), desc='Mailbox Identifier', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct('mbi_voicemail'/Int8ub, 'mbi_fax'/Int8ub, 'mbi_email'/Int8ub,
                                 'mbi_other'/Int8ub, 'mbi_videocall'/COptional(Int8ub))

# TS 51.011 Section 10.3.45 + TS 31.102 4.2.63
class EF_MWIS(LinFixedEF):
    _test_de_encode = [
        ( '0000000000',
          {"mwi_status": {"voicemail": False, "fax": False, "email": False, "other": False, "videomail":
                          False}, "num_waiting_voicemail": 0, "num_waiting_fax": 0, "num_waiting_email": 0,
           "num_waiting_other": 0, "num_waiting_videomail": None} ),
    ]
    _test_no_pad = True

    def __init__(self, fid='6fca', sfid=None, name='EF.MWIS', rec_len=(5, 6),
                 desc='Message Waiting Indication Status', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct('mwi_status'/FlagsEnum(Byte, voicemail=1, fax=2, email=4, other=8, videomail=16),
                                 'num_waiting_voicemail'/Int8ub,
                                 'num_waiting_fax'/Int8ub, 'num_waiting_email'/Int8ub,
                                 'num_waiting_other'/Int8ub, 'num_waiting_videomail'/COptional(Int8ub))

# TS 51.011 Section 10.3.66
class EF_SPDI(TransparentEF):
    # TODO: a305800337f800ffffffffffffffffffffffffffffffffffffffffffffff
    class ServiceProviderPLMN(BER_TLV_IE, tag=0x80):
        # flexible numbers of 3-byte PLMN records
        _construct = GreedyRange(PlmnAdapter(Bytes(3)))

    class SPDI(BER_TLV_IE, tag=0xA3, nested=[ServiceProviderPLMN]):
        pass
    def __init__(self, fid='6fcd', sfid=None, name='EF.SPDI',
                 desc='Service Provider Display Information', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_SPDI.SPDI

# TS 51.011 Section 10.3.51
class EF_MMSN(LinFixedEF):
    def __init__(self, fid='6fce', sfid=None, name='EF.MMSN', rec_len=(4, 20), desc='MMS Notification', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct('mms_status'/HexAdapter(Bytes(2)), 'mms_implementation'/HexAdapter(Bytes(1)),
                                 'mms_notification'/HexAdapter(Bytes(this._.total_len-4)), 'ext_record_nr'/Byte)

# TS 51.011 Annex K.1
class MMS_Implementation(BER_TLV_IE, tag=0x80):
    _construct = FlagsEnum(Byte, WAP=1)

# TS 51.011 Section 10.3.53
class EF_MMSICP(TransparentEF):
    class MMS_Relay_Server(BER_TLV_IE, tag=0x81):
        # 3GPP TS 23.140
        pass

    class Interface_to_CN(BER_TLV_IE, tag=0x82):
        # 3GPP TS 23.140
        pass

    class Gateway(BER_TLV_IE, tag=0x83):
        # Address, Type of address, Port, Service, AuthType, AuthId, AuthPass / 3GPP TS 23.140
        pass

    class MMS_ConnectivityParamters(TLV_IE_Collection,
                                    nested=[MMS_Implementation, MMS_Relay_Server, Interface_to_CN, Gateway]):
        pass
    def __init__(self, fid='6fd0', sfid=None, name='EF.MMSICP', size=(1, None),
                 desc='MMS Issuer Connectivity Parameters', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._tlv = EF_MMSICP.MMS_ConnectivityParamters

# TS 51.011 Section 10.3.54
class EF_MMSUP(LinFixedEF):
    class MMS_UserPref_ProfileName(BER_TLV_IE, tag=0x81):
        _construct = GsmOrUcs2Adapter(GreedyBytes)

    class MMS_UserPref_Info(BER_TLV_IE, tag=0x82):
        pass

    class MMS_User_Preferences(TLV_IE_Collection,
                               nested=[MMS_Implementation, MMS_UserPref_ProfileName, MMS_UserPref_Info]):
        pass
    def __init__(self, fid='6fd1', sfid=None, name='EF.MMSUP', rec_len=(1, None),
                 desc='MMS User Preferences', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._tlv = EF_MMSUP.MMS_User_Preferences

# TS 51.011 Section 10.3.55
class EF_MMSUCP(TransparentEF):
    def __init__(self, fid='6fd2', sfid=None, name='EF.MMSUCP', size=(1, None),
                 desc='MMS User Connectivity Parameters', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)


# TS 102 221 Section 13.2 / TS 31.101 Section 13 / TS 51.011 Section 10.1.1
class EF_ICCID(TransparentEF):
    _test_de_encode = [
        ( '988812010000400310f0', { "iccid": "8988211000000430010" } ),
    ]
    def __init__(self, fid='2fe2', sfid=0x02, name='EF.ICCID', desc='ICC Identification'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=(10, 10))

    def _decode_hex(self, raw_hex):
        return {'iccid': dec_iccid(raw_hex)}

    def _encode_hex(self, abstract, **kwargs):
        return enc_iccid(abstract['iccid'])

# TS 102 221 Section 13.3 / TS 31.101 Secction 13 / TS 51.011 Section 10.1.2
class EF_PL(TransRecEF):
    _test_de_encode = [
        ( '6465', "de" ),
        ( '656e', "en" ),
        ( 'ffff', None ),
    ]

    def __init__(self, fid='2f05', sfid=0x05, name='EF.PL', desc='Preferred Languages'):
        super().__init__(fid, sfid=sfid, name=name,
                         desc=desc, rec_len=2, size=(2, None))

    def _decode_record_bin(self, bin_data, **kwargs):
        if bin_data == b'\xff\xff':
            return None
        else:
            return bin_data.decode('ascii')

    def _encode_record_bin(self, in_json, **kwargs):
        if in_json is None:
            return b'\xff\xff'
        else:
            return in_json.encode('ascii')

class DF_GSM(CardDF):
    def __init__(self, fid='7f20', name='DF.GSM', desc='GSM Network related files'):
        super().__init__(fid=fid, name=name, desc=desc)
        self.shell_commands += [self.AddlShellCommands()]

        files = [
            EF_LP(),
            EF_IMSI(),
            EF_Kc(),
            EF_PLMNsel(),
            TransparentEF('6f31', None, 'EF.HPPLMN',
                          desc='Higher Priority PLMN search period'),
            EF_ACMmax(),
            EF_ServiceTable('6f38', None, 'EF.SST',
                            desc='SIM service table', table=EF_SST_map, size=(2, 16)),
            CyclicEF('6f39', None, 'EF.ACM',
                     desc='Accumulated call meter', rec_len=(3, 3)),
            TransparentEF('6f3e', None, 'EF.GID1', desc='Group Identifier Level 1'),
            TransparentEF('6f3f', None, 'EF.GID2', desc='Group Identifier Level 2'),
            EF_SPN(),
            TransparentEF('6f41', None, 'EF.PUCT',
                          desc='Price per unit and currency table', size=(5, 5)),
            EF_CBMI(),
            TransparentEF('6f74', None, 'EF.BCCH',
                          desc='Broadcast control channels', size=(16, 16)),
            EF_ACC(),
            EF_PLMNsel('6f7b', None, 'EF.FPLMN',
                       desc='Forbidden PLMNs', size=(12, 12)),
            EF_LOCI(),
            EF_AD(),
            TransparentEF('6fae', None, 'EF.Phase',
                          desc='Phase identification', size=(1, 1)),
            EF_VGCS(),
            EF_VGCSS(),
            EF_VGCS('6fb3', None, 'EF.VBS', desc='Voice Broadcast Service'),
            EF_VGCSS('6fb4', None, 'EF.VBSS',
                     desc='Voice Broadcast Service Status'),
            EF_eMLPP(),
            EF_AAeM(),
            EF_CBMID(),
            EF_ECC(),
            EF_CBMIR(),
            EF_DCK(),
            EF_CNL(),
            EF_NIA(),
            EF_Kc('6f52', None, 'EF.KcGPRS', desc='GPRS Ciphering key KcGPRS'),
            EF_LOCIGPRS(),
            TransparentEF('6f54', None, 'EF.SUME', desc='SetUpMenu Elements'),
            EF_xPLMNwAcT('6f60', None, 'EF.PLMNwAcT',
                         desc='User controlled PLMN Selector with Access Technology'),
            EF_xPLMNwAcT('6f61', None, 'EF.OPLMNwAcT',
                         desc='Operator controlled PLMN Selector with Access Technology'),
            EF_xPLMNwAcT('6f62', None, 'EF.HPLMNwAcT',
                         desc='HPLMN Selector with Access Technology'),
            EF_CPBCCH(),
            EF_InvScan(),
            EF_PNN(),
            EF_OPL(),
            EF_ADN('6fc7', None, 'EF.MBDN', desc='Mailbox Dialling Numbers'),
            EF_MBI(),
            EF_MWIS(),
            EF_CFIS(),
            EF_EXT('6fc8', None, 'EF.EXT6', desc='Externsion6 (MBDN)'),
            EF_EXT('6fcc', None, 'EF.EXT7', desc='Externsion7 (CFIS)'),
            EF_SPDI(),
            EF_MMSN(),
            EF_EXT('6fcf', None, 'EF.EXT8', desc='Extension8 (MMSN)'),
            EF_MMSICP(),
            EF_MMSUP(),
            EF_MMSUCP(),
        ]
        self.add_files(files)

    @with_default_category('Application-Specific Commands')
    class AddlShellCommands(CommandSet):
        def __init__(self):
            super().__init__()

        authenticate_parser = argparse.ArgumentParser()
        authenticate_parser.add_argument('RAND', type=is_hexstr, help='Random challenge')

        @cmd2.with_argparser(authenticate_parser)
        def do_authenticate(self, opts):
            """Perform GSM Authentication."""
            (data, sw) = self._cmd.lchan.scc.run_gsm(opts.RAND)
            self._cmd.poutput_json(data)


class CardProfileSIM(CardProfile):

    ORDER = 30

    def __init__(self):
        sw = {
            'Normal': {
                '9000': 'Normal ending of the command',
                '91xx': 'normal ending of the command, with extra information from the proactive SIM containing a command for the ME',
                '9exx': 'length XX of the response data given in case of a SIM data download error',
                '9fxx': 'length XX of the response data',
            },
            'Postponed processing': {
                '9300': 'SIM Application Toolkit is busy. Command cannot be executed at present, further normal commands are allowed',
            },
            'Memory management': {
                '920x': 'command successful but after using an internal update retry routine X times',
                '9240': 'memory problem',
            },
            'Referencing management': {
                '9400': 'no EF selected',
                '9402': 'out of range (invalid address)',
                '9404': 'file ID not found or pattern not found',
                '9408': 'file is inconsistent with the command',
            },
            'Security management': {
                '9802': 'no CHV initialized',
                '9804': 'access condition not fulfilled, unsuccessful CHV verification or authentication failed',
                '9808': 'in contradiction with CHV status',
                '9810': 'in contradiction with invalidation status',
                '9840': 'unsuccessful verification, CHV blocked, UNBLOCK CHV blocked',
                '9850': 'increase cannot be performed, Max value reached',
            },
            'Application independent errors': {
                '67xx': 'incorrect parameter P3',
                '6bxx': 'incorrect parameter P1 or P2',
                '6dxx': 'unknown instruction code given in the command',
                '6exx': 'wrong instruction class given in the command',
                '6fxx': 'technical problem with no diagnostic given',
            },
        }

        files = [
            EF_ICCID(),
            EF_PL(),
            DF_TELECOM(),
            DF_GSM(),
        ]

        addons = [
            AddonGSMR,
        ]

        super().__init__('SIM', desc='GSM SIM Card', cla="a0",
                         sel_ctrl="0000", files_in_mf=files, sw=sw, addons = addons)

    @staticmethod
    def decode_select_response(resp_hex: str) -> object:
        # we try to build something that resembles a dict resulting from the TLV decoder
        # of TS 102.221 (FcpTemplate), so that higher-level code only has to deal with one
        # format of SELECT response
        resp_bin = h2b(resp_hex)
        struct_of_file_map = {
            0: 'transparent',
            1: 'linear_fixed',
            3: 'cyclic'
        }
        type_of_file_map = {
            1: 'mf',
            2: 'df',
            4: 'working_ef'
        }
        ret = {
            'file_descriptor': {
                'file_descriptor_byte': {},
            },
            'proprietary_info': {},
        }
        ret['file_id'] = b2h(resp_bin[4:6])
        file_type = type_of_file_map[resp_bin[6]
                                     ] if resp_bin[6] in type_of_file_map else resp_bin[6]
        ret['file_descriptor']['file_descriptor_byte']['file_type'] = file_type
        if file_type in ['mf', 'df']:
            ret['proprietary_info']['available_memory'] = int.from_bytes(resp_bin[2:4], 'big')
            ret['file_characteristics'] = b2h(resp_bin[13:14])
            ret['num_direct_child_df'] = resp_bin[14]
            ret['num_direct_child_ef'] = resp_bin[15]
            ret['num_chv_unblock_adm_codes'] = int(resp_bin[16])
            # CHV / UNBLOCK CHV stats
        elif file_type in ['working_ef']:
            ret['file_size'] = int.from_bytes(resp_bin[2:4], 'big')
            file_struct = struct_of_file_map[resp_bin[13]
                                             ] if resp_bin[13] in struct_of_file_map else resp_bin[13]
            ret['file_descriptor']['file_descriptor_byte']['structure'] = file_struct
            if file_struct != 'transparent':
                record_len = resp_bin[14]
                ret['file_descriptor']['record_len'] = record_len
                ret['file_descriptor']['num_of_rec'] = ret['file_size'] // record_len
            ret['access_conditions'] = b2h(resp_bin[8:10])
            if resp_bin[11] & 0x01 == 0:
                ret['life_cycle_status_int'] = 'operational_activated'
            elif resp_bin[11] & 0x04:
                ret['life_cycle_status_int'] = 'operational_deactivated'
            else:
                ret['life_cycle_status_int'] = 'terminated'
        return ret

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        cls._mf_select_test(scc, "a0", "0000", ["3f00"])


class AddonSIM(CardProfileAddon):
    """An add-on that can be found on a UICC in order to support classic GSM SIM."""
    def __init__(self):
        files = [
            DF_GSM(),
            DF_TELECOM(),
        ]
        super().__init__('SIM', desc='GSM SIM', files_in_mf=files)

    def probe(self, card:'CardBase') -> bool:
        # we assume the add-on to be present in case DF.GSM is found on the card
        return card.file_exists(self.files_in_mf[0].fid)
