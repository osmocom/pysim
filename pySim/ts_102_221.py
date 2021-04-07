# coding=utf-8
"""Utilities / Functions related to ETSI TS 102 221, the core UICC spec.

(C) 2021 by Harald Welte <laforge@osmocom.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from pytlv.TLV import *
from struct import pack, unpack
from pySim.utils import *
from pySim.filesystem import *


FCP_TLV_MAP = {
    '82': 'file_descriptor',
    '83': 'file_identifier',
    '84': 'df_name',
    'A5': 'proprietary_info',
    '8A': 'life_cycle_status_int',
    '8B': 'security_attrib_ref_expanded',
    '8C': 'security_attrib_compact',
    'AB': 'security_attrib_espanded',
    'C6': 'pin_status_template_do',
    '80': 'file_size',
    '81': 'total_file_size',
    '88': 'short_file_id',
    }

# ETSI TS 102 221 11.1.1.4.6
FCP_Proprietary_TLV_MAP = {
    '80': 'uicc_characteristics',
    '81': 'application_power_consumption',
    '82': 'minimum_app_clock_freq',
    '83': 'available_memory',
    '84': 'file_details',
    '85': 'reserved_file_size',
    '86': 'maximum_file_size',
    '87': 'suported_system_commands',
    '88': 'specific_uicc_env_cond',
    '89': 'p2p_cat_secured_apdu',
    # Additional private TLV objects (bits b7 and b8 of the first byte of the tag set to '1')
    }

# ETSI TS 102 221 11.1.1.4.3
def interpret_file_descriptor(in_hex):
    in_bin = h2b(in_hex)
    out = {}
    ft_dict = {
        0: 'working_ef',
        1: 'internal_ef',
        7: 'df'
    }
    fs_dict = {
        0: 'no_info_given',
        1: 'transparent',
        2: 'linear_fixed',
        6: 'cyclic',
    }
    fdb = in_bin[0]
    ftype = (fdb >> 3) & 7
    fstruct = fdb & 7
    out['shareable'] = True if fdb & 0x40 else False
    out['file_type'] = ft_dict[ftype] if ftype in ft_dict else ftype
    out['structure'] = fs_dict[fstruct] if fstruct in fs_dict else fstruct
    if len(in_bin) >= 5:
        out['record_len'] = int.from_bytes(in_bin[2:4], 'big')
        out['num_of_rec'] = int.from_bytes(in_bin[4:5], 'big')
    return out

# ETSI TS 102 221 11.1.1.4.9
def interpret_life_cycle_sts_int(in_hex):
    lcsi = int(in_hex, 16)
    if lcsi == 0x00:
        return 'no_information'
    elif lcsi == 0x01:
        return 'creation'
    elif lcsi == 0x03:
        return 'initialization'
    elif lcsi & 0x05 == 0x05:
        return 'operational_activated'
    elif lcsi & 0x05 == 0x04:
        return 'operational_deactivated'
    elif lcsi & 0xc0 == 0xc0:
        return 'termination'
    else:
        return in_hex

# ETSI TS 102 221 11.1.1.4.10
FCP_Pin_Status_TLV_MAP = {
    '90': 'ps_do',
    '95': 'usage_qualifier',
    '83': 'key_reference',
    }

def interpret_ps_templ_do(in_hex):
    # cannot use the 'TLV' parser due to repeating tags
    #psdo_tlv = TLV(FCP_Pin_Status_TLV_MAP)
    #return psdo_tlv.parse(in_hex)
    return in_hex

# 'interpreter' functions for each tag
FCP_interpreter_map = {
    '80': lambda x: int(x, 16),
    '82': interpret_file_descriptor,
    '8A': interpret_life_cycle_sts_int,
    'C6': interpret_ps_templ_do,
    }

FCP_prorietary_interpreter_map = {
    '83': lambda x: int(x, 16),
    }

# pytlv unfortunately doesn't have a setting using which we can make it
# accept unknown tags.  It also doesn't raise a specific exception type but
# just the generic ValueError, so we cannot ignore those either.  Instead,
# we insert a dict entry for every possible proprietary tag permitted
def fixup_fcp_proprietary_tlv_map(tlv_map):
    if 'D0' in tlv_map:
        return
    for i in range(0xc0, 0xff):
        i_hex = i2h([i]).upper()
        tlv_map[i_hex] = 'proprietary_' + i_hex


def tlv_key_replace(inmap, indata):
    def newkey(inmap, key):
        if key in inmap:
            return inmap[key]
        else:
            return key
    return {newkey(inmap, d[0]): d[1] for d in indata.items()}

def tlv_val_interpret(inmap, indata):
    def newval(inmap, key, val):
        if key in inmap:
            return inmap[key](val)
        else:
            return val
    return {d[0]: newval(inmap, d[0], d[1]) for d in indata.items()}


# ETSI TS 102 221 Section 11.1.1.3
def decode_select_response(resp_hex):
    fixup_fcp_proprietary_tlv_map(FCP_Proprietary_TLV_MAP)
    resp_hex = resp_hex.upper()
    # outer layer
    fcp_base_tlv = TLV(['62'])
    fcp_base = fcp_base_tlv.parse(resp_hex)
    # actual FCP
    fcp_tlv = TLV(FCP_TLV_MAP)
    fcp = fcp_tlv.parse(fcp_base['62'])
    # further decode the proprietary information
    if fcp['A5']:
        prop_tlv = TLV(FCP_Proprietary_TLV_MAP)
        prop = prop_tlv.parse(fcp['A5'])
        fcp['A5'] = tlv_val_interpret(FCP_prorietary_interpreter_map, prop)
        fcp['A5'] = tlv_key_replace(FCP_Proprietary_TLV_MAP, fcp['A5'])
    # finally make sure we get human-readable keys in the output dict
    r = tlv_val_interpret(FCP_interpreter_map, fcp)
    return tlv_key_replace(FCP_TLV_MAP, r)


# TS 102 221 Section 13.1
class EF_DIR(LinFixedEF):
    def __init__(self, fid='2f00', sfid=0x1e, name='EF.DIR', desc='Application Directory'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={5,54})

    def _decode_record_hex(self, raw_hex_data):
        raw_hex_data = raw_hex_data.upper()
        atempl_base_tlv = TLV(['61'])
        atempl_base = atempl_base_tlv.parse(raw_hex_data)
        atempl_TLV_MAP = {'4F': 'aid_value', 50:'label'}
        atempl_tlv = TLV(atempl_TLV_MAP)
        atempl = atempl_tlv.parse(atempl_base['61'])
        # FIXME: "All other Dos are according to ISO/IEC 7816-4"
        return tlv_key_replace(atempl_TLV_MAP, atempl)

# TS 102 221 Section 13.2
class EF_ICCID(TransparentEF):
    def __init__(self, fid='2fe2', sfid=0x02, name='EF.ICCID', desc='ICC Identification'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size={10,10})

    def _decode_hex(self, raw_hex):
        return {'iccid': dec_iccid(raw_hex)}

    def _encode_hex(self, abstract):
        return enc_iccid(abstract['iccid'])

# TS 102 221 Section 13.3
class EF_PL(TransRecEF):
    def __init__(self, fid='2f05', sfid=0x05, name='EF.PL', desc='Preferred Languages'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=2, size={2,None})

# TS 102 221 Section 13.4
class EF_ARR(LinFixedEF):
    def __init__(self, fid='2f06', sfid=0x06, name='EF.ARR', desc='Access Rule Reference'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc)

# TS 102 221 Section 13.6
class EF_UMPC(TransparentEF):
    def __init__(self, fid='2f08', sfid=0x08, name='EF.UMPC', desc='UICC Maximum Power Consumption'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size={5,5})



class CardProfileUICC(CardProfile):
    def __init__(self):
        files = [
            EF_DIR(),
            EF_ICCID(),
            EF_PL(),
            EF_ARR(),
            # FIXME: DF.CD
            EF_UMPC(),
        ]
        sw = {
          'Normal': {
            '9000': 'Normal ending of the command',
            '91xx': 'Normal ending of the command, with extra information from the proactive UICC containing a command for the terminal',
            '92xx': 'Normal ending of the command, with extra information concerning an ongoing data transfer session',
            },
          'Postponed processing': {
            '9300': 'SIM Application Toolkit is busy. Command cannot be executed at present, further normal commands are allowed',
            },
          'Warnings': {
            '6200': 'No information given, state of non-volatile memory unchanged',
            '6281': 'Part of returned data may be corrupted',
            '6282': 'End of file/record reached before reading Le bytes or unsuccessful search',
            '6283': 'Selected file invalidated',
            '6284': 'Selected file in termination state',
            '62f1': 'More data available',
            '62f2': 'More data available and proactive command pending',
            '62f3': 'Response data available',
            '63f1': 'More data expected',
            '63f2': 'More data expected and proactive command pending',
            '63cx': 'Command successful but after using an internal update retry routine X times',
            },
          'Execution errors': {
            '6400': 'No information given, state of non-volatile memory unchanged',
            '6500': 'No information given, state of non-volatile memory changed',
            '6581': 'Memory problem',
            },
          'Checking errors': {
            '6700': 'Wrong length',
            '67xx': 'The interpretation of this status word is command dependent',
            '6b00': 'Wrong parameter(s) P1-P2',
            '6d00': 'Instruction code not supported or invalid',
            '6e00': 'Class not supported',
            '6f00': 'Technical problem, no precise diagnosis',
            '6fxx': 'The interpretation of this status word is command dependent',
            },
          'Functions in CLA not supported': {
            '6800': 'No information given',
            '6881': 'Logical channel not supported',
            '6882': 'Secure messaging not supported',
            },
          'Command not allowed': {
            '6900': 'No information given',
            '6981': 'Command incompatible with file structure',
            '6982': 'Security status not satisfied',
            '6983': 'Authentication/PIN method blocked',
            '6984': 'Referenced data invalidated',
            '6985': 'Conditions of use not satisfied',
            '6986': 'Command not allowed (no EF selected)',
            '6989': 'Command not allowed - secure channel - security not satisfied',
            },
          'Wrong parameters': {
            '6a80': 'Incorrect parameters in the data field',
            '6a81': 'Function not supported',
            '6a82': 'File not found',
            '6a83': 'Record not found',
            '6a84': 'Not enough memory space',
            '6a86': 'Incorrect parameters P1 to P2',
            '6a87': 'Lc inconsistent with P1 to P2',
            '6a88': 'Referenced data not found',
            },
          'Application errors': {
            '9850': 'INCREASE cannot be performed, max value reached',
            '9862': 'Authentication error, application specific',
            '9863': 'Security session or association expired',
            '9864': 'Minimum UICC suspension time is too long',
            },
          }

        super().__init__('UICC', desc='ETSI TS 102 221', files_in_mf=files, sw=sw)
