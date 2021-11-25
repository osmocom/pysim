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
from construct import *
from pySim.construct import *
from pySim.utils import *
from pySim.filesystem import *
from bidict import bidict
from pySim.profile import CardProfile
from pySim.profile import match_uicc
from pySim.profile import match_sim

# A UICC will usually also support 2G functionality. If this is the case, we
# need to add DF_GSM and DF_TELECOM along with the UICC related files
from pySim.ts_51_011 import DF_GSM, DF_TELECOM

ts_102_22x_cmdset = CardCommandSet('TS 102 22x', [
    # TS 102 221 Section 10.1.2 Table 10.5 "Coding of Instruction Byte"
    CardCommand('SELECT',                   0xA4, ['0X', '4X', '6X']),
    CardCommand('STATUS',                   0xF2, ['8X', 'CX', 'EX']),
    CardCommand('READ BINARY',              0xB0, ['0X', '4X', '6X']),
    CardCommand('UPDATE BINARY',            0xD6, ['0X', '4X', '6X']),
    CardCommand('READ RECORD',              0xB2, ['0X', '4X', '6X']),
    CardCommand('UPDATE RECORD',            0xDC, ['0X', '4X', '6X']),
    CardCommand('SEARCH RECORD',            0xA2, ['0X', '4X', '6X']),
    CardCommand('INCREASE',                 0x32, ['8X', 'CX', 'EX']),
    CardCommand('RETRIEVE DATA',            0xCB, ['8X', 'CX', 'EX']),
    CardCommand('SET DATA',                 0xDB, ['8X', 'CX', 'EX']),
    CardCommand('VERIFY PIN',               0x20, ['0X', '4X', '6X']),
    CardCommand('CHANGE PIN',               0x24, ['0X', '4X', '6X']),
    CardCommand('DISABLE PIN',              0x26, ['0X', '4X', '6X']),
    CardCommand('ENABLE PIN',               0x28, ['0X', '4X', '6X']),
    CardCommand('UNBLOCK PIN',              0x2C, ['0X', '4X', '6X']),
    CardCommand('DEACTIVATE FILE',          0x04, ['0X', '4X', '6X']),
    CardCommand('ACTIVATE FILE',            0x44, ['0X', '4X', '6X']),
    CardCommand('AUTHENTICATE',             0x88, ['0X', '4X', '6X']),
    CardCommand('AUTHENTICATE',             0x89, ['0X', '4X', '6X']),
    CardCommand('GET CHALLENGE',            0x84, ['0X', '4X', '6X']),
    CardCommand('TERMINAL CAPABILITY',      0xAA, ['8X', 'CX', 'EX']),
    CardCommand('TERMINAL PROFILE',         0x10, ['80']),
    CardCommand('ENVELOPE',                 0xC2, ['80']),
    CardCommand('FETCH',                    0x12, ['80']),
    CardCommand('TERMINAL RESPONSE',        0x14, ['80']),
    CardCommand('MANAGE CHANNEL',           0x70, ['0X', '4X', '6X']),
    CardCommand('MANAGE SECURE CHANNEL',    0x73, ['0X', '4X', '6X']),
    CardCommand('TRANSACT DATA',            0x75, ['0X', '4X', '6X']),
    CardCommand('SUSPEND UICC',             0x76, ['80']),
    CardCommand('GET IDENTITY',             0x78, ['8X', 'CX', 'EX']),
    CardCommand('EXCHANGE CAPABILITIES',    0x7A, ['80']),
    CardCommand('GET RESPONSE',             0xC0, ['0X', '4X', '6X']),
    # TS 102 222 Section 6.1 Table 1 "Coding of the commands"
    CardCommand('CREATE FILE',              0xE0, ['0X', '4X']),
    CardCommand('DELETE FILE',              0xE4, ['0X', '4X']),
    CardCommand('DEACTIVATE FILE',          0x04, ['0X', '4X']),
    CardCommand('ACTIVATE FILE',            0x44, ['0X', '4X']),
    CardCommand('TERMINATE DF',             0xE6, ['0X', '4X']),
    CardCommand('TERMINATE EF',             0xE8, ['0X', '4X']),
    CardCommand('TERMINATE CARD USAGE',     0xFE, ['0X', '4X']),
    CardCommand('RESIZE FILE',              0xD4, ['8X', 'CX']),
    ])


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
     0x39: 'ber_tlv',
    }
    fdb = in_bin[0]
    ftype = (fdb >> 3) & 7
    if fdb & 0xbf == 0x39:
        fstruct = 0x39
    else:
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
    # Other non-standard TLV objects found on some cards
    tlv_map['9B'] = 'target_ef' # for sysmoUSIM-SJS1


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

# ETSI TS 102 221 Section 9.2.7 + ISO7816-4 9.3.3/9.3.4

class _AM_DO_DF(DataObject):
    def __init__(self):
        super().__init__('access_mode', 'Access Mode', tag=0x80)

    def from_bytes(self, do:bytes):
        res = []
        if len(do) != 1:
            raise ValueError("We only support single-byte AMF inside AM-DO")
        amf = do[0]
        # tables 17..29 and 41..44 of 7816-4
        if amf & 0x80 == 0:
            if amf & 0x40:
                res.append('delete_file')
            if amf & 0x20:
                res.append('terminate_df')
            if amf & 0x10:
                res.append('activate_file')
            if amf & 0x08:
                res.append('deactivate_file')
        if amf & 0x04:
            res.append('create_file_df')
        if amf & 0x02:
            res.append('create_file_ef')
        if amf & 0x01:
            res.append('delete_file_child')
        self.decoded = res

    def to_bytes(self):
        val = 0
        if 'delete_file' in self.decoded:
            val |= 0x40
        if 'terminate_df' in self.decoded:
            val |= 0x20
        if 'activate_file' in self.decoded:
            val |= 0x10
        if 'deactivate_file' in self.decoded:
            val |= 0x08
        if 'create_file_df' in self.decoded:
            val |= 0x04
        if 'create_file_ef' in self.decoded:
            val |= 0x02
        if 'delete_file_child' in self.decoded:
            val |= 0x01
        return val.to_bytes(1, 'big')


class _AM_DO_EF(DataObject):
    """ISO7816-4 9.3.2 Table 18 + 9.3.3.1 Table 31"""
    def __init__(self):
        super().__init__('access_mode', 'Access Mode', tag=0x80)

    def from_bytes(self, do:bytes):
        res = []
        if len(do) != 1:
            raise ValueError("We only support single-byte AMF inside AM-DO")
        amf = do[0]
        # tables 17..29 and 41..44 of 7816-4
        if amf & 0x80 == 0:
            if amf & 0x40:
                res.append('delete_file')
            if amf & 0x20:
                res.append('terminate_ef')
            if amf & 0x10:
                res.append('activate_file_or_record')
            if amf & 0x08:
                res.append('deactivate_file_or_record')
        if amf & 0x04:
            res.append('write_append')
        if amf & 0x02:
            res.append('update_erase')
        if amf & 0x01:
            res.append('read_search_compare')
        self.decoded = res

    def to_bytes(self):
        val = 0
        if 'delete_file' in self.decoded:
            val |= 0x40
        if 'terminate_ef' in self.decoded:
            val |= 0x20
        if 'activate_file_or_record' in self.decoded:
            val |= 0x10
        if 'deactivate_file_or_record' in self.decoded:
            val |= 0x08
        if 'write_append' in self.decoded:
            val |= 0x04
        if 'update_erase' in self.decoded:
            val |= 0x02
        if 'read_search_compare' in self.decoded:
            val |= 0x01
        return val.to_bytes(1, 'big')

class _AM_DO_CHDR(DataObject):
    """Command Header Access Mode DO according to ISO 7816-4 Table 32."""
    def __init__(self, tag):
        super().__init__('command_header', 'Command Header Description', tag=tag)

    def from_bytes(self, do:bytes):
        res = {}
        i = 0
        if self.tag & 0x08:
            res['CLA'] = do[i]
            i += 1
        if self.tag & 0x04:
            res['INS'] = do[i]
            i += 1
        if self.tag & 0x02:
            res['P1'] = do[i]
            i += 1
        if self.tag & 0x01:
            res['P2'] = do[i]
            i += 1
        self.decoded = res

    def _compute_tag(self):
        """Override to encode the tag, as it depends on the value."""
        tag = 0x80
        if 'CLA' in self.decoded:
            tag |= 0x08
        if 'INS' in self.decoded:
            tag |= 0x04
        if 'P1' in self.decoded:
            tag |= 0x02
        if 'P2' in self.decoded:
            tag |= 0x01
        return tag

    def to_bytes(self):
        res = bytearray()
        if 'CLA' in self.decoded:
            res.append(self.decoded['CLA'])
        if 'INS' in self.decoded:
            res.append(self.decoded['INS'])
        if 'P1' in self.decoded:
            res.append(self.decoded['P1'])
        if 'P2' in self.decoded:
            res.append(self.decoded['P2'])
        return res

AM_DO_CHDR = DataObjectChoice('am_do_chdr', members=[
              _AM_DO_CHDR(0x81), _AM_DO_CHDR(0x82), _AM_DO_CHDR(0x83), _AM_DO_CHDR(0x84),
              _AM_DO_CHDR(0x85), _AM_DO_CHDR(0x86), _AM_DO_CHDR(0x87), _AM_DO_CHDR(0x88),
              _AM_DO_CHDR(0x89), _AM_DO_CHDR(0x8a), _AM_DO_CHDR(0x8b), _AM_DO_CHDR(0x8c),
              _AM_DO_CHDR(0x8d), _AM_DO_CHDR(0x8e), _AM_DO_CHDR(0x8f)])

AM_DO_DF = AM_DO_CHDR | _AM_DO_DF()
AM_DO_EF = AM_DO_CHDR | _AM_DO_EF()


# TS 102 221 Section 9.5.1 / Table 9.3
pin_names = bidict({
    0x01: 'PIN1',
    0x02: 'PIN2',
    0x03: 'PIN3',
    0x04: 'PIN4',
    0x05: 'PIN5',
    0x06: 'PIN6',
    0x07: 'PIN7',
    0x08: 'PIN8',
    0x0a: 'ADM1',
    0x0b: 'ADM2',
    0x0c: 'ADM3',
    0x0d: 'ADM4',
    0x0e: 'ADM5',

    0x11: 'UNIVERSAL_PIN',
    0x81: '2PIN1',
    0x82: '2PIN2',
    0x83: '2PIN3',
    0x84: '2PIN4',
    0x85: '2PIN5',
    0x86: '2PIN6',
    0x87: '2PIN7',
    0x88: '2PIN8',
    0x8a: 'ADM6',
    0x8b: 'ADM7',
    0x8c: 'ADM8',
    0x8d: 'ADM9',
    0x8e: 'ADM10',
    })

class CRT_DO(DataObject):
    """Control Reference Template as per TS 102 221 9.5.1"""
    def __init__(self):
        super().__init__('control_reference_template', 'Control Reference Template', tag=0xA4)

    def from_bytes(self, do: bytes):
        """Decode a Control Reference Template DO."""
        if len(do) != 6:
            raise ValueError('Unsupported CRT DO length: %s', do)
        if do[0] != 0x83 or do[1] != 0x01:
            raise ValueError('Unsupported Key Ref Tag or Len in CRT DO %s', do)
        if do[3:] != b'\x95\x01\x08':
            raise ValueError('Unsupported Usage Qualifier Tag or Len in CRT DO %s', do)
        self.encoded = do[0:6]
        self.decoded = pin_names[do[2]]
        return do[6:]

    def to_bytes(self):
        pin = pin_names.inverse[self.decoded]
        return b'\x83\x01' + pin.to_bytes(1, 'big') + b'\x95\x01\x08'

# ISO7816-4 9.3.3 Table 33
class SecCondByte_DO(DataObject):
    def __init__(self, tag=0x9d):
        super().__init__('security_condition_byte', tag=tag)

    def from_bytes(self, binary:bytes):
        if len(binary) != 1:
            raise ValueError
        inb = binary[0]
        if inb == 0:
            cond = 'always'
        if inb == 0xff:
            cond = 'never'
        res = []
        if inb & 0x80:
            cond = 'and'
        else:
            cond = 'or'
        if inb & 0x40:
            res.append('secure_messaging')
        if inb & 0x20:
            res.append('external_auth')
        if inb & 0x10:
            res.append('user_auth')
        rd = {'mode': cond }
        if len(res):
            rd['conditions'] = res
        self.decoded = rd

    def to_bytes(self):
        mode = self.decoded['mode']
        if mode == 'always':
            res = 0
        elif mode == 'never':
            res = 0xff
        else:
            res = 0
            if mode == 'and':
                res |= 0x80
            elif mode == 'or':
                pass
            else:
                raise ValueError('Unknown mode %s' % mode)
            for c in self.decoded['conditions']:
                if c == 'secure_messaging':
                    res |= 0x40
                elif c == 'external_auth':
                    res |= 0x20
                elif c == 'user_auth':
                    res |= 0x10
                else:
                    raise ValueError('Unknown condition %s' % c)
        return res.to_bytes(1, 'big')

Always_DO = TL0_DataObject('always', 'Always', 0x90)
Never_DO = TL0_DataObject('never', 'Never', 0x97)
SC_DO = DataObjectChoice('security_condition', 'Security Condition',
                         members=[Always_DO, Never_DO, SecCondByte_DO(), SecCondByte_DO(0x9e), CRT_DO()])

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
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [self.AddlShellCommands()]

    @staticmethod
    def flatten(inp:list):
        """Flatten the somewhat deep/complex/nested data returned from decoder."""
        def sc_abbreviate(sc):
            if 'always' in sc:
                return 'always'
            elif 'never' in sc:
                return 'never'
            elif 'control_reference_template' in sc:
                return sc['control_reference_template']
            else:
                return sc

        by_mode = {}
        for t in inp:
            am = t[0]
            sc = t[1]
            sc_abbr = sc_abbreviate(sc)
            if 'access_mode' in am:
                for m in am['access_mode']:
                    by_mode[m] = sc_abbr
            elif 'command_header' in am:
                ins = am['command_header']['INS']
                if 'CLA' in am['command_header']:
                    cla = am['command_header']['CLA']
                else:
                    cla = None
                cmd = ts_102_22x_cmdset.lookup(ins, cla)
                if cmd:
                    name = cmd.name.lower().replace(' ','_')
                    by_mode[name] = sc_abbr
                else:
                    raise ValueError
            else:
                raise ValueError
        return by_mode

    def _decode_record_bin(self, raw_bin_data):
        # we can only guess if we should decode for EF or DF here :(
        arr_seq = DataObjectSequence('arr', sequence = [AM_DO_EF, SC_DO])
        dec = arr_seq.decode_multi(raw_bin_data)
        # we cannot pass the result through flatten() here, as we don't have a related
        # 'un-flattening' decoder, and hence would be unable to encode :(
        return dec[0]

    @with_default_category('File-Specific Commands')
    class AddlShellCommands(CommandSet):
        def __init__(self):
            super().__init__()

        @cmd2.with_argparser(LinFixedEF.ShellCommands.read_rec_dec_parser)
        def do_read_arr_record(self, opts):
            """Read one EF.ARR record in flattened, human-friendly form."""
            (data, sw) = self._cmd.rs.read_record_dec(opts.record_nr)
            data = self._cmd.rs.selected_file.flatten(data)
            self._cmd.poutput_json(data, opts.oneline)

        @cmd2.with_argparser(LinFixedEF.ShellCommands.read_recs_dec_parser)
        def do_read_arr_records(self, opts):
            """Read + decode all EF.ARR records in flattened, human-friendly form."""
            num_of_rec = self._cmd.rs.selected_file_fcp['file_descriptor']['num_of_rec']
            # collect all results in list so they are rendered as JSON list when printing
            data_list = []
            for recnr in range(1, 1 + num_of_rec):
                (data, sw) = self._cmd.rs.read_record_dec(recnr)
                data = self._cmd.rs.selected_file.flatten(data)
                data_list.append(data)
            self._cmd.poutput_json(data_list, opts.oneline)


# TS 102 221 Section 13.6
class EF_UMPC(TransparentEF):
    def __init__(self, fid='2f08', sfid=0x08, name='EF.UMPC', desc='UICC Maximum Power Consumption'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size={5,5})
        addl_info = FlagsEnum(Byte, req_inc_idle_current=1, support_uicc_suspend=2)
        self._construct = Struct('max_current_mA'/Int8ub, 't_op_s'/Int8ub, 'addl_info'/addl_info)

class CardProfileUICC(CardProfile):

    ORDER = 1

    def __init__(self, name = 'UICC'):
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

        super().__init__(name, desc='ETSI TS 102 221', cla="00", sel_ctrl="0004", files_in_mf=files, sw=sw)

    @staticmethod
    def decode_select_response(resp_hex:str) -> object:
        """ETSI TS 102 221 Section 11.1.1.3"""
        fixup_fcp_proprietary_tlv_map(FCP_Proprietary_TLV_MAP)
        resp_hex = resp_hex.upper()
        # outer layer
        fcp_base_tlv = TLV(['62'])
        fcp_base = fcp_base_tlv.parse(resp_hex)
        # actual FCP
        fcp_tlv = TLV(FCP_TLV_MAP)
        fcp = fcp_tlv.parse(fcp_base['62'])
        # further decode the proprietary information
        if 'A5' in fcp:
            prop_tlv = TLV(FCP_Proprietary_TLV_MAP)
            prop = prop_tlv.parse(fcp['A5'])
            fcp['A5'] = tlv_val_interpret(FCP_prorietary_interpreter_map, prop)
            fcp['A5'] = tlv_key_replace(FCP_Proprietary_TLV_MAP, fcp['A5'])
        # finally make sure we get human-readable keys in the output dict
        r = tlv_val_interpret(FCP_interpreter_map, fcp)
        return tlv_key_replace(FCP_TLV_MAP, r)

    @staticmethod
    def match_with_card(scc:SimCardCommands) -> bool:
        return match_uicc(scc)

class CardProfileUICCSIM(CardProfileUICC):
    """Same as above, but including 2G SIM support"""

    ORDER = 0

    def __init__(self):
        super().__init__('UICC-SIM')

        # Add GSM specific files
        self.files_in_mf.append(DF_TELECOM())
        self.files_in_mf.append(DF_GSM())

    @staticmethod
    def match_with_card(scc:SimCardCommands) -> bool:
        return match_uicc(scc) and match_sim(scc)
