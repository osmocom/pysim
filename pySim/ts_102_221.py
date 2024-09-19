# coding=utf-8
"""Utilities / Functions related to ETSI TS 102 221, the core UICC spec.

(C) 2021-2024 by Harald Welte <laforge@osmocom.org>

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
from bidict import bidict

from construct import Select, Const, Bit, Struct, Int16ub, FlagsEnum, ValidationError
from construct import Optional as COptional, Computed

from osmocom.construct import *
from osmocom.utils import *
from osmocom.tlv import BER_TLV_IE, flatten_dict_lists
from pySim.utils import *

#from pySim.filesystem import *
#from pySim.profile import CardProfile

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


# ETSI TS 102 221 6.2.1
SupplyVoltageClasses = FlagsEnum(Int8ub, a=0x1, b=0x2, c=0x4, d=0x8, e=0x10)

# ETSI TS 102 221 11.1.1.4.2
class FileSize(BER_TLV_IE, tag=0x80):
    _construct = GreedyInteger(minlen=2)

# ETSI TS 102 221 11.1.1.4.2
class TotalFileSize(BER_TLV_IE, tag=0x81):
    _construct = GreedyInteger(minlen=2)

# ETSI TS 102 221 11.1.1.4.3
class FileDescriptor(BER_TLV_IE, tag=0x82):
    _test_de_encode = [
        ( '82027921', { "file_descriptor_byte": { "shareable": True, "file_type": "working_ef", "structure": "ber_tlv" }, "record_len": None, "num_of_rec": None } ),
        ( '82027821', { "file_descriptor_byte": { "shareable": True, "file_type": "df", "structure": "no_info_given" }, "record_len": None, "num_of_rec": None }),
        ( '82024121', { "file_descriptor_byte": { "shareable": True, "file_type": "working_ef", "structure": "transparent" }, "record_len": None, "num_of_rec": None } ),
        ( '82054221006e05', { "file_descriptor_byte": { "shareable": True, "file_type": "working_ef", "structure": "linear_fixed" }, "record_len": 110, "num_of_rec": 5 } ),
    ]
    class BerTlvAdapter(Adapter):
        def _decode(self, obj, context, path):
            if obj == 0x39:
                return 'ber_tlv'
            raise ValidationError
        def _encode(self, obj, context, path):
            if obj == 'ber_tlv':
                return 0x39
            raise ValidationError

    FDB = Select(BitStruct(Const(0, Bit), 'shareable'/Flag, 'structure'/BerTlvAdapter(Const(0x39, BitsInteger(6))), 'file_type'/Computed('working_ef')),
                 BitStruct(Const(0, Bit), 'shareable'/Flag, 'file_type'/Enum(BitsInteger(3), working_ef=0, internal_ef=1, df=7),
                           'structure'/Enum(BitsInteger(3), no_info_given=0, transparent=1, linear_fixed=2, cyclic=6))
                )
    _construct = Struct('file_descriptor_byte'/FDB, Const(b'\x21'),
                        'record_len'/COptional(Int16ub), 'num_of_rec'/COptional(Int8ub))

# ETSI TS 102 221 11.1.1.4.4
class FileIdentifier(BER_TLV_IE, tag=0x83):
    _construct = HexAdapter(GreedyBytes)

# ETSI TS 102 221 11.1.1.4.5
class DfName(BER_TLV_IE, tag=0x84):
    _construct = HexAdapter(GreedyBytes)

# ETSI TS 102 221 11.1.1.4.6.1
class UiccCharacteristics(BER_TLV_IE, tag=0x80):
    _construct = GreedyBytes

# ETSI TS 102 221 11.1.1.4.6.2
class ApplicationPowerConsumption(BER_TLV_IE, tag=0x81):
    _construct = Struct('voltage_class'/SupplyVoltageClasses,
                        'power_consumption_ma'/Int8ub,
                        'reference_freq_100k'/Int8ub)

# ETSI TS 102 221 11.1.1.4.6.3
class MinApplicationClockFrequency(BER_TLV_IE, tag=0x82):
    _construct = Int8ub

# ETSI TS 102 221 11.1.1.4.6.4
class AvailableMemory(BER_TLV_IE, tag=0x83):
    _construct = GreedyInteger()

# ETSI TS 102 221 11.1.1.4.6.5
class FileDetails(BER_TLV_IE, tag=0x84):
    _construct = FlagsEnum(Byte, der_coding_only=1)

# ETSI TS 102 221 11.1.1.4.6.6
class ReservedFileSize(BER_TLV_IE, tag=0x85):
    _construct = GreedyInteger()

# ETSI TS 102 221 11.1.1.4.6.7
class MaximumFileSize(BER_TLV_IE, tag=0x86):
    _construct = GreedyInteger()

# ETSI TS 102 221 11.1.1.4.6.8
class SupportedFilesystemCommands(BER_TLV_IE, tag=0x87):
    _construct = FlagsEnum(Byte, terminal_capability=1)

# ETSI TS 102 221 11.1.1.4.6.9
class SpecificUiccEnvironmentConditions(BER_TLV_IE, tag=0x88):
    _construct = BitStruct('rfu'/BitsRFU(4),
                           'high_humidity_supported'/Flag,
                           'temperature_class'/Enum(BitsInteger(3), standard=0, class_A=1, class_B=2, class_C=3))

# ETSI TS 102 221 11.1.1.4.6.10
class Platform2PlatformCatSecuredApdu(BER_TLV_IE, tag=0x89):
    _construct = GreedyBytes

# TS 102 222 Table 4a + 5
class SpecialFileInfo(BER_TLV_IE, tag=0xC0):
    _construct = FlagsEnum(Byte, high_update_activity=0x80, readable_and_updatable_when_deactivated=0x40)

# TS 102 222 Table 4a
class FillingPattern(BER_TLV_IE, tag=0xC1):
    # The first W-1 bytes of the transparent EF or the first W-1 bytes of each record of a record
    # oriented EF shall be initialized with the first W-1 bytes of the Filling Pattern. All remaining
    # bytes (if any) shall be initialized with the value of the last byte of the Filling Pattern. If
    # the file or record length is shorter than the Filling Pattern, the Filling Pattern shall be
    # truncated accordingly.
    _construct = GreedyBytes

# TS 102 222 Table 4a
class RepeatPattern(BER_TLV_IE, tag=0xC2):
    # The first X bytes of the transparent EF or the first X bytes of each record of a record oriented
    # EF shall be initialized with the X bytes of the Repeat Pattern. This shall be repeated
    # consecutively for all remaining blocks of X bytes of data in the file or in a record. If
    # necessary, the Repeat Pattern shall be truncated at the end of the file or at the end of each
    # record to initialize the remaining bytes.
    _construct = GreedyBytes

# sysmoISIM-SJA2 specific
class ToolkitAccessConditions(BER_TLV_IE, tag=0xD2):
    _construct = FlagsEnum(Byte, rfm_create=1, rfm_delete_terminate=2, other_applet_create=4,
                           other_applet_delete_terminate=8)

# ETSI TS 102 221 11.1.1.4.6.0 + TS 102 222 Table 4A
class ProprietaryInformation(BER_TLV_IE, tag=0xA5,
                             nested=[UiccCharacteristics, ApplicationPowerConsumption,
                                     MinApplicationClockFrequency, AvailableMemory,
                                     FileDetails, ReservedFileSize, MaximumFileSize,
                                     SupportedFilesystemCommands, SpecificUiccEnvironmentConditions,
                                     SpecialFileInfo, FillingPattern, RepeatPattern,
                                     ToolkitAccessConditions]):
    pass

# ETSI TS 102 221 11.1.1.4.7.1
class SecurityAttribCompact(BER_TLV_IE, tag=0x8c):
    _construct = GreedyBytes

# ETSI TS 102 221 11.1.1.4.7.2
class SecurityAttribExpanded(BER_TLV_IE, tag=0xab):
    _construct = GreedyBytes

# ETSI TS 102 221 11.1.1.4.7.3
class SecurityAttribReferenced(BER_TLV_IE, tag=0x8b):
    # TODO: longer format with SEID
    _construct = Struct('ef_arr_file_id'/HexAdapter(Bytes(2)), 'ef_arr_record_nr'/Int8ub)

# ETSI TS 102 221 11.1.1.4.8
class ShortFileIdentifier(BER_TLV_IE, tag=0x88):
    # If the length of the TLV is 1, the SFI value is indicated in the 5 most significant bits (bits b8 to b4)
    # of the TLV value field. In this case, bits b3 to b1 shall be set to 0
    class Shift3RAdapter(Adapter):
        def _decode(self, obj, context, path):
            return int.from_bytes(obj, 'big') >> 3
        def _encode(self, obj, context, path):
            val = int(obj) << 3
            return val.to_bytes(1, 'big')
    _construct = COptional(Shift3RAdapter(Bytes(1)))

# ETSI TS 102 221 11.1.1.4.9
class LifeCycleStatusInteger(BER_TLV_IE, tag=0x8A):
    _test_de_encode = [
        ( '8a0105', 'operational_activated' ),
    ]
    def _from_bytes(self, do: bytes):
        lcsi = int.from_bytes(do, 'big')
        if lcsi == 0x00:
            ret = 'no_information'
        elif lcsi == 0x01:
            ret = 'creation'
        elif lcsi == 0x03:
            ret = 'initialization'
        elif lcsi & 0x05 == 0x05:
            ret = 'operational_activated'
        elif lcsi & 0x05 == 0x04:
            ret = 'operational_deactivated'
        elif lcsi & 0xc0 == 0xc0:
            ret = 'termination'
        else:
            ret = lcsi
        self.decoded = ret
        return self.decoded
    def _to_bytes(self):
        if self.decoded == 'no_information':
            return b'\x00'
        if self.decoded == 'creation':
            return b'\x01'
        if self.decoded == 'initialization':
            return b'\x03'
        if self.decoded == 'operational_activated':
            return b'\x05'
        if self.decoded == 'operational_deactivated':
            return b'\x04'
        if self.decoded == 'termination':
            return b'\x0c'
        if isinstance(self.decoded, int):
            return self.decoded.to_bytes(1, 'big')
        raise ValueError

# ETSI TS 102 221 11.1.1.4.9
class PS_DO(BER_TLV_IE, tag=0x90):
    _construct = GreedyBytes
class UsageQualifier_DO(BER_TLV_IE, tag=0x95):
    _construct = GreedyBytes
class KeyReference(BER_TLV_IE, tag=0x83):
    _construct = Byte
class PinStatusTemplate_DO(BER_TLV_IE, tag=0xC6, nested=[PS_DO, UsageQualifier_DO, KeyReference]):
    pass

class FcpTemplate(BER_TLV_IE, tag=0x62, nested=[FileSize, TotalFileSize, FileDescriptor, FileIdentifier,
                                                DfName, ProprietaryInformation, SecurityAttribCompact,
                                                SecurityAttribExpanded, SecurityAttribReferenced,
                                                ShortFileIdentifier, LifeCycleStatusInteger,
                                                PinStatusTemplate_DO]):
    pass

def decode_select_response(data_hex: str) -> object:
    """ETSI TS 102 221 Section 11.1.1.3"""
    t = FcpTemplate()
    t.from_tlv(h2b(data_hex))
    d = t.to_dict()
    return flatten_dict_lists(d['fcp_template'])

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

# TS 102 221 11.1.19.2.1
class TerminalPowerSupply(BER_TLV_IE, tag=0x80):
    _construct = Struct('used_supply_voltage_class'/SupplyVoltageClasses,
                        'maximum_available_power_supply'/Int8ub,
                        'actual_used_freq_100k'/Int8ub)

# TS 102 221 11.1.19.2.2
class ExtendedLchanTerminalSupport(BER_TLV_IE, tag=0x81):
    _construct = GreedyBytes

# TS 102 221 11.1.19.2.3
class AdditionalInterfacesSupport(BER_TLV_IE, tag=0x82):
    _construct = FlagsEnum(Int8ub, uicc_clf=0x01)

# TS 102 221 11.1.19.2.4 + SGP.32 v3.0 3.4.2 RSP Device Capabilities
class AdditionalTermCapEuicc(BER_TLV_IE, tag=0x83):
    _construct = FlagsEnum(Int8ub, lui_d=0x01, lpd_d=0x02, lds_d=0x04, lui_e_scws=0x08,
                           metadata_update_alerting=0x10,
                           enterprise_capable_device=0x20,
                           lui_e_e4e=0x40,
                           lpr=0x80)

# TS 102 221 11.1.19.2.0
class TerminalCapability(BER_TLV_IE, tag=0xa9, nested=[TerminalPowerSupply, ExtendedLchanTerminalSupport,
                                                       AdditionalInterfacesSupport, AdditionalTermCapEuicc]):
    pass

# ETSI TS 102 221 Section 9.2.7 + ISO7816-4 9.3.3/9.3.4
class _AM_DO_DF(DataObject):
    def __init__(self):
        super().__init__('access_mode', 'Access Mode', tag=0x80)

    def from_bytes(self, do: bytes):
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

    def from_bytes(self, do: bytes):
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

    def from_bytes(self, do: bytes):
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
        super().__init__('control_reference_template',
                         'Control Reference Template', tag=0xA4)

    def from_bytes(self, do: bytes):
        """Decode a Control Reference Template DO."""
        if len(do) != 6:
            raise ValueError('Unsupported CRT DO length: %s' %do)
        if do[0] != 0x83 or do[1] != 0x01:
            raise ValueError('Unsupported Key Ref Tag or Len in CRT DO %s' % do)
        if do[3:] != b'\x95\x01\x08':
            raise ValueError('Unsupported Usage Qualifier Tag or Len in CRT DO %s' % do)
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

    def from_bytes(self, binary: bytes):
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
        rd = {'mode': cond}
        if len(res) > 0:
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


class Nested_DO(DataObject):
    """A DO that nests another DO/Choice/Sequence"""

    def __init__(self, name, tag, choice):
        super().__init__(name, tag=tag)
        self.children = choice

    def from_bytes(self, binary: bytes) -> list:
        remainder = binary
        self.decoded = []
        while remainder:
            rc, remainder = self.children.decode(remainder)
            self.decoded.append(rc)
        return self.decoded

    def to_bytes(self) -> bytes:
        encoded = [self.children.encode(d) for d in self.decoded]
        return b''.join(encoded)


OR_Template = DataObjectChoice('or_template', 'OR-Template',
                               members=[Always_DO, Never_DO, SecCondByte_DO(), SecCondByte_DO(0x9e), CRT_DO()])
OR_DO = Nested_DO('or', 0xa0, OR_Template)
AND_Template = DataObjectChoice('and_template', 'AND-Template',
                                members=[Always_DO, Never_DO, SecCondByte_DO(), SecCondByte_DO(0x9e), CRT_DO()])
AND_DO = Nested_DO('and', 0xa7, AND_Template)
NOT_Template = DataObjectChoice('not_template', 'NOT-Template',
                                members=[Always_DO, Never_DO, SecCondByte_DO(), SecCondByte_DO(0x9e), CRT_DO()])
NOT_DO = Nested_DO('not', 0xaf, NOT_Template)
SC_DO = DataObjectChoice('security_condition', 'Security Condition',
                         members=[Always_DO, Never_DO, SecCondByte_DO(), SecCondByte_DO(0x9e), CRT_DO(),
                                  OR_DO, AND_DO, NOT_DO])
