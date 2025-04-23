# coding=utf-8
"""Utilities / Functions related to sysmocom SJA2/SJA5 cards

(C) 2021-2023 by Harald Welte <laforge@osmocom.org>

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

from struct import unpack
from construct import FlagsEnum, Byte, Struct, Int8ub, Mapping, Enum, Padding, BitsInteger
from construct import Bit, this, Int32ub, Int16ub, Nibble, BytesInteger, GreedyRange, Const
from construct import Optional as COptional
from osmocom.utils import *
from osmocom.construct import *

from pySim.filesystem import *
from pySim.runtime import RuntimeState
import pySim

key_type2str = {
    0: 'kic',
    1: 'kid',
    2: 'kik',
    3: 'any',
}

key_algo2str = {
    0: 'des',
    1: 'aes'
}

mac_length = {
    0: 8,
    1: 4
}


class EF_PIN(TransparentEF):
    _test_de_encode = [
        ( 'f1030331323334ffffffff0a0a3132333435363738',
          { 'state': { 'valid': True, 'change_able': True, 'unblock_able': True, 'disable_able': True,
                       'not_initialized': False, 'disabled': True },
           'attempts_remaining': 3, 'maximum_attempts': 3, 'pin': '31323334',
           'puk': { 'attempts_remaining': 10, 'maximum_attempts': 10, 'puk': '3132333435363738' }
          } ),
        ( 'f003039999999999999999',
          { 'state': { 'valid': True, 'change_able': True, 'unblock_able': True, 'disable_able': True,
                       'not_initialized': False, 'disabled': False },
           'attempts_remaining': 3, 'maximum_attempts': 3, 'pin': '9999999999999999',
           'puk': None } ),
    ]
    def __init__(self, fid='6f01', name='EF.CHV1'):
        super().__init__(fid, name=name, desc='%s PIN file' % name)
        StateByte = FlagsEnum(Byte, disabled=1, not_initialized=2, disable_able=0x10, unblock_able=0x20,
                                    change_able=0x40, valid=0x80)
        PukStruct = Struct('attempts_remaining'/Int8ub,
                           'maximum_attempts'/Int8ub,
                           'puk'/HexAdapter(Rpad(Bytes(8))))
        self._construct = Struct('state'/StateByte,
                                 'attempts_remaining'/Int8ub,
                                 'maximum_attempts'/Int8ub,
                                 'pin'/HexAdapter(Rpad(Bytes(8))),
                                 'puk'/COptional(PukStruct))


class EF_MILENAGE_CFG(TransparentEF):
    _test_de_encode = [
        ( '40002040600000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000020000000000000000000000000000000400000000000000000000000000000008',
          {"r1": 64, "r2": 0, "r3": 32, "r4": 64, "r5": 96, "c1": "00000000000000000000000000000000", "c2":
           "00000000000000000000000000000001", "c3": "00000000000000000000000000000002", "c4":
           "00000000000000000000000000000004", "c5": "00000000000000000000000000000008"} ),
      ]
    def __init__(self, fid='6f21', name='EF.MILENAGE_CFG', desc='Milenage connfiguration'):
        super().__init__(fid, name=name, desc=desc)
        self._construct = Struct('r1'/Int8ub, 'r2'/Int8ub, 'r3'/Int8ub, 'r4'/Int8ub, 'r5'/Int8ub,
                                 'c1'/HexAdapter(Bytes(16)),
                                 'c2'/HexAdapter(Bytes(16)),
                                 'c3'/HexAdapter(Bytes(16)),
                                 'c4'/HexAdapter(Bytes(16)),
                                 'c5'/HexAdapter(Bytes(16)))


class EF_0348_KEY(LinFixedEF):
    def __init__(self, fid='6f22', name='EF.0348_KEY', desc='TS 03.48 OTA Keys'):
        super().__init__(fid, name=name, desc=desc, rec_len=(27, 35))
        KeyLenAndType = BitStruct('mac_length'/Mapping(Bit, {8:0, 4:1}),
                                  'algorithm'/Enum(Bit, des=0, aes=1),
                                  'key_length'/MultiplyAdapter(BitsInteger(3), 8),
                                  '_rfu'/BitsRFU(1),
                                  'key_type'/Enum(BitsInteger(2), kic=0, kid=1, kik=2, any=3))
        self._construct = Struct('security_domain'/Int8ub,
                                 'key_set_version'/Int8ub,
                                 'key_len_and_type'/KeyLenAndType,
                                 'key'/HexAdapter(Bytes(this.key_len_and_type.key_length)))


class EF_0348_COUNT(LinFixedEF):
    _test_de_encode = [
        ( 'fe010000000000', {"sec_domain": 254, "key_set_version": 1, "counter": "0000000000"} ),
      ]
    def __init__(self, fid='6f23', name='EF.0348_COUNT', desc='TS 03.48 OTA Counters'):
        super().__init__(fid, name=name, desc=desc, rec_len=(7, 7))
        self._construct = Struct('sec_domain'/Int8ub,
                                 'key_set_version'/Int8ub,
                                 'counter'/HexAdapter(Bytes(5)))


class EF_SIM_AUTH_COUNTER(TransparentEF):
    def __init__(self, fid='af24', name='EF.SIM_AUTH_COUNTER'):
        super().__init__(fid, name=name, desc='Number of remaining RUN GSM ALGORITHM executions')
        self._construct = Struct('num_run_gsm_algo_remain'/Int32ub)


class EF_GP_COUNT(LinFixedEF):
    _test_de_encode = [
        ( '0070000000', {"sec_domain": 0, "key_set_version": 112, "counter": 0, "rfu": 0} ),
      ]
    def __init__(self, fid='6f26', name='EF.GP_COUNT', desc='GP SCP02 Counters'):
        super().__init__(fid, name=name, desc=desc, rec_len=(5, 5))
        self._construct = Struct('sec_domain'/Int8ub,
                                 'key_set_version'/Int8ub,
                                 'counter'/Int16ub,
                                 'rfu'/Int8ub)

class EF_GP_DIV_DATA(LinFixedEF):
    def __init__(self, fid='6f27', name='EF.GP_DIV_DATA', desc='GP SCP02 key diversification data'):
        super().__init__(fid, name=name, desc=desc, rec_len=(12, 12))

    def _decode_record_bin(self, raw_bin_data, **kwargs):
        u = unpack('!BB8s', raw_bin_data)
        return {'sec_domain': u[0], 'key_set_version': u[1], 'key_div_data': u[2].hex()}


class EF_SIM_AUTH_KEY(TransparentEF):
    _test_de_encode = [
        ( '14000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
          {"cfg": {"sres_deriv_func": 1, "use_opc_instead_of_op": True, "algorithm": "milenage"}, "key":
           "000102030405060708090a0b0c0d0e0f", "op_opc": "101112131415161718191a1b1c1d1e1f"} ),
      ]
    def __init__(self, fid='6f20', name='EF.SIM_AUTH_KEY'):
        super().__init__(fid, name=name, desc='USIM authentication key')
        CfgByte = BitStruct(Padding(2),
                            'sres_deriv_func'/Mapping(Bit, {1:0, 2:1}),
                            'use_opc_instead_of_op'/Flag,
                            'algorithm'/Enum(Nibble, milenage=4, comp128v1=1, comp128v2=2, comp128v3=3))
        self._construct = Struct('cfg'/CfgByte,
                                 'key'/HexAdapter(Bytes(16)),
                                 'op_opc' /HexAdapter(Bytes(16)))


class DF_SYSTEM(CardDF):
    def __init__(self):
        super().__init__(fid='a515', name='DF.SYSTEM', desc='CardOS specifics')
        files = [
            EF_PIN('6f01', 'EF.CHV1'),
            EF_PIN('6f81', 'EF.CHV2'),
            EF_PIN('6f0a', 'EF.ADM1'),
            EF_PIN('6f0b', 'EF.ADM2'),
            EF_PIN('6f0c', 'EF.ADM3'),
            EF_PIN('6f0d', 'EF.ADM4'),
            EF_MILENAGE_CFG(),
            EF_0348_KEY(),
            EF_SIM_AUTH_COUNTER(),
            EF_SIM_AUTH_KEY(),
            EF_0348_COUNT(),
            EF_GP_COUNT(),
            EF_GP_DIV_DATA(),
        ]
        self.add_files(files)

    def decode_select_response(self, resp_hex):
        return pySim.ts_102_221.CardProfileUICC.decode_select_response(resp_hex)


class EF_USIM_SQN(TransparentEF):
    _test_de_encode = [
        ( 'd503000200000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
          {"flag1": {"skip_next_sqn_check": True, "delta_max_check": True, "age_limit_check": False, "sqn_check": True,
                     "ind_len": 5}, "flag2": {"rfu": 0, "dont_clear_amf_for_macs": False, "aus_concealed": True,
                                              "autn_concealed": True}, "delta_max": 8589934592, "age_limit":
           8589934592, "freshness": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0]} ),
      ]
    def __init__(self, fid='af30', name='EF.USIM_SQN'):
        super().__init__(fid, name=name, desc='SQN parameters for AKA')
        Flag1 = BitStruct('skip_next_sqn_check'/Flag, 'delta_max_check'/Flag,
                          'age_limit_check'/Flag, 'sqn_check'/Flag,
                          'ind_len'/BitsInteger(4))
        Flag2 = BitStruct('rfu'/BitsRFU(5), 'dont_clear_amf_for_macs'/Flag,
                          'aus_concealed'/Flag, 'autn_concealed'/Flag)
        self._construct = Struct('flag1'/Flag1, 'flag2'/Flag2,
                                 'delta_max' /
                                 BytesInteger(6), 'age_limit'/BytesInteger(6),
                                 'freshness'/GreedyRange(BytesInteger(6)))


class EF_USIM_AUTH_KEY(TransparentEF):
    _test_de_encode = [
        ( '141898d827f70120d33b3e7462ee5fd6fe6ca53d7a0a804561646816d7b0c702fb',
          { "cfg": { "only_4bytes_res_in_3g": False, "sres_deriv_func_in_2g": 1, "use_opc_instead_of_op": True, "algorithm": "milenage" },
            "key": "1898d827f70120d33b3e7462ee5fd6fe", "op_opc": "6ca53d7a0a804561646816d7b0c702fb" } ),
        ( '160a04101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f000102030405060708090a0b0c0d0e0f',
         { "cfg" : { "algorithm" : "tuak", "key_length" : 128, "sres_deriv_func_in_2g" : 1, "use_opc_instead_of_op" : True },
           "tuak_cfg" : { "ck_and_ik_size" : 128, "mac_size" : 128, "res_size" : 128 },
           "num_of_keccak_iterations" : 4,
           "k" : "000102030405060708090a0b0c0d0e0f",
           "op_opc" : "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
         } ),
      ]
    def __init__(self, fid='af20', name='EF.USIM_AUTH_KEY'):
        super().__init__(fid, name=name, desc='USIM authentication key')
        Algorithm = Enum(Nibble, milenage=4, sha1_aka=5, tuak=6, xor=15)
        CfgByte = BitStruct(Padding(1), 'only_4bytes_res_in_3g'/Flag,
                            'sres_deriv_func_in_2g'/Mapping(Bit, {1:0, 2:1}),
                            'use_opc_instead_of_op'/Mapping(Bit, {False:0, True:1}),
                            'algorithm'/Algorithm)
        self._construct = Struct('cfg'/CfgByte,
                                 'key'/HexAdapter(Bytes(16)),
                                 'op_opc' /HexAdapter(Bytes(16)))
        # TUAK has a rather different layout for the data, so we define a different
        # construct below and use explicit _{decode,encode}_bin() methods for separating
        # the TUAK and non-TUAK situation
        CfgByteTuak = BitStruct(Padding(1),
                                'key_length'/Mapping(Bit, {128:0, 256:1}),
                                'sres_deriv_func_in_2g'/Mapping(Bit, {1:0, 2:1}),
                                'use_opc_instead_of_op'/Mapping(Bit, {False:0, True:1}),
                                'algorithm'/Algorithm)
        TuakCfgByte = BitStruct(Padding(1),
                                'ck_and_ik_size'/Mapping(Bit, {128:0, 256:1}),
                                'mac_size'/Mapping(BitsInteger(3), {64:0, 128:1, 256:2}),
                                'res_size'/Mapping(BitsInteger(3), {32:0, 64:1, 128:2, 256:3}))
        self._constr_tuak = Struct('cfg'/CfgByteTuak,
                                   'tuak_cfg'/TuakCfgByte,
                                   'num_of_keccak_iterations'/Int8ub,
                                   'op_opc'/HexAdapter(Bytes(32)),
                                   'k'/HexAdapter(Bytes(this.cfg.key_length//8)))

    def _decode_bin(self, raw_bin_data: bytearray) -> dict:
        if raw_bin_data[0] & 0x0F == 0x06:
            return parse_construct(self._constr_tuak, raw_bin_data)
        else:
            return parse_construct(self._construct, raw_bin_data)

    def _encode_bin(self, abstract_data: dict, **kwargs) -> bytearray:
        if abstract_data['cfg']['algorithm'] == 'tuak':
            return build_construct(self._constr_tuak, abstract_data)
        else:
            return build_construct(self._construct, abstract_data)


class EF_USIM_AUTH_KEY_2G(TransparentEF):
    _test_de_encode = [
        ( '14000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
          {"cfg": {"only_4bytes_res_in_3g": False, "sres_deriv_func_in_2g": 1, "use_opc_instead_of_op": True,
                   "algorithm": "milenage"}, "key": "000102030405060708090a0b0c0d0e0f", "op_opc":
           "101112131415161718191a1b1c1d1e1f"} ),
      ]
    def __init__(self, fid='af22', name='EF.USIM_AUTH_KEY_2G'):
        super().__init__(fid, name=name, desc='USIM authentication key in 2G context')
        CfgByte = BitStruct(Padding(1), 'only_4bytes_res_in_3g'/Flag,
                            'sres_deriv_func_in_2g'/Mapping(Bit, {1:0, 2:1}),
                            'use_opc_instead_of_op'/Flag,
                            'algorithm'/Enum(Nibble, milenage=4, comp128v1=1, comp128v2=2, comp128v3=3, xor=14))
        self._construct = Struct('cfg'/CfgByte,
                                 'key'/HexAdapter(Bytes(16)),
                                 'op_opc' /HexAdapter(Bytes(16)))


class EF_GBA_SK(TransparentEF):
    def __init__(self, fid='af31', name='EF.GBA_SK'):
        super().__init__(fid, name=name, desc='Secret key for GBA key derivation')
        self._construct = GreedyBytes


class EF_GBA_REC_LIST(TransparentEF):
    def __init__(self, fid='af32', name='EF.GBA_REC_LIST'):
        super().__init__(fid, name=name, desc='Secret key for GBA key derivation')
        # integers representing record numbers in EF-GBANL
        self._construct = GreedyRange(Int8ub)


class EF_GBA_INT_KEY(LinFixedEF):
    def __init__(self, fid='af33', name='EF.GBA_INT_KEY'):
        super().__init__(fid, name=name,
                         desc='Secret key for GBA key derivation', rec_len=(32, 32))
        self._construct = GreedyBytes


class SysmocomSJA2(CardModel):
    _atrs = ["3b9f96801f878031e073fe211b674a4c753034054ba9",
             "3b9f96801f878031e073fe211b674a4c7531330251b2",
             "3b9f96801f878031e073fe211b674a4c5275310451d5"]

    @classmethod
    def add_files(cls, rs: RuntimeState):
        """Add sysmocom SJA2 specific files to given RuntimeState."""
        rs.mf.add_file(DF_SYSTEM())
        # optional USIM application
        if 'a0000000871002' in rs.mf.applications:
            usim_adf = rs.mf.applications['a0000000871002']
            files_adf_usim = [
                EF_USIM_AUTH_KEY(),
                EF_USIM_AUTH_KEY_2G(),
                EF_GBA_SK(),
                EF_GBA_REC_LIST(),
                EF_GBA_INT_KEY(),
                EF_USIM_SQN(),
            ]
            usim_adf.add_files(files_adf_usim)
        # optional ISIM application
        if 'a0000000871004' in rs.mf.applications:
            isim_adf = rs.mf.applications['a0000000871004']
            files_adf_isim = [
                EF_USIM_AUTH_KEY(name='EF.ISIM_AUTH_KEY'),
                EF_USIM_AUTH_KEY_2G(name='EF.ISIM_AUTH_KEY_2G'),
                EF_USIM_SQN(name='EF.ISIM_SQN'),
            ]
            isim_adf.add_files(files_adf_isim)

class SysmocomSJA5(CardModel):
    _atrs = ["3b9f96801f878031e073fe211b674a357530350251cc",
             "3b9f96801f878031e073fe211b674a357530350265f8",
             "3b9f96801f878031e073fe211b674a357530350259c4"]

    @classmethod
    def add_files(cls, rs: RuntimeState):
        """Add sysmocom SJA2 specific files to given RuntimeState."""
        rs.mf.add_file(DF_SYSTEM())
        # optional USIM application
        if 'a0000000871002' in rs.mf.applications:
            usim_adf = rs.mf.applications['a0000000871002']
            files_adf_usim = [
                EF_USIM_AUTH_KEY(),
                EF_USIM_AUTH_KEY_2G(),
                EF_GBA_SK(),
                EF_GBA_REC_LIST(),
                EF_GBA_INT_KEY(),
                EF_USIM_SQN(),
            ]
            usim_adf.add_files(files_adf_usim)
        # optional ISIM application
        if 'a0000000871004' in rs.mf.applications:
            isim_adf = rs.mf.applications['a0000000871004']
            files_adf_isim = [
                EF_USIM_AUTH_KEY(name='EF.ISIM_AUTH_KEY'),
                EF_USIM_AUTH_KEY_2G(name='EF.ISIM_AUTH_KEY_2G'),
                EF_USIM_SQN(name='EF.ISIM_SQN'),
            ]
            isim_adf.add_files(files_adf_isim)
