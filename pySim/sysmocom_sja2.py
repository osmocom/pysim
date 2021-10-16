# coding=utf-8
"""Utilities / Functions related to sysmocom SJA2 cards

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
from pySim.ts_102_221 import CardProfileUICC
from pySim.construct import *
from construct import *
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
    def __init__(self, fid, name):
        super().__init__(fid, name=name, desc='%s PIN file' % name)
    def _decode_bin(self, raw_bin_data):
        u = unpack('!BBB8s', raw_bin_data[:11])
        res =  {'enabled': (True, False)[u[0] & 0x01],
                'initialized': (True, False)[u[0] & 0x02],
                'disable_able': (False, True)[u[0] & 0x10],
                'unblock_able': (False, True)[u[0] & 0x20],
                'change_able': (False, True)[u[0] & 0x40],
                'valid': (False, True)[u[0] & 0x80],
                'attempts_remaining': u[1],
                'maximum_attempts': u[2],
                'pin': u[3].hex(),
                }
        if len(raw_bin_data) == 21:
            u2 = unpack('!BB8s', raw_bin_data[11:10])
            res['attempts_remaining_puk'] = u2[0]
            res['maximum_attempts_puk'] = u2[1]
            res['puk'] = u2[2].hex()
        return res

class EF_MILENAGE_CFG(TransparentEF):
    def __init__(self, fid='6f21', name='EF.MILENAGE_CFG', desc='Milenage connfiguration'):
        super().__init__(fid, name=name, desc=desc)
    def _decode_bin(self, raw_bin_data):
        u = unpack('!BBBBB16s16s16s16s16s', raw_bin_data)
        return {'r1': u[0], 'r2': u[1], 'r3': u[2], 'r4': u[3], 'r5': u[4],
                'c1': u[5].hex(),
                'c2': u[6].hex(),
                'c3': u[7].hex(),
                'c4': u[8].hex(),
                'c5': u[9].hex(),
               }

class EF_0348_KEY(LinFixedEF):
    def __init__(self, fid='6f22', name='EF.0348_KEY', desc='TS 03.48 OTA Keys'):
        super().__init__(fid, name=name, desc=desc, rec_len={27,35})
    def _decode_record_bin(self, raw_bin_data):
        u = unpack('!BBB', raw_bin_data[0:3])
        key_algo = (u[2] >> 6) & 1
        key_length = ((u[2] >> 3) & 3) * 8
        return {'sec_domain': u[0],
                'key_set_version': u[1],
                'key_type': key_type2str[u[2] & 3],
                'key_length': key_length,
                'algorithm': key_algo2str[key_algo],
                'mac_length': mac_length[(u[2] >> 7)],
                'key': raw_bin_data[3:key_length].hex()
               }

class EF_0348_COUNT(LinFixedEF):
    def __init__(self, fid='6f23', name='EF.0348_COUNT', desc='TS 03.48 OTA Counters'):
        super().__init__(fid, name=name, desc=desc, rec_len={7,7})
    def _decode_record_bin(self, raw_bin_data):
        u = unpack('!BB5s', raw_bin_data)
        return {'sec_domain': u[0], 'key_set_version': u[1], 'counter': u[2]}

class EF_SIM_AUTH_COUNTER(TransparentEF):
    def __init__(self, fid='af24', name='EF.SIM_AUTH_COUNTER'):
        super().__init__(fid, name=name, desc='Number of remaining RUN GSM ALGORITHM executions')
        self._construct = Struct('num_run_gsm_algo_remain'/Int32ub)

class EF_GP_COUNT(LinFixedEF):
    def __init__(self, fid='6f26', name='EF.GP_COUNT', desc='GP SCP02 Counters'):
        super().__init__(fid, name=name, desc=desc, rec_len={5,5})
    def _decode_record_bin(self, raw_bin_data):
        u = unpack('!BBHB', raw_bin_data)
        return {'sec_domain': u[0], 'key_set_version': u[1], 'counter': u[2], 'rfu': u[3]}

class EF_GP_DIV_DATA(LinFixedEF):
    def __init__(self, fid='6f27', name='EF.GP_DIV_DATA', desc='GP SCP02 key diversification data'):
        super().__init__(fid, name=name, desc=desc, rec_len={12,12})
    def _decode_record_bin(self, raw_bin_data):
        u = unpack('!BB8s', raw_bin_data)
        return {'sec_domain': u[0], 'key_set_version': u[1], 'key_div_data': u[2].hex()}

class EF_SIM_AUTH_KEY(TransparentEF):
    def __init__(self, fid='6f20', name='EF.SIM_AUTH_KEY'):
        super().__init__(fid, name=name, desc='USIM authentication key')
        CfgByte = BitStruct(Bit[2],
                            'use_sres_deriv_func_2'/Bit,
                            'use_opc_instead_of_op'/Bit,
                            'algorithm'/Enum(Nibble, milenage=4, comp128v1=1, comp128v2=2, comp128v3=3))
        self._construct = Struct('cfg'/CfgByte,
                                 'key'/Bytes(16),
                                 'op'/If(this.cfg.algorithm=='milenage' and not this.cfg.use_opc_instead_of_op, Bytes(16)),
                                 'opc'/If(this.cfg.algorithm=='milenage' and this.cfg.use_opc_instead_of_op, Bytes(16))
                                 )

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
        return pySim.ts_102_221.decode_select_response(resp_hex)

class EF_USIM_SQN(TransparentEF):
    def __init__(self, fid='af30', name='EF.USIM_SQN'):
        super().__init__(fid, name=name, desc='SQN parameters for AKA')
        Flag1 = BitStruct('skip_next_sqn_check'/Bit, 'delta_max_check'/Bit,
                          'age_limit_check'/Bit, 'sqn_check'/Bit,
                          'ind_len'/BitsInteger(4))
        Flag2 = BitStruct('rfu'/BitsRFU(5), 'dont_clear_amf_for_macs'/Bit,
                          'aus_concealed'/Bit, 'autn_concealed'/Bit)
        self._construct = Struct('flag1'/Flag1, 'flag2'/Flag2,
                                 'delta_max'/BytesInteger(6), 'age_limit'/BytesInteger(6),
                                 'freshness'/GreedyRange(BytesInteger(6)))

class EF_USIM_AUTH_KEY(TransparentEF):
    def __init__(self, fid='af20', name='EF.USIM_AUTH_KEY'):
        super().__init__(fid, name=name, desc='USIM authentication key')
        CfgByte = BitStruct(Bit, 'only_4bytes_res_in_3g'/Bit,
                            'use_sres_deriv_func_2_in_3g'/Bit,
                            'use_opc_instead_of_op'/Bit,
                            'algorithm'/Enum(Nibble, milenage=4, sha1_aka=5, xor=15))
        self._construct = Struct('cfg'/CfgByte,
                                 'key'/Bytes(16),
                                 'op'/If(this.cfg.algorithm=='milenage' and not this.cfg.use_opc_instead_of_op, Bytes(16)),
                                 'opc'/If(this.cfg.algorithm=='milenage' and this.cfg.use_opc_instead_of_op, Bytes(16))
                                 )
class EF_USIM_AUTH_KEY_2G(TransparentEF):
    def __init__(self, fid='af22', name='EF.USIM_AUTH_KEY_2G'):
        super().__init__(fid, name=name, desc='USIM authentication key in 2G context')
        CfgByte = BitStruct(Bit, 'only_4bytes_res_in_3g'/Bit,
                            'use_sres_deriv_func_2_in_3g'/Bit,
                            'use_opc_instead_of_op'/Bit,
                            'algorithm'/Enum(Nibble, milenage=4, comp128v1=1, comp128v2=2, comp128v3=3))
        self._construct = Struct('cfg'/CfgByte,
                                 'key'/Bytes(16),
                                 'op'/If(this.cfg.algorithm=='milenage' and not this.cfg.use_opc_instead_of_op, Bytes(16)),
                                 'opc'/If(this.cfg.algorithm=='milenage' and this.cfg.use_opc_instead_of_op, Bytes(16))
                                 )
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
        super().__init__(fid, name=name, desc='Secret key for GBA key derivation', rec_len={32,32})
        self._construct = GreedyBytes



class SysmocomSJA2(CardModel):
    _atrs = [ "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 75 30 34 05 4B A9",
              "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 75 31 33 02 51 B2",
              "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 52 75 31 04 51 D5" ]
    @classmethod
    def add_files(cls, rs:RuntimeState):
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
