# -*- coding: utf-8 -*-

# without this, pylint will fail when inner classes are used
# within the 'nested' kwarg of our TlvMeta metaclass on python 3.7 :(
# pylint: disable=undefined-variable

"""
APDU commands of 3GPP TS 31.102 V16.6.0
"""
from typing import Dict

from construct import *
from construct import Optional as COptional
from pySim.filesystem import *
from pySim.construct import *
from pySim.ts_31_102 import SUCI_TlvDataObject

from pySim.apdu import ApduCommand, ApduCommandSet

# Copyright (C) 2022 Harald Welte <laforge@osmocom.org>
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

# Mapping between USIM Service Number and its description

from pySim.apdu import ApduCommand, ApduCommandSet

# TS 31.102 Section 7.1
class UsimAuthenticateEven(ApduCommand, n='AUTHENTICATE', ins=0x88, cla=['0X', '4X', '6X']):
    _apdu_case = 4
    _construct_p2 = BitStruct('scope'/Enum(Flag, mf=0, df_adf_specific=1),
                              BitsInteger(4),
                              'authentication_context'/Enum(BitsInteger(3), gsm=0, umts=1,
                                                            vgcs_vbs=2, gba=4))
    _cs_cmd_gsm_3g =  Struct('_rand_len'/Int8ub, 'rand'/HexAdapter(Bytes(this._rand_len)),
                         '_autn_len'/COptional(Int8ub), 'autn'/If(this._autn_len, HexAdapter(Bytes(this._autn_len))))
    _cs_cmd_vgcs = Struct('_vsid_len'/Int8ub, 'vservice_id'/HexAdapter(Bytes(this._vsid_len)),
                          '_vkid_len'/Int8ub, 'vk_id'/HexAdapter(Bytes(this._vkid_len)),
                          '_vstk_rand_len'/Int8ub, 'vstk_rand'/HexAdapter(Bytes(this._vstk_rand_len)))
    _cmd_gba_bs = Struct('_rand_len'/Int8ub, 'rand'/HexAdapter(Bytes(this._rand_len)),
                         '_autn_len'/Int8ub, 'autn'/HexAdapter(Bytes(this._autn_len)))
    _cmd_gba_naf = Struct('_naf_id_len'/Int8ub, 'naf_id'/HexAdapter(Bytes(this._naf_id_len)),
                          '_impi_len'/Int8ub, 'impi'/HexAdapter(Bytes(this._impi_len)))
    _cs_cmd_gba = Struct('tag'/Int8ub, 'body'/Switch(this.tag, { 0xDD: 'bootstrap'/_cmd_gba_bs,
                                                                 0xDE: 'naf_derivation'/_cmd_gba_naf }))
    _cs_rsp_gsm = Struct('_len_sres'/Int8ub, 'sres'/HexAdapter(Bytes(this._len_sres)),
                         '_len_kc'/Int8ub, 'kc'/HexAdapter(Bytes(this._len_kc)))
    _rsp_3g_ok = Struct('_len_res'/Int8ub, 'res'/HexAdapter(Bytes(this._len_res)),
                        '_len_ck'/Int8ub, 'ck'/HexAdapter(Bytes(this._len_ck)),
                        '_len_ik'/Int8ub, 'ik'/HexAdapter(Bytes(this._len_ik)),
                        '_len_kc'/COptional(Int8ub), 'kc'/If(this._len_kc, HexAdapter(Bytes(this._len_kc))))
    _rsp_3g_sync = Struct('_len_auts'/Int8ub, 'auts'/HexAdapter(Bytes(this._len_auts)))
    _cs_rsp_3g = Struct('tag'/Int8ub, 'body'/Switch(this.tag, { 0xDB: 'success'/_rsp_3g_ok,
                                                                0xDC: 'sync_fail'/_rsp_3g_sync}))
    _cs_rsp_vgcs = Struct(Const(b'\xDB'), '_vstk_len'/Int8ub, 'vstk'/HexAdapter(Bytes(this._vstk_len)))
    _cs_rsp_gba_naf = Struct(Const(b'\xDB'), '_ks_ext_naf_len'/Int8ub, 'ks_ext_naf'/HexAdapter(Bytes(this._ks_ext_naf_len)))
    def _decode_cmd(self) -> Dict:
        r = {}
        r['p1'] = parse_construct(self._construct_p1, self.p1.to_bytes(1, 'big'))
        r['p2'] = parse_construct(self._construct_p2, self.p2.to_bytes(1, 'big'))
        auth_ctx = r['p2']['authentication_context']
        if auth_ctx in ['gsm', 'umts']:
            r['body'] = parse_construct(self._cs_cmd_gsm_3g, self.cmd_data)
        elif auth_ctx == 'vgcs_vbs':
            r['body'] = parse_construct(self._cs_cmd_vgcs, self.cmd_data)
        elif auth_ctx == 'gba':
            r['body'] = parse_construct(self._cs_cmd_gba, self.cmd_data)
        else:
            raise ValueError('Unsupported authentication_context: %s' % auth_ctx)
        return r

    def _decode_rsp(self) -> Dict:
        r = {}
        auth_ctx = self.cmd_dict['p2']['authentication_context']
        if auth_ctx == 'gsm':
            r['body'] = parse_construct(self._cs_rsp_gsm, self.rsp_data)
        elif auth_ctx == 'umts':
            r['body'] = parse_construct(self._cs_rsp_3g, self.rsp_data)
        elif auth_ctx == 'vgcs_vbs':
            r['body'] = parse_construct(self._cs_rsp_vgcs, self.rsp_data)
        elif auth_ctx == 'gba':
            if self.cmd_dict['body']['tag'] == 0xDD:
                r['body'] = parse_construct(self._cs_rsp_3g, self.rsp_data)
            else:
                r['body'] = parse_construct(self._cs_rsp_gba_naf, self.rsp_data)
        else:
            raise ValueError('Unsupported authentication_context: %s' % auth_ctx)
        return r

class UsimAuthenticateOdd(ApduCommand, n='AUTHENTICATE', ins=0x89, cla=['0X', '4X', '6X']):
    _apdu_case = 4
    _construct_p2 = BitStruct('scope'/Enum(Flag, mf=0, df_adf_specific=1),
                              BitsInteger(4),
                              'authentication_context'/Enum(BitsInteger(3), mbms=5, local_key=6))
# TS 31.102 Section 7.5
class UsimGetIdentity(ApduCommand, n='GET IDENTITY', ins=0x78, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4
    _construct_p2 = BitStruct('scope'/Enum(Flag, mf=0, df_adf_specific=1),
                              'identity_context'/Enum(BitsInteger(7), suci=1))
    _tlv_rsp = SUCI_TlvDataObject

ApduCommands = ApduCommandSet('TS 31.102', cmds=[UsimAuthenticateEven, UsimAuthenticateOdd,
                                                 UsimGetIdentity])
