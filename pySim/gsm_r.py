# -*- coding: utf-8 -*-

# without this, pylint will fail when inner classes are used
# within the 'nested' kwarg of our TlvMeta metaclass on python 3.7 :(
# pylint: disable=undefined-variable

"""
The File (and its derived classes) uses the classes of pySim.filesystem in
order to describe the files specified in UIC Reference P38 T 9001 5.0 "FFFIS for GSM-R SIM Cards"
"""

#
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


from pySim.utils import *
#from pySim.tlv import *
from struct import pack, unpack
from construct import *
from construct import Optional as COptional
from pySim.construct import *
import enum

from pySim.filesystem import *
import pySim.ts_102_221
import pySim.ts_51_011

######################################################################
# DF.EIRENE (FFFIS for GSM-R SIM Cards)
######################################################################

class FuncNTypeAdapter(Adapter):
    def _decode(self, obj, context, path):
        bcd = swap_nibbles(b2h(obj))
        last_digit = bcd[-1]
        return {'functional_number': bcd[:-1],
                'presentation_of_only_this_fn': last_digit & 4,
                'permanent_fn': last_digit & 8 }
    def _encode(self, obj, context, path):
        return 'FIXME'

class EF_FN(LinFixedEF):
    """Section 7.2"""
    def __init__(self):
        super().__init__(fid='6ff1', sfid=None, name='EF.EN', desc='Functional numbers', rec_len={9,9})
        self._construct = Struct('functional_number_and_type'/FuncNTypeAdapter(Bytes(8)),
                                 'list_number'/Int8ub)


class PlConfAdapter(Adapter):
    """Section 7.4.3"""
    def _decode(self, obj, context, path):
        num = int(obj) & 0x7
        if num == 0:
            return 'None'
        elif num == 1:
            return 4
        elif num == 2:
            return 3
        elif num == 3:
            return 2
        elif num == 4:
            return 1
        elif num == 5:
            return 0
    def _encode(self, obj, context, path):
        if obj == 'None':
            return 0
        obj = int(obj)
        if obj == 4:
            return 1
        elif obj == 3:
            return 2
        elif obj == 2:
            return 3
        elif obj == 1:
            return 4
        elif obj == 0:
            return 5

class PlCallAdapter(Adapter):
    """Section 7.4.12"""
    def _decode(self, obj, context, path):
        num = int(obj) & 0x7
        if num == 0:
            return 'None'
        elif num == 1:
            return 4
        elif num == 2:
            return 3
        elif num == 3:
            return 2
        elif num == 4:
            return 1
        elif num == 5:
            return 0
        elif num == 6:
            return 'B'
        elif num == 7:
            return 'A'
    def _encode(self, obj, context, path):
        if obj == 'None':
            return 0
        if obj == 4:
            return 1
        elif obj == 3:
            return 2
        elif obj == 2:
            return 3
        elif obj == 1:
            return 4
        elif obj == 0:
            return 5
        elif obj == 'B':
            return 6
        elif obj == 'A':
            return 7

NextTableType = Enum(Byte, decision=0xf0, predefined=0xf1, num_dial_digits=0xf2, ic=0xf3, empty=0xff)

class EF_CallconfC(TransparentEF):
    """Section 7.3"""
    def __init__(self):
        super().__init__(fid='6ff2', sfid=None, name='EF.CallconfC', size={24,24},
                         desc='Call Configuration of emergency calls Configuration')
        self._construct = Struct('pl_conf'/PlConfAdapter(Int8ub),
                                 'conf_nr'/BcdAdapter(Bytes(8)),
                                 'max_rand'/Int8ub,
                                 'n_ack_max'/Int16ub,
                                 'pl_ack'/PlCallAdapter(Int8ub),
                                 'n_nested_max'/Int8ub,
                                 'train_emergency_gid'/Int8ub,
                                 'shunting_emergency_gid'/Int8ub,
                                 'imei'/BcdAdapter(Bytes(8)))

class EF_CallconfI(LinFixedEF):
    """Section 7.5"""
    def __init__(self):
        super().__init__(fid='6ff3', sfid=None, name='EF.CallconfI', rec_len={21,21},
                         desc='Call Configuration of emergency calls Information')
        self._construct = Struct('t_dur'/Int24ub,
                                 't_relcalc'/Int32ub,
                                 'pl_call'/PlCallAdapter(Int8ub),
                                 'cause'/FlagsEnum(Int8ub, powered_off=1, radio_link_error=2, user_command=5),
                                 'gcr'/BcdAdapter(Bytes(4)),
                                 'fnr'/BcdAdapter(Bytes(8)))

class EF_Shunting(TransparentEF):
    """Section 7.6"""
    def __init__(self):
        super().__init__(fid='6ff4', sfid=None, name='EF.Shunting', desc='Shunting', size={8,8})
        self._construct = Struct('common_gid'/Int8ub,
                                 'shunting_gid'/Bytes(7))

class EF_GsmrPLMN(LinFixedEF):
    """Section 7.7"""
    def __init__(self):
        super().__init__(fid='6ff5', sfid=None, name='EF.GsmrPLMN', desc='GSM-R network selection', rec_len={9,9})
        self._construct = Struct('plmn'/BcdAdapter(Bytes(3)),
                                 'class_of_network'/BitStruct('supported'/FlagsEnum(BitsInteger(5), vbs=1, vgcs=2, emlpp=4, fn=8, eirene=16),
                                                              'preference'/BitsInteger(3)),
                                 'ic_incoming_ref_tbl'/HexAdapter(Bytes(2)),
                                 'outgoing_ref_tbl'/HexAdapter(Bytes(2)),
                                 'ic_table_ref'/HexAdapter(Bytes(1)))

class EF_IC(LinFixedEF):
    """Section 7.8"""
    def __init__(self):
        super().__init__(fid='6f8d', sfid=None, name='EF.IC', desc='International Code', rec_len={7,7})
        self._construct = Struct('next_table_type'/NextTableType,
                                 'id_of_next_table'/HexAdapter(Bytes(2)),
                                 'ic_decision_value'/BcdAdapter(Bytes(2)),
                                 'network_string_table_index'/Int8ub)

class EF_NW(LinFixedEF):
    """Section 7.9"""
    def __init__(self):
        super().__init__(fid='6f80', sfid=None, name='EF.NW', desc='Network Name', rec_len={8,8})
        self._construct = GsmString(8)

class EF_Switching(LinFixedEF):
    """Section 8.4"""
    def __init__(self, fid, name, desc):
        super().__init__(fid=fid, sfid=None, name=name, desc=desc, rec_len={6,6})
        self._construct = Struct('next_table_type'/NextTableType,
                                 'id_of_next_table'/HexAdapter(Bytes(2)),
                                 'decision_value'/BcdAdapter(Bytes(2)),
                                 'string_table_index'/Int8ub)

class EF_Predefined(LinFixedEF):
    """Section 8.5"""
    def __init__(self, fid, name, desc):
        super().__init__(fid=fid, sfid=None, name=name, desc=desc, rec_len={3,3})
        # header and other records have different structure. WTF !?!
        self._construct = Struct('next_table_type'/NextTableType,
                                 'id_of_next_table'/HexAdapter(Bytes(2)),
                                 'predefined_value1'/HexAdapter(Bytes(2)),
                                 'string_table_index1'/Int8ub)
        # TODO: predefined value n, ...

class EF_DialledVals(TransparentEF):
    """Section 8.6"""
    def __init__(self, fid, name, desc):
        super().__init__(fid=fid, sfid=None, name=name, desc=desc, size={4,4})
        self._construct = Struct('next_table_type'/NextTableType,
                                 'id_of_next_table'/HexAdapter(Bytes(2)),
                                 'dialed_digits'/BcdAdapter(Bytes(1)))


class DF_EIRENE(CardDF):
    def __init__(self, fid='7fe0', name='DF.EIRENE', desc='GSM-R EIRENE'):
        super().__init__(fid=fid, name=name, desc=desc)
        files = [
            # Section 7.1.6 / Table 10 EIRENE GSM EFs
            EF_FN(),
            EF_CallconfC(),
            EF_CallconfI(),
            EF_Shunting(),
            EF_GsmrPLMN(),
            EF_IC(),
            EF_NW(),

            # support of the numbering plan
            EF_Switching(fid='6f8e', name='EF.CT', desc='Call Type'),
            EF_Switching(fid='6f8f', name='EF.SC', desc='Short Code'),
            EF_Predefined(fid='6f88', name='EF.FC', desc='Function Code'),
            EF_Predefined(fid='6f89', name='EF.Service', desc='VGCS/VBS Service Code'),
            EF_Predefined(fid='6f8a', name='EF.Call', desc='First digit of the group ID'),
            EF_Predefined(fid='6f8b', name='EF.FctTeam', desc='Call Type 6 Team Type + Team member function'),
            EF_Predefined(fid='6f92', name='EF.Controller', desc='Call Type 7 Controller function code'),
            EF_Predefined(fid='6f8c', name='EF.Gateway', desc='Access to external networks'),
            EF_DialledVals(fid='6f81', name='EF.5to8digits', desc='Call Type 2 User Identity Number length'),
            EF_DialledVals(fid='6f82', name='EF.2digits', desc='2 digits input'),
            EF_DialledVals(fid='6f83', name='EF.8digits', desc='8 digits input'),
            EF_DialledVals(fid='6f84', name='EF.9digits', desc='9 digits input'),
            EF_DialledVals(fid='6f85', name='EF.SSSSS', desc='Group call area input'),
            EF_DialledVals(fid='6f86', name='EF.LLLLL', desc='Location number Call Type 6'),
            EF_DialledVals(fid='6f91', name='EF.Location', desc='Location number Call Type 7'),
            EF_DialledVals(fid='6f87', name='EF.FreeNumber', desc='Free Number Call Type 0 and 8'),
          ]
        self.add_files(files)

    def decode_select_response(self, data_hex):
        return pySim.ts_51_011.decode_select_response(data_hex)
