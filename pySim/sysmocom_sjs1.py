# coding=utf-8
"""Utilities / Functions related to sysmocom sysmoUSIM-SJS1 cards

(C) 2026 by sysmocom - s.f.m.c. GmbH
All Rights Reserved

Author: Eric Wild <ewild@sysmocom.de>

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

from construct import Struct, Bytes, Flag
from osmocom.utils import *
from osmocom.construct import *

from pySim.filesystem import *
from pySim.runtime import RuntimeState


class EF_Ki(TransparentEF):
    _test_de_encode = [
        ('000102030405060708090a0b0c0d0e0f',
         {'key': h2b('000102030405060708090a0b0c0d0e0f')}),
    ]

    def __init__(self, fid='00ff', name='EF.Ki'):
        super().__init__(fid, name=name, desc='K/Ki authentication key', size=(16, 16))
        self._construct = Struct('key'/Bytes(16))


class EF_OPc(TransparentEF):
    _test_de_encode = [
        ('016ca53d7a0a804561646816d7b0c702fb',
         {'use_opc_instead_of_op': True, 'op_opc': h2b('6ca53d7a0a804561646816d7b0c702fb')}),
    ]

    def __init__(self, fid='00f7', name='EF.OPc'):
        super().__init__(fid, name=name, desc='OP/OPc for milenage', size=(17, 17))
        self._construct = Struct('use_opc_instead_of_op'/Flag, 'op_opc'/Bytes(16))


class SysmoUSIMSJS1(CardModel):
    _atrs = ["3b9f96801fc78031a073be21136743200718000001a5"]

    @classmethod
    def add_files(cls, rs: RuntimeState):
        """Add sysmoUSIM-SJS1 specific files to given RuntimeState."""
        # the key material lives in DF.GSM shared with ADF.USIM
        if '7f20' in rs.mf.children:
            rs.mf.children['7f20'].add_files([EF_Ki(), EF_OPc()])
