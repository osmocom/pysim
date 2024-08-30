# coding=utf-8
"""APDU definitions/decoders of ETSI TS 102 222.

(C) 2022-2024 by Harald Welte <laforge@osmocom.org>

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

import logging

from construct import Struct
from osmocom.construct import *

from pySim.apdu import ApduCommand, ApduCommandSet
from pySim.ts_102_221 import FcpTemplate

logger = logging.getLogger(__name__)

# TS 102 222 Section 6.3
class CreateFile(ApduCommand, n='CREATE FILE', ins=0xE0, cla=['0X', '4X', 'EX']):
    _apdu_case = 3
    _tlv = FcpTemplate

# TS 102 222 Section 6.4
class DeleteFile(ApduCommand, n='DELETE FILE', ins=0xE4, cla=['0X', '4X']):
    _apdu_case = 3
    _construct = Struct('file_id'/Bytes(2))

# TS 102 222 Section 6.7
class TerminateDF(ApduCommand, n='TERMINATE DF', ins=0xE6, cla=['0X', '4X']):
    _apdu_case = 1

# TS 102 222 Section 6.8
class TerminateEF(ApduCommand, n='TERMINATE EF', ins=0xE8, cla=['0X', '4X']):
    _apdu_case = 1

# TS 102 222 Section 6.9
class TerminateCardUsage(ApduCommand, n='TERMINATE CARD USAGE', ins=0xFE, cla=['0X', '4X']):
    _apdu_case = 1

# TS 102 222 Section 6.10
class ResizeFile(ApduCommand, n='RESIZE FILE', ins=0xD4, cla=['8X', 'CX', 'EX']):
    _apdu_case = 3
    _construct_p1 = Enum(Byte, mode_0=0, mode_1=1)
    _tlv = FcpTemplate


ApduCommands = ApduCommandSet('TS 102 222', cmds=[CreateFile, DeleteFile, TerminateDF,
                                                  TerminateEF, TerminateCardUsage, ResizeFile])
