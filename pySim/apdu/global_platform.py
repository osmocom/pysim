# coding=utf-8
"""APDU definition/decoder of GlobalPLatform Card Spec (currently 2.1.1)

(C) 2022 by Harald Welte <laforge@osmocom.org>

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

from pySim.apdu import ApduCommand, ApduCommandSet

class GpDelete(ApduCommand, n='DELETE', ins=0xE4, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpStoreData(ApduCommand, n='STORE DATA', ins=0xE2, cla=['8X', 'CX', 'EX']):
    @classmethod
    def _get_apdu_case(cls, hdr:bytes) -> int:
        p1 = hdr[2]
        if p1 & 0x01:
            return 4
        else:
            return 3

class GpGetDataCA(ApduCommand, n='GET DATA', ins=0xCA, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpGetDataCB(ApduCommand, n='GET DATA', ins=0xCB, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpGetStatus(ApduCommand, n='GET STATUS', ins=0xF2, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpInstall(ApduCommand, n='INSTALL', ins=0xE6, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpLoad(ApduCommand, n='LOAD', ins=0xE8, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpPutKey(ApduCommand, n='PUT KEY', ins=0xD8, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpSetStatus(ApduCommand, n='SET STATUS', ins=0xF0, cla=['8X', 'CX', 'EX']):
    _apdu_case = 3

ApduCommands = ApduCommandSet('GlobalPlatform v2.3.1', cmds=[GpDelete, GpStoreData,
                              GpGetDataCA, GpGetDataCB, GpGetStatus, GpInstall,
                              GpLoad, GpPutKey, GpSetStatus])
