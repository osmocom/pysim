# coding=utf-8
"""APDU definition/decoder of GlobalPLatform Card Spec (currently 2.1.1)

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

from construct import FlagsEnum, Struct
from osmocom.tlv import flatten_dict_lists
from osmocom.construct import *
from pySim.apdu import ApduCommand, ApduCommandSet
from pySim.global_platform import InstallParameters

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

# GPCS Section 11.5.2
class GpInstall(ApduCommand, n='INSTALL', ins=0xE6, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4
    _construct_p1 = FlagsEnum(Byte, more_commands=0x80, for_registry_update=0x40,
                              for_personalization=0x20, for_extradition=0x10,
                              for_make_selectable=0x08, for_install=0x04, for_load=0x02)
    _construct_p2 = Enum(Byte, no_info_provided=0x00, beginning_of_combined=0x01,
                         end_of_combined=0x03)
    _construct = Struct('load_file_aid'/Prefixed(Int8ub, GreedyBytes),
                        'module_aid'/Prefixed(Int8ub, GreedyBytes),
                        'application_aid'/Prefixed(Int8ub, GreedyBytes),
                        'privileges'/Prefixed(Int8ub, GreedyBytes),
                        'install_parameters'/Prefixed(Int8ub, GreedyBytes), # TODO: InstallParameters
                        'install_token'/Prefixed(Int8ub, GreedyBytes))
    def _decode_cmd(self):
        # first use _construct* above
        res = self._cmd_to_dict()
        # then do TLV decode of install_parameters
        ip = InstallParameters()
        ip.from_tlv(res['body']['install_parameters'])
        res['body']['install_parameters'] = flatten_dict_lists(ip.to_dict())
        return res


class GpLoad(ApduCommand, n='LOAD', ins=0xE8, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpPutKey(ApduCommand, n='PUT KEY', ins=0xD8, cla=['8X', 'CX', 'EX']):
    _apdu_case = 4

class GpSetStatus(ApduCommand, n='SET STATUS', ins=0xF0, cla=['8X', 'CX', 'EX']):
    _apdu_case = 3

ApduCommands = ApduCommandSet('GlobalPlatform v2.3.1', cmds=[GpDelete, GpStoreData,
                              GpGetDataCA, GpGetDataCB, GpGetStatus, GpInstall,
                              GpLoad, GpPutKey, GpSetStatus])
