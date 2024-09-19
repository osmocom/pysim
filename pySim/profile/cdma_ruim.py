# coding=utf-8
"""R-UIM (Removable User Identity Module) card profile (see 3GPP2 C.S0023-D)

(C) 2023 by Vadim Yanitskiy <fixeria@osmocom.org>

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

import enum

from construct import Bytewise, BitStruct, BitsInteger, Struct, FlagsEnum
from osmocom.utils import *
from osmocom.construct import *

from pySim.filesystem import *
from pySim.profile import CardProfile, CardProfileAddon
from pySim.ts_51_011 import CardProfileSIM
from pySim.ts_51_011 import DF_TELECOM, DF_GSM
from pySim.ts_51_011 import EF_ServiceTable


# Mapping between CDMA Service Number and its description
EF_CST_map = {
    1 : 'CHV disable function',
    2 : 'Abbreviated Dialing Numbers (ADN)',
    3 : 'Fixed Dialing Numbers (FDN)',
    4 : 'Short Message Storage (SMS)',
    5 : 'HRPD',
    6 : 'Enhanced Phone Book',
    7 : 'Multi Media Domain (MMD)',
    8 : 'SF_EUIMID-based EUIMID',
    9 : 'MEID Support',
    10 : 'Extension1',
    11 : 'Extension2',
    12 : 'SMS Parameters',
    13 : 'Last Number Dialled (LND)',
    14 : 'Service Category Program for BC-SMS',
    15 : 'Messaging and 3GPD Extensions',
    16 : 'Root Certificates',
    17 : 'CDMA Home Service Provider Name',
    18 : 'Service Dialing Numbers (SDN)',
    19 : 'Extension3',
    20 : '3GPD-SIP',
    21 : 'WAP Browser',
    22 : 'Java',
    23 : 'Reserved for CDG',
    24 : 'Reserved for CDG',
    25 : 'Data Download via SMS Broadcast',
    26 : 'Data Download via SMS-PP',
    27 : 'Menu Selection',
    28 : 'Call Control',
    29 : 'Proactive R-UIM',
    30 : 'AKA',
    31 : 'IPv6',
    32 : 'RFU',
    33 : 'RFU',
    34 : 'RFU',
    35 : 'RFU',
    36 : 'RFU',
    37 : 'RFU',
    38 : '3GPD-MIP',
    39 : 'BCMCS',
    40 : 'Multimedia Messaging Service (MMS)',
    41 : 'Extension 8',
    42 : 'MMS User Connectivity Parameters',
    43 : 'Application Authentication',
    44 : 'Group Identifier Level 1',
    45 : 'Group Identifier Level 2',
    46 : 'De-Personalization Control Keys',
    47 : 'Cooperative Network List',
}


######################################################################
# DF.CDMA
######################################################################

class EF_SPN(TransparentEF):
    '''3.4.31 CDMA Home Service Provider Name'''

    _test_de_encode = [
        ( "010801536b796c696e6b204e57ffffffffffffffffffffffffffffffffffffffffffff",
          { 'rfu1' : 0, 'show_in_hsa' : True, 'rfu2' : 0,
            'char_encoding' : 8, 'lang_ind' : 1, 'spn' : 'Skylink NW' } ),
    ]

    def __init__(self, fid='6f41', sfid=None, name='EF.SPN',
                 desc='Service Provider Name', size=(35, 35), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = BitStruct(
            # Byte 1: Display Condition
            'rfu1'/BitsRFU(7),
            'show_in_hsa'/Flag,
            # Byte 2: Character Encoding
            'rfu2'/BitsRFU(3),
            'char_encoding'/BitsInteger(5), # see C.R1001-G
            # Byte 3: Language Indicator
            'lang_ind'/BitsInteger(8), # see C.R1001-G
            # Bytes 4-35: Service Provider Name
            'spn'/Bytewise(GsmString(32))
        )

class EF_AD(TransparentEF):
    '''3.4.33 Administrative Data'''

    _test_de_encode = [
        ( "000000", { 'ms_operation_mode' : 'normal', 'additional_info' : '0000', 'rfu' : '' } ),
    ]
    _test_no_pad = True

    class OP_MODE(enum.IntEnum):
        normal = 0x00
        type_approval = 0x80
        normal_and_specific_facilities = 0x01
        type_approval_and_specific_facilities = 0x81
        maintenance_off_line = 0x02
        cell_test = 0x04

    def __init__(self, fid='6f43', sfid=None, name='EF.AD',
                 desc='Service Provider Name', size=(3, None), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct(
            # Byte 1: Display Condition
            'ms_operation_mode'/Enum(Byte, self.OP_MODE),
            # Bytes 2-3: Additional information
            'additional_info'/HexAdapter(Bytes(2)),
            # Bytes 4..: RFU
            'rfu'/HexAdapter(GreedyBytesRFU),
        )


class EF_SMS(LinFixedEF):
    '''3.4.27 Short Messages'''
    def __init__(self, fid='6f3c', sfid=None, name='EF.SMS', desc='Short messages', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=(2, 255), **kwargs)
        self._construct = Struct(
            # Byte 1: Status
            'status'/BitStruct(
                'rfu87'/BitsRFU(2),
                'protection'/Flag,
                'rfu54'/BitsRFU(2),
                'status'/FlagsEnum(BitsInteger(2), read=0, to_be_read=1, sent=2, to_be_sent=3),
                'used'/Flag,
            ),
            # Byte 2: Length
            'length'/Int8ub,
            # Bytes 3..: SMS Transport Layer Message
            'tpdu'/Bytes(lambda ctx: ctx.length if ctx.status.used else 0),
        )


class DF_CDMA(CardDF):
    def __init__(self):
        super().__init__(fid='7f25', name='DF.CDMA',
                         desc='CDMA related files (3GPP2 C.S0023-D)')
        files = [
            # TODO: lots of other files
            EF_ServiceTable('6f32', None, 'EF.CST',
                            'CDMA Service Table', table=EF_CST_map, size=(5, 16)),
            EF_SPN(),
            EF_AD(),
            EF_SMS(),
        ]
        self.add_files(files)


class CardProfileRUIM(CardProfile):
    '''R-UIM card profile as per 3GPP2 C.S0023-D'''

    ORDER = 20

    def __init__(self):
        super().__init__('R-UIM', desc='CDMA R-UIM Card', cla="a0",
                         sel_ctrl="0000", files_in_mf=[DF_TELECOM(), DF_GSM(), DF_CDMA()])

    @staticmethod
    def decode_select_response(data_hex: str) -> object:
        # TODO: Response parameters/data in case of DF_CDMA (section 2.6)
        return CardProfileSIM.decode_select_response(data_hex)

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        """ Try to access MF/DF.CDMA via 2G APDUs (3GPP TS 11.11), if this works,
        the card is considered an R-UIM card for CDMA."""
        cls._mf_select_test(scc, "a0", "0000", ["3f00", "7f25"])


class AddonRUIM(CardProfileAddon):
    """An Addon that can be found on on a combined SIM + RUIM or UICC + RUIM to support CDMA."""
    def __init__(self):
        files = [
            DF_CDMA()
        ]
        super().__init__('RUIM', desc='CDMA RUIM', files_in_mf=files)

    def probe(self, card: 'CardBase') -> bool:
        return card.file_exists(self.files_in_mf[0].fid)
