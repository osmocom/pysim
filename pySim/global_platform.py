# coding=utf-8
"""Partial Support for GlobalPLatform Card Spec (currently 2.1.1)

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

from typing import Optional, List, Dict, Tuple
from construct import Optional as COptional
from construct import *
from bidict import bidict
from pySim.construct import *
from pySim.utils import *
from pySim.filesystem import *
from pySim.tlv import *
from pySim.profile import CardProfile

sw_table = {
    'Warnings': {
        '6200': 'Logical Channel already closed',
        '6283': 'Card Life Cycle State is CARD_LOCKED',
        '6310': 'More data available',
    },
    'Execution errors': {
        '6400': 'No specific diagnosis',
        '6581': 'Memory failure',
    },
    'Checking errors': {
        '6700': 'Wrong length in Lc',
    },
    'Functions in CLA not supported': {
        '6881': 'Logical channel not supported or active',
        '6882': 'Secure messaging not supported',
    },
    'Command not allowed': {
        '6982': 'Security Status not satisfied',
        '6985': 'Conditions of use not satisfied',
    },
    'Wrong parameters': {
        '6a80': 'Incorrect values in command data',
        '6a81': 'Function not supported e.g. card Life Cycle State is CARD_LOCKED',
        '6a82': 'Application not found',
        '6a84': 'Not enough memory space',
        '6a86': 'Incorrect P1 P2',
        '6a88': 'Referenced data not found',
    },
    'GlobalPlatform': {
        '6d00': 'Invalid instruction',
        '6e00': 'Invalid class',
    },
    'Application errors': {
        '9484': 'Algorithm not supported',
        '9485': 'Invalid key check value',
    },
}

# GlobalPlatform 2.1.1 Section 9.1.6
KeyType = Enum(Byte,    des=0x80,
                        rsa_public_exponent_e_cleartex=0xA0,
                        rsa_modulus_n_cleartext=0xA1,
                        rsa_modulus_n=0xA2,
                        rsa_private_exponent_d=0xA3,
                        rsa_chines_remainder_p=0xA4,
                        rsa_chines_remainder_q=0xA5,
                        rsa_chines_remainder_pq=0xA6,
                        rsa_chines_remainder_dpi=0xA7,
                        rsa_chines_remainder_dqi=0xA8,
                        not_available=0xff)

# GlobalPlatform 2.1.1 Section 9.3.3.1
# example:
#   e0 48
#       c0 04 01708010
#       c0 04 02708010
#       c0 04 03708010
#       c0 04 01018010
#       c0 04 02018010
#       c0 04 03018010
#       c0 04 01028010
#       c0 04 02028010
#       c0 04 03028010
#       c0 04 01038010
#       c0 04 02038010
#       c0 04 03038010
class KeyInformationData(BER_TLV_IE, tag=0xc0):
    _construct = Struct('key_identifier'/Byte, 'key_version_number'/Byte,
                        'key_types'/GreedyRange(KeyType))
class KeyInformation(BER_TLV_IE, tag=0xe0, nested=[KeyInformationData]):
    pass

# card data sample, returned in response to GET DATA (80ca006600):
# 66 31
#    73 2f
#        06 07
#            2a864886fc6b01
#        60 0c
#            06 0a
#                2a864886fc6b02020101
#        63 09
#            06 07
#                2a864886fc6b03
#        64 0b
#            06 09
#                2a864886fc6b040215

# GlobalPlatform 2.1.1 Table F-1
class ObjectIdentifier(BER_TLV_IE, tag=0x06):
    _construct = GreedyBytes
class CardManagementTypeAndVersion(BER_TLV_IE, tag=0x60, nested=[ObjectIdentifier]):
    pass
class CardIdentificationScheme(BER_TLV_IE, tag=0x63, nested=[ObjectIdentifier]):
    pass
class SecureChannelProtocolOfISD(BER_TLV_IE, tag=0x64, nested=[ObjectIdentifier]):
    pass
class CardConfigurationDetails(BER_TLV_IE, tag=0x65):
    _construct = GreedyBytes
class CardChipDetails(BER_TLV_IE, tag=0x66):
    _construct = GreedyBytes
class CardRecognitionData(BER_TLV_IE, tag=0x73, nested=[ObjectIdentifier,
                                                        CardManagementTypeAndVersion,
                                                        CardIdentificationScheme,
                                                        SecureChannelProtocolOfISD,
                                                        CardConfigurationDetails,
                                                        CardChipDetails]):
    pass
class CardData(BER_TLV_IE, tag=0x66, nested=[CardRecognitionData]):
    pass

# GlobalPlatform 2.1.1 Table F-2
class SecureChannelProtocolOfSelectedSD(BER_TLV_IE, tag=0x64, nested=[ObjectIdentifier]):
    pass
class SecurityDomainMgmtData(BER_TLV_IE, tag=0x73, nested=[CardManagementTypeAndVersion,
                                                           CardIdentificationScheme,
                                                           SecureChannelProtocolOfSelectedSD,
                                                           CardConfigurationDetails,
                                                           CardChipDetails]):
    pass

# GlobalPlatform 2.1.1 Section 9.1.1
IsdLifeCycleState = Enum(Byte, op_ready=0x01, initialized=0x07, secured=0x0f,
                         card_locked = 0x7f, terminated=0xff)

# GlobalPlatform 2.1.1 Section 9.9.3.1
class ApplicationID(BER_TLV_IE, tag=0x84):
    _construct = GreedyBytes

# GlobalPlatform 2.1.1 Section 9.9.3.1
class SecurityDomainManagementData(BER_TLV_IE, tag=0x73):
    _construct = GreedyBytes

# GlobalPlatform 2.1.1 Section 9.9.3.1
class ApplicationProductionLifeCycleData(BER_TLV_IE, tag=0x9f6e):
    _construct = GreedyBytes

# GlobalPlatform 2.1.1 Section 9.9.3.1
class MaximumLengthOfDataFieldInCommandMessage(BER_TLV_IE, tag=0x9f65):
    _construct = GreedyInteger()

# GlobalPlatform 2.1.1 Section 9.9.3.1
class ProprietaryData(BER_TLV_IE, tag=0xA5, nested=[SecurityDomainManagementData,
                                                    ApplicationProductionLifeCycleData,
                                                    MaximumLengthOfDataFieldInCommandMessage]):
    pass

# GlobalPlatform 2.1.1 Section 9.9.3.1
class FciTemplate(BER_TLV_IE, tag=0x6f, nested=[ApplicationID, SecurityDomainManagementData,
                                                ApplicationProductionLifeCycleData,
                                                MaximumLengthOfDataFieldInCommandMessage,
                                                ProprietaryData]):
    pass

class IssuerIdentificationNumber(BER_TLV_IE, tag=0x42):
    _construct = BcdAdapter(GreedyBytes)

class CardImageNumber(BER_TLV_IE, tag=0x45):
    _construct = BcdAdapter(GreedyBytes)

class SequenceCounterOfDefaultKvn(BER_TLV_IE, tag=0xc1):
    _construct = GreedyInteger()

class ConfirmationCounter(BER_TLV_IE, tag=0xc2):
    _construct = GreedyInteger()

# Collection of all the data objects we can get from GET DATA
class DataCollection(TLV_IE_Collection, nested=[IssuerIdentificationNumber,
                                                CardImageNumber,
                                                CardData,
                                                KeyInformation,
                                                SequenceCounterOfDefaultKvn,
                                                ConfirmationCounter]):
    pass

def decode_select_response(resp_hex: str) -> object:
    t = FciTemplate()
    t.from_tlv(h2b(resp_hex))
    d = t.to_dict()
    return flatten_dict_lists(d['fci_template'])

# Application Dedicated File of a Security Domain
class ADF_SD(CardADF):
    def __init__(self, aid: str, name: str, desc: str):
        super().__init__(aid=aid, fid=None, sfid=None, name=name, desc=desc)
        self.shell_commands += [self.AddlShellCommands()]

    @staticmethod
    def decode_select_response(res_hex: str) -> object:
        return decode_select_response(res_hex)

    @with_default_category('Application-Specific Commands')
    class AddlShellCommands(CommandSet):
        def __init__(self):
            super().__init__()

        def do_get_data(self, opts):
            tlv_cls_name = opts.arg_list[0]
            tlv_cls = DataCollection().members_by_name[tlv_cls_name]
            (data, sw) = self._cmd.card._scc.get_data(cla=0x80, tag=tlv_cls.tag)
            ie = tlv_cls()
            ie.from_tlv(h2b(data))
            self._cmd.poutput_json(ie.to_dict())

        def complete_get_data(self, text, line, begidx, endidx) -> List[str]:
            #data_dict = {camel_to_snake(str(x.__name__)): x for x in DataCollection.possible_nested}
            data_dict = {str(x.__name__): x for x in DataCollection.possible_nested}
            index_dict = {1: data_dict}
            return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

# Card Application of a Security Domain
class CardApplicationSD(CardApplication):
    def __init__(self, aid: str, name: str, desc: str):
        super().__init__(name, adf=ADF_SD(aid, name, desc), sw=sw_table)

# Card Application of Issuer Security Domain
class CardApplicationISD(CardApplicationSD):
    # FIXME: ISD AID is not static, but could be different. One can select the empty
    # application using '00a4040000' and then parse the response FCI to get the ISD AID
    def __init__(self, aid='a000000003000000'):
        super().__init__(aid=aid, name='ADF.ISD', desc='Issuer Security Domain')

#class CardProfileGlobalPlatform(CardProfile):
#    ORDER = 23
#
#    def __init__(self, name='GlobalPlatform'):
#        super().__init__(name, desc='GlobalPlatfomr 2.1.1', cla=['00','80','84'], sw=sw_table)
