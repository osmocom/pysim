# -*- coding: utf-8 -*-

# without this, pylint will fail when inner classes are used
# within the 'nested' kwarg of our TlvMeta metaclass on python 3.7 :(
# pylint: disable=undefined-variable

"""
Various constants from 3GPP TS 31.102 V16.6.0
"""

#
# Copyright (C) 2020 Supreeth Herle <herlesupreeth@gmail.com>
# Copyright (C) 2021-2022 Harald Welte <laforge@osmocom.org>
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
import pySim.ts_102_221
from pySim.ts_51_011 import EF_ACMmax, EF_AAeM, EF_eMLPP, EF_CMI, EF_PNN
from pySim.ts_51_011 import EF_MMSN, EF_MMSICP, EF_MMSUP, EF_MMSUCP, EF_VGCS, EF_VGCSS, EF_NIA
from pySim.ts_51_011 import EF_SMSR, EF_DCK, EF_EXT, EF_CNL, EF_OPL, EF_MBI, EF_MWIS
from pySim.ts_51_011 import EF_CBMID, EF_CBMIR, EF_ADN, EF_SMS, EF_MSISDN, EF_SMSP, EF_SMSS
from pySim.ts_51_011 import EF_IMSI, EF_xPLMNwAcT, EF_SPN, EF_CBMI, EF_ACC, EF_PLMNsel
from pySim.ts_51_011 import EF_Kc, EF_CPBCCH, EF_InvScan
from pySim.ts_102_221 import EF_ARR
from pySim.tlv import *
from pySim.filesystem import *
from pySim.ts_31_102_telecom import DF_PHONEBOOK, EF_UServiceTable
from pySim.construct import *
from construct import Optional as COptional
from construct import *
from typing import Tuple
from struct import unpack, pack
import enum
EF_UST_map = {
    1: 'Local Phone Book',
    2: 'Fixed Dialling Numbers (FDN)',
    3: 'Extension 2',
    4: 'Service Dialling Numbers (SDN)',
    5: 'Extension3',
    6: 'Barred Dialling Numbers (BDN)',
    7: 'Extension4',
    8: 'Outgoing Call Information (OCI and OCT)',
    9: 'Incoming Call Information (ICI and ICT)',
    10: 'Short Message Storage (SMS)',
    11: 'Short Message Status Reports (SMSR)',
    12: 'Short Message Service Parameters (SMSP)',
    13: 'Advice of Charge (AoC)',
    14: 'Capability Configuration Parameters 2 (CCP2)',
    15: 'Cell Broadcast Message Identifier',
    16: 'Cell Broadcast Message Identifier Ranges',
    17: 'Group Identifier Level 1',
    18: 'Group Identifier Level 2',
    19: 'Service Provider Name',
    20: 'User controlled PLMN selector with Access Technology',
    21: 'MSISDN',
    22: 'Image (IMG)',
    23: 'Support of Localised Service Areas (SoLSA)',
    24: 'Enhanced Multi-Level Precedence and Pre-emption Service',
    25: 'Automatic Answer for eMLPP',
    26: 'RFU',
    27: 'GSM Access',
    28: 'Data download via SMS-PP',
    29: 'Data download via SMS-CB',
    30: 'Call Control by USIM',
    31: 'MO-SMS Control by USIM',
    32: 'RUN AT COMMAND command',
    33: 'shall be set to 1',
    34: 'Enabled Services Table',
    35: 'APN Control List (ACL)',
    36: 'Depersonalisation Control Keys',
    37: 'Co-operative Network List',
    38: 'GSM security context',
    39: 'CPBCCH Information',
    40: 'Investigation Scan',
    41: 'MexE',
    42: 'Operator controlled PLMN selector with Access Technology',
    43: 'HPLMN selector with Access Technology',
    44: 'Extension 5',
    45: 'PLMN Network Name',
    46: 'Operator PLMN List',
    47: 'Mailbox Dialling Numbers',
    48: 'Message Waiting Indication Status',
    49: 'Call Forwarding Indication Status',
    50: 'Reserved and shall be ignored',
    51: 'Service Provider Display Information',
    52: 'Multimedia Messaging Service (MMS)',
    53: 'Extension 8',
    54: 'Call control on GPRS by USIM',
    55: 'MMS User Connectivity Parameters',
    56: 'Network\'s indication of alerting in the MS (NIA)',
    57: 'VGCS Group Identifier List (EFVGCS and EFVGCSS)',
    58: 'VBS Group Identifier List (EFVBS and EFVBSS)',
    59: 'Pseudonym',
    60: 'User Controlled PLMN selector for I-WLAN access',
    61: 'Operator Controlled PLMN selector for I-WLAN access',
    62: 'User controlled WSID list',
    63: 'Operator controlled WSID list',
    64: 'VGCS security',
    65: 'VBS security',
    66: 'WLAN Reauthentication Identity',
    67: 'Multimedia Messages Storage',
    68: 'Generic Bootstrapping Architecture (GBA)',
    69: 'MBMS security',
    70: 'Data download via USSD and USSD application mode',
    71: 'Equivalent HPLMN',
    72: 'Additional TERMINAL PROFILE after UICC activation',
    73: 'Equivalent HPLMN Presentation Indication',
    74: 'Last RPLMN Selection Indication',
    75: 'OMA BCAST Smart Card Profile',
    76: 'GBA-based Local Key Establishment Mechanism',
    77: 'Terminal Applications',
    78: 'Service Provider Name Icon',
    79: 'PLMN Network Name Icon',
    80: 'Connectivity Parameters for USIM IP connections',
    81: 'Home I-WLAN Specific Identifier List',
    82: 'I-WLAN Equivalent HPLMN Presentation Indication',
    83: 'I-WLAN HPLMN Priority Indication',
    84: 'I-WLAN Last Registered PLMN',
    85: 'EPS Mobility Management Information',
    86: 'Allowed CSG Lists and corresponding indications',
    87: 'Call control on EPS PDN connection by USIM',
    88: 'HPLMN Direct Access',
    89: 'eCall Data',
    90: 'Operator CSG Lists and corresponding indications',
    91: 'Support for SM-over-IP',
    92: 'Support of CSG Display Control',
    93: 'Communication Control for IMS by USIM',
    94: 'Extended Terminal Applications',
    95: 'Support of UICC access to IMS',
    96: 'Non-Access Stratum configuration by USIM',
    97: 'PWS configuration by USIM',
    98: 'RFU',
    99: 'URI support by UICC',
    100: 'Extended EARFCN support',
    101: 'ProSe',
    102: 'USAT Application Pairing',
    103: 'Media Type support',
    104: 'IMS call disconnection cause',
    105: 'URI support for MO SHORT MESSAGE CONTROL',
    106: 'ePDG configuration Information support',
    107: 'ePDG configuration Information configured',
    108: 'ACDC support',
    109: 'MCPTT',
    110: 'ePDG configuration Information for Emergency Service support',
    111: 'ePDG configuration Information for Emergency Service configured',
    112: 'eCall Data over IMS',
    113: 'URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111 [12]',
    114: 'From Preferred',
    115: 'IMS configuration data',
    116: 'TV configuration',
    117: '3GPP PS Data Off',
    118: '3GPP PS Data Off Service List',
    119: 'V2X',
    120: 'XCAP Configuration Data',
    121: 'EARFCN list for MTC/NB-IOT UEs',
    122: '5GS Mobility Management Information',
    123: '5G Security Parameters',
    124: 'Subscription identifier privacy support',
    125: 'SUCI calculation by the USIM',
    126: 'UAC Access Identities support',
    127: 'Expect control plane-based Steering of Roaming information during initial registration in VPLMN',
    128: 'Call control on PDU Session by USIM',
    129: '5GS Operator PLMN List',
    130: 'Support for SUPI of type NSI or GLI or GCI',
    131: '3GPP PS Data Off separate Home and Roaming lists',
    132: 'Support for URSP by USIM',
    133: '5G Security Parameters extended',
    134: 'MuD and MiD configuration data',
    135: 'Support for Trusted non-3GPP access networks by USIM'
}

# Mapping between USIM Enbled Service Number and its description
EF_EST_map = {
    1: 'Fixed Dialling Numbers (FDN)',
    2: 'Barred Dialling Numbers (BDN)',
    3: 'APN Control List (ACL)'
}

LOCI_STATUS_map = {
    0:	'updated',
    1:	'not updated',
    2:	'plmn not allowed',
    3:	'locatation area not allowed'
}

EF_USIM_ADF_map = {
    'LI': '6F05',
    'ARR': '6F06',
    'IMSI': '6F07',
    'Keys': '6F08',
    'KeysPS': '6F09',
    'DCK': '6F2C',
    'HPPLMN': '6F31',
    'CNL': '6F32',
    'ACMmax': '6F37',
    'UST': '6F38',
    'ACM': '6F39',
    'FDN': '6F3B',
    'SMS': '6F3C',
    'GID1': '6F3E',
    'GID2': '6F3F',
    'MSISDN': '6F40',
    'PUCT': '6F41',
    'SMSP': '6F42',
    'SMSS': '6F42',
    'CBMI': '6F45',
    'SPN': '6F46',
    'SMSR': '6F47',
    'CBMID': '6F48',
    'SDN': '6F49',
    'EXT2': '6F4B',
    'EXT3': '6F4C',
    'BDN': '6F4D',
    'EXT5': '6F4E',
    'CCP2': '6F4F',
    'CBMIR': '6F50',
    'EXT4': '6F55',
    'EST': '6F56',
    'ACL': '6F57',
    'CMI': '6F58',
    'START-HFN': '6F5B',
    'THRESHOLD': '6F5C',
    'PLMNwAcT': '6F60',
    'OPLMNwAcT': '6F61',
    'HPLMNwAcT': '6F62',
    'PSLOCI': '6F73',
    'ACC': '6F78',
    'FPLMN': '6F7B',
    'LOCI': '6F7E',
    'ICI': '6F80',
    'OCI': '6F81',
    'ICT': '6F82',
    'OCT': '6F83',
    'AD': '6FAD',
    'VGCS': '6FB1',
    'VGCSS': '6FB2',
    'VBS': '6FB3',
    'VBSS': '6FB4',
    'eMLPP': '6FB5',
    'AAeM': '6FB6',
    'ECC': '6FB7',
    'Hiddenkey': '6FC3',
    'NETPAR': '6FC4',
    'PNN': '6FC5',
    'OPL': '6FC6',
    'MBDN': '6FC7',
    'EXT6': '6FC8',
    'MBI': '6FC9',
    'MWIS': '6FCA',
    'CFIS': '6FCB',
    'EXT7': '6FCC',
    'SPDI': '6FCD',
    'MMSN': '6FCE',
    'EXT8': '6FCF',
    'MMSICP': '6FD0',
    'MMSUP': '6FD1',
    'MMSUCP': '6FD2',
    'NIA': '6FD3',
    'VGCSCA': '6FD4',
    'VBSCA': '6FD5',
    'GBAP': '6FD6',
    'MSK': '6FD7',
    'MUK': '6FD8',
    'EHPLMN': '6FD9',
    'GBANL': '6FDA',
    'EHPLMNPI': '6FDB',
    'LRPLMNSI': '6FDC',
    'NAFKCA': '6FDD',
    'SPNI': '6FDE',
    'PNNI': '6FDF',
    'NCP-IP': '6FE2',
    'EPSLOCI': '6FE3',
    'EPSNSC': '6FE4',
    'UFC': '6FE6',
    'UICCIARI': '6FE7',
    'NASCONFIG': '6FE8',
    'PWC': '6FEC',
    'FDNURI': '6FED',
    'BDNURI': '6FEE',
    'SDNURI': '6FEF',
    'IWL': '6FF0',
    'IPS': '6FF1',
    'IPD': '6FF2',
    'ePDGId': '6FF3',
    'ePDGSelection': '6FF4',
    'ePDGIdEm': '6FF5',
    'ePDGSelectionEm': '6FF6',
}

# 3gPP TS 31.102 Section 7.5.2.1
class SUCI_TlvDataObject(BER_TLV_IE, tag=0xA1):
    _construct = HexAdapter(GreedyBytes)

######################################################################
# ADF.USIM
######################################################################


# 3GPP TS 31.102 Section 4.4.11.4 (EF_5GS3GPPNSC)
class EF_5GS3GPPNSC(LinFixedEF):
    class NgKSI(BER_TLV_IE, tag=0x80):
        _construct = Int8ub

    class K_AMF(BER_TLV_IE, tag=0x81):
        _construct = HexAdapter(Bytes(32))

    class UplinkNASCount(BER_TLV_IE, tag=0x82):
        _construct = Int32ub

    class DownlinkNASCount(BER_TLV_IE, tag=0x83):
        _construct = Int32ub

    class IdsOfSelectedNasAlgos(BER_TLV_IE, tag=0x84):
        # 3GPP TS 24.501 Section 9.11.3.34
        _construct = BitStruct('ciphering'/Nibble, 'integrity'/Nibble)

    class IdsOfSelectedEpsAlgos(BER_TLV_IE, tag=0x85):
        # 3GPP TS 24.301 Section 9.9.3.23
        _construct = BitStruct('ciphering'/Nibble, 'integrity'/Nibble)

    class FiveGSNasSecurityContext(BER_TLV_IE, tag=0xA0,
                                   nested=[NgKSI, K_AMF, UplinkNASCount,
                                           DownlinkNASCount, IdsOfSelectedNasAlgos,
                                           IdsOfSelectedEpsAlgos]):
        pass

    def __init__(self, fid="4f03", sfid=0x03, name='EF.5GS3GPPNSC', rec_len=(57, None),
                 desc='5GS 3GPP Access NAS Security Context', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._tlv = EF_5GS3GPPNSC.FiveGSNasSecurityContext

# 3GPP TS 31.102 Section 4.4.11.6
class EF_5GAUTHKEYS(TransparentEF):
    class K_AUSF(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(GreedyBytes)

    class K_SEAF(BER_TLV_IE, tag=0x81):
        _construct = HexAdapter(GreedyBytes)

    class FiveGAuthKeys(TLV_IE_Collection, nested=[K_AUSF, K_SEAF]):
        pass

    def __init__(self, fid='4f05', sfid=0x05, name='EF.5GAUTHKEYS', size=(68, None),
                 desc='5G authentication keys', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._tlv = EF_5GAUTHKEYS.FiveGAuthKeys

# 3GPP TS 31.102 Section 4.4.11.8
class ProtSchemeIdList(BER_TLV_IE, tag=0xa0):
    # FIXME: 3GPP TS 24.501 Protection Scheme Identifier
    # repeated sequence of (id, index) tuples
    _construct = GreedyRange(
        Struct('id'/Enum(Byte, null=0, A=1, B=2), 'index'/Int8ub))


class HomeNetPubKeyId(BER_TLV_IE, tag=0x80):
    # 3GPP TS 24.501 / 3GPP TS 23.003
    _construct = Int8ub


class HomeNetPubKey(BER_TLV_IE, tag=0x81):
    # FIXME: RFC 5480
    _construct = HexAdapter(GreedyBytes)


class HomeNetPubKeyList(BER_TLV_IE, tag=0xa1,
                        nested=[HomeNetPubKeyId, HomeNetPubKey]):
    pass

# 3GPP TS 31.102 Section 4.4.11.6
class SUCI_CalcInfo(TLV_IE_Collection, nested=[ProtSchemeIdList, HomeNetPubKeyList]):
    pass


# TS 31.102 4.4.11.8
class EF_SUCI_Calc_Info(TransparentEF):
    def __init__(self, fid="4f07", sfid=0x07, name='EF.SUCI_Calc_Info', size=(2, None),
                 desc='SUCI Calc Info', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)

    def _encode_prot_scheme_id_list(self, in_list):
        out_bytes = [0xa0]
        out_bytes.append(len(in_list)*2)  # two byte per entry

        # position in list determines priority; high-priority items (low index) come first
        for scheme in sorted(in_list, key=lambda item: item["priority"]):
            out_bytes.append(scheme["identifier"])
            out_bytes.append(scheme["key_index"])

        return out_bytes

    def _encode_hnet_pubkey_list(self, hnet_pubkey_list):
        out_bytes = [0xa1]  # pubkey list tag
        out_bytes.append(0x00)  # length filled later
        length = 0

        for key in hnet_pubkey_list:
            out_bytes.append(0x80)  # identifier tag
            out_bytes.append(0x01)  # TODO size, fixed to 1 byte
            out_bytes.append(key["hnet_pubkey_identifier"])
            out_bytes.append(0x81)  # key tag
            out_bytes.append(len(key["hnet_pubkey"])//2)
            length += 5+len(key["hnet_pubkey"])//2

            pubkey_bytes = h2b(key["hnet_pubkey"])
            out_bytes += pubkey_bytes

        # fill length
        out_bytes[1] = length
        return out_bytes

    def _encode_hex(self, in_json):
        out_bytes = self._encode_prot_scheme_id_list(
            in_json['prot_scheme_id_list'])
        out_bytes += self._encode_hnet_pubkey_list(in_json['hnet_pubkey_list'])
        return "".join(["%02X" % i for i in out_bytes])

    def _decode_prot_scheme_id_list(self, in_bytes):
        prot_scheme_id_list = []
        pos = 0
        # two bytes per entry
        while pos < len(in_bytes):
            prot_scheme = {
                'priority':   pos//2,  # first in list: high priority
                'identifier': in_bytes[pos],
                'key_index':  in_bytes[pos+1]
            }
            pos += 2
            prot_scheme_id_list.append(prot_scheme)
        return prot_scheme_id_list

    def _decode_hnet_pubkey_list(self, in_bytes):
        hnet_pubkey_list = []
        pos = 0
        if in_bytes[pos] != 0xa1:
            print("missing Home Network Public Key List data object")
            return {}
        pos += 1
        hnet_pubkey_list_len = in_bytes[pos]
        pos += 1

        while pos < hnet_pubkey_list_len:
            if in_bytes[pos] != 0x80:
                print("missing Home Network Public Key Identifier tag")
                return {}
            pos += 1
            # TODO might be more than 1 byte?
            hnet_pubkey_id_len = in_bytes[pos]
            pos += 1
            hnet_pubkey_id = in_bytes[pos:pos+hnet_pubkey_id_len][0]
            pos += hnet_pubkey_id_len
            if in_bytes[pos] != 0x81:
                print("missing Home Network Public Key tag")
                return {}
            pos += 1
            hnet_pubkey_len = in_bytes[pos]
            pos += 1
            hnet_pubkey = in_bytes[pos:pos+hnet_pubkey_len]
            pos += hnet_pubkey_len

            hnet_pubkey_list.append({
                'hnet_pubkey_identifier': hnet_pubkey_id,
                'hnet_pubkey':            b2h(hnet_pubkey)
            })

        return hnet_pubkey_list

    def _decode_bin(self, in_bin):
        return self._decode_hex(b2h(in_bin))

    def _decode_hex(self, in_hex):
        in_bytes = h2b(in_hex)
        pos = 0

        if in_bytes[pos] != 0xa0:
            print("missing Protection Scheme Identifier List data object tag")
            return {}
        pos += 1

        prot_scheme_id_list_len = in_bytes[pos]  # TODO maybe more than 1 byte
        pos += 1
        # decode Protection Scheme Identifier List data object
        prot_scheme_id_list = self._decode_prot_scheme_id_list(
            in_bytes[pos:pos+prot_scheme_id_list_len])
        pos += prot_scheme_id_list_len

        # remaining data holds Home Network Public Key Data Object
        hnet_pubkey_list = self._decode_hnet_pubkey_list(in_bytes[pos:])

        return {
            'prot_scheme_id_list': prot_scheme_id_list,
            'hnet_pubkey_list':    hnet_pubkey_list
        }

    def _encode_bin(self, in_json):
        return h2b(self._encode_hex(in_json))


class EF_LI(TransRecEF):
    def __init__(self, fid='6f05', sfid=None, name='EF.LI', size=(2, None), rec_len=2,
                 desc='Language Indication'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)

    def _decode_record_bin(self, in_bin):
        if in_bin == b'\xff\xff':
            return None
        else:
            # officially this is 7-bit GSM alphabet with one padding bit in each byte
            return in_bin.decode('ascii')

    def _encode_record_bin(self, in_json):
        if in_json == None:
            return b'\xff\xff'
        else:
            # officially this is 7-bit GSM alphabet with one padding bit in each byte
            return in_json.encode('ascii')


class EF_Keys(TransparentEF):
    def __init__(self, fid='6f08', sfid=0x08, name='EF.Keys', size=(33, 33),
                 desc='Ciphering and Integrity Keys'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct(
            'ksi'/Int8ub, 'ck'/HexAdapter(Bytes(16)), 'ik'/HexAdapter(Bytes(16)))

# TS 31.102 Section 4.2.6
class EF_HPPLMN(TransparentEF):
    def __init__(self, fid='6f31', sfid=0x12, name='EF.HPPLMN', size=(1, 1),
                 desc='Higher Priority PLMN search period'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Int8ub

class EF_UST(EF_UServiceTable):
    def __init__(self, **kwargs):
        super().__init__(fid='6f38', sfid=0x04, name='EF.UST', desc='USIM Service Table', size=(1,17), table=EF_UST_map, **kwargs)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [self.AddlShellCommands()]

    @with_default_category('File-Specific Commands')
    class AddlShellCommands(CommandSet):
        def __init__(self):
            super().__init__()

        def do_ust_service_activate(self, arg):
            """Activate a service within EF.UST"""
            self._cmd.card.update_ust(int(arg), 1)

        def do_ust_service_deactivate(self, arg):
            """Deactivate a service within EF.UST"""
            self._cmd.card.update_ust(int(arg), 0)

        def do_ust_service_check(self, arg):
            """Check consistency between services of this file and files present/activated.

            Many services determine if one or multiple files shall be present/activated or if they shall be
            absent/deactivated.  This performs a consistency check to ensure that no services are activated
            for files that are not - and vice-versa, no files are activated for services that are not.  Error
            messages are printed for every inconsistency found."""
            selected_file = self._cmd.lchan.selected_file
            num_problems = selected_file.ust_service_check(self._cmd)
            # obtain list of currently active services
            active_services = selected_file.get_active_services(self._cmd)
            # Service n°46 can only be declared "available" if service n°45 is declared "available"
            if 46 in active_services and not 45 in active_services:
                self._cmd.perror("ERROR: Service 46 available, but it requires Service 45")
                num_problems += 1
            # Service n°125 shall only be taken into account if Service n°124 is declared "available"
            if 125 in active_services and not 124 in active_services:
                self._cmd.perror("ERROR: Service 125 is ignored as Service 124 not available")
                num_problems += 1
            # Service n°95, n°99 and n°115 shall not be declared "available" if an ISIM application is present on the UICC
            non_isim_services = [95, 99, 115]
            app_names = selected_file.get_mf().get_app_names()
            if 'ADF.ISIM' in app_names:
                for s in non_isim_services:
                    if s in active_services:
                        self._cmd.perror("ERROR: Service %u shall not be available as ISIM application is present" % s)
                        num_problems += 1
            self._cmd.poutput("===> %u service / file inconsistencies detected" % num_problems)


# TS 31.103 Section 4.2.7 - *not* the same as DF.GSM/EF.ECC!
class EF_ECC(LinFixedEF):
    cc_construct = Rpad(BcdAdapter(Rpad(Bytes(3))), pattern='f')
    category_construct = FlagsEnum(Byte, police=1, ambulance=2, fire_brigade=3, marine_guard=4,
                                   mountain_rescue=5, manual_ecall=6, automatic_ecall=7)
    alpha_construct = GsmStringAdapter(Rpad(GreedyBytes))

    def __init__(self, fid='6fb7', sfid=0x01, name='EF.ECC',
                 desc='Emergency Call Codes'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=(4, 20))

    def _decode_record_bin(self, in_bin):
        # mandatory parts
        code = in_bin[:3]
        if code == b'\xff\xff\xff':
            return None
        svc_category = in_bin[-1:]
        ret = {'call_code': parse_construct(EF_ECC.cc_construct, code),
               'service_category': parse_construct(EF_ECC.category_construct, svc_category)}
        # optional alpha identifier
        if len(in_bin) > 4:
            alpha_id = in_bin[3:-1]
            ret['alpha_id'] = parse_construct(EF_ECC.alpha_construct, alpha_id)
        return ret

    def _encode_record_bin(self, in_json):
        if in_json is None:
            return b'\xff\xff\xff\xff'
        code = EF_ECC.cc_construct.build(in_json['call_code'])
        svc_category = EF_ECC.category_construct.build(in_json['category'])
        alpha_id = EF_ECC.alpha_construct.build(in_json['alpha_id'])
        # FIXME: alpha_id needs padding up to 'record_length - 4'
        return code + alpha_id + svc_category


# TS 31.102 Section 4.2.17
class EF_LOCI(TransparentEF):
    def __init__(self, fid='6f7e', sfid=0x0b, name='EF.LOCI', desc='Location information', size=(11, 11)):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        Lai = Struct('mcc_mnc'/BcdAdapter(Bytes(3)), 'lac'/HexAdapter(Bytes(2)))
        self._construct = Struct('tmsi'/HexAdapter(Bytes(4)), 'lai'/Lai, 'rfu'/Int8ub, 'lu_status'/Int8ub)
# TS 31.102 Section 4.2.18
class EF_AD(TransparentEF):
    class OP_MODE(enum.IntEnum):
        normal = 0x00
        type_approval = 0x80
        normal_and_specific_facilities = 0x01
        type_approval_and_specific_facilities = 0x81
        maintenance_off_line = 0x02
        cell_test = 0x04

    def __init__(self, fid='6fad', sfid=0x03, name='EF.AD', desc='Administrative Data', size=(4, 6)):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = BitStruct(
            # Byte 1
            'ms_operation_mode'/Bytewise(Enum(Byte, EF_AD.OP_MODE)),
            # Byte 2 + 3
            'additional_info'/Bytewise(FlagsEnum(Int16ub, ciphering_indicator=1, csg_display_control=2,
                                                 prose_services=4, extended_drx=8)),
            'rfu'/BitsRFU(4),
            'mnc_len'/BitsInteger(4),
            'extensions'/COptional(Bytewise(GreedyBytesRFU))
        )

# TS 31.102 Section 4.2.23
class EF_PSLOCI(TransparentEF):
    def __init__(self, fid='6f73', sfid=0x0c, name='EF.PSLOCI', desc='PS Location information', size=(14, 14)):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('ptmsi'/HexAdapter(Bytes(4)), 'ptmsi_sig'/HexAdapter(Bytes(3)),
                                 'rai'/HexAdapter(Bytes(6)), 'rau_status'/Int8ub)

# TS 31.102 Section 4.2.33
class EF_ICI(CyclicEF):
    def __init__(self, fid='6f80', sfid=0x14, name='EF.ICI', rec_len=(28, 48),
                 desc='Incoming Call Information', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct('alpha_id'/HexAdapter(Bytes(this._.total_len-28)),
                                 'len_of_bcd_contents'/Int8ub,
                                 'ton_npi'/Int8ub,
                                 'call_number'/BcdAdapter(Bytes(10)),
                                 'cap_cfg2_record_id'/Int8ub,
                                 'ext5_record_id'/Int8ub,
                                 'date_and_time'/BcdAdapter(Bytes(7)),
                                 'duration'/Int24ub,
                                 'status'/Byte,
                                 'link_to_phonebook'/HexAdapter(Bytes(3)))

# TS 31.102 Section 4.2.34
class EF_OCI(CyclicEF):
    def __init__(self, fid='6f81', sfid=0x15, name='EF.OCI', rec_len=(27, 47),
                 desc='Outgoing Call Information', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct('alpha_id'/HexAdapter(Bytes(this._.total_len-27)),
                                 'len_of_bcd_contents'/Int8ub,
                                 'ton_npi'/Int8ub,
                                 'call_number'/BcdAdapter(Bytes(10)),
                                 'cap_cfg2_record_id'/Int8ub,
                                 'ext5_record_id'/Int8ub,
                                 'date_and_time'/BcdAdapter(Bytes(7)),
                                 'duration'/Int24ub,
                                 'link_to_phonebook'/HexAdapter(Bytes(3)))

# TS 31.102 Section 4.2.35
class EF_ICT(CyclicEF):
    def __init__(self, fid='6f82', sfid=None, name='EF.ICT', rec_len=(3, 3),
                 desc='Incoming Call Timer', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct('accumulated_call_timer'/Int24ub)

# TS 31.102 Section 4.2.38
class EF_CCP2(LinFixedEF):
    def __init__(self, fid='6f4f', sfid=0x16, name='EF.CCP2', desc='Capability Configuration Parameters 2', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(15, None), **kwargs)

# TS 31.102 Section 4.2.47
class EF_EST(EF_UServiceTable):
    def __init__(self, **kwargs):
        super().__init__(fid='6f56', sfid=0x05, name='EF.EST', desc='Enabled Services Table', size=(1,None), table=EF_EST_map, **kwargs)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [self.AddlShellCommands()]

    @with_default_category('File-Specific Commands')
    class AddlShellCommands(CommandSet):
        def __init__(self):
            super().__init__()

        def do_est_service_activate(self, arg):
            """Activate a service within EF.UST"""
            self._cmd.card.update_est(int(arg), 1)

        def do_est_service_deactivate(self, arg):
            """Deactivate a service within EF.UST"""
            self._cmd.card.update_est(int(arg), 0)

# TS 31.102 Section 4.2.48
class EF_ACL(TransparentEF):
    def __init__(self, fid='6f57', sfid=None, name='EF.ACL', size=(32, None),
                 desc='Access Point Name Control List', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct('num_of_apns'/Int8ub, 'tlvs'/HexAdapter(GreedyBytes))

# TS 31.102 Section 4.2.51
class EF_START_HFN(TransparentEF):
    def __init__(self, fid='6f5b', sfid=0x0f, name='EF.START-HFN', size=(6, 6),
                 desc='Initialisation values for Hyperframe number', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct('start_cs'/Int24ub, 'start_ps'/Int24ub)

# TS 31.102 Section 4.2.52
class EF_THRESHOLD(TransparentEF):
    def __init__(self, fid='6f5c', sfid=0x10, name='EF.THRESHOLD', size=(3, 3),
                 desc='Maximum value of START', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct('max_start'/Int24ub)

# TS 31.102 (old releases like 3.8.0) Section 4.2.56
class EF_RPLMNAcT(TransRecEF):
    def __init__(self, fid='6f65', sfid=None, name='EF.RPLMNAcTD', size=(2, 4), rec_len=2,
                 desc='RPLMN Last used Access Technology', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
    def _decode_record_hex(self, in_hex):
        return dec_act(in_hex)
    # TODO: Encode

# TS 31.102 Section 4.2.77
class EF_VGCSCA(TransRecEF):
    def __init__(self, fid='6fd4', sfid=None, name='EF.VGCSCA', size=(2, 100), rec_len=2,
                 desc='Voice Group Call Service Ciphering Algorithm', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len, **kwargs)
        self._construct = Struct('alg_v_ki_1'/Int8ub, 'alg_v_ki_2'/Int8ub)

# TS 31.102 Section 4.2.79
class EF_GBABP(TransparentEF):
    def __init__(self, fid='6fd6', sfid=None, name='EF.GBABP', size=(3, 50),
                 desc='GBA Bootstrapping parameters', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct('rand'/LV, 'b_tid'/LV, 'key_lifetime'/LV)

# TS 31.102 Section 4.2.80
class EF_MSK(LinFixedEF):
    def __init__(self, fid='6fd7', sfid=None, name='EF.MSK', desc='MBMS Service Key List', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(20, None), **kwargs)
        msk_ts_constr = Struct('msk_id'/Int32ub, 'timestamp_counter'/Int32ub)
        self._construct = Struct('key_domain_id'/HexAdapter(Bytes(3)),
                                 'num_msk_id'/Int8ub,
                                 'msk_ids'/msk_ts_constr[this.num_msk_id])
# TS 31.102 Section 4.2.81
class EF_MUK(LinFixedEF):
    class MUK_Idr(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(GreedyBytes)

    class MUK_Idi(BER_TLV_IE, tag=0x82):
        _construct = HexAdapter(GreedyBytes)

    class MUK_ID(BER_TLV_IE, tag=0xA0, nested=[MUK_Idr, MUK_Idi]):
        pass

    class TimeStampCounter(BER_TLV_IE, tag=0x81):
        pass

    class EF_MUK_Collection(TLV_IE_Collection, nested=[MUK_ID, TimeStampCounter]):
        pass

    def __init__(self, fid='6fd8', sfid=None, name='EF.MUK', desc='MBMS User Key', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(None, None), **kwargs)
        self._tlv = EF_MUK.EF_MUK_Collection

# TS 31.102 Section 4.2.83
class EF_GBANL(LinFixedEF):
    class NAF_ID(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(GreedyBytes)

    class B_TID(BER_TLV_IE, tag=0x81):
        _construct = HexAdapter(GreedyBytes)

    class EF_GBANL_Collection(BER_TLV_IE, nested=[NAF_ID, B_TID]):
        pass

    def __init__(self, fid='6fda', sfid=None, name='EF.GBANL', desc='GBA NAF List', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(None, None), **kwargs)
        self._tlv = EF_GBANL.EF_GBANL_Collection

# TS 31.102 Section 4.2.85
class EF_EHPLMNPI(TransparentEF):
    def __init__(self, fid='6fdb', sfid=None, name='EF.EHPLMNPI', size=(1, 1),
                 desc='Equivalent HPLMN Presentation Indication', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = Struct('presentation_ind' /
                                 Enum(Byte, no_preference=0, display_highest_prio_only=1, display_all=2))

# TS 31.102 Section 4.2.87
class EF_NAFKCA(LinFixedEF):
    class NAF_KeyCentreAddress(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(GreedyBytes)
    def __init__(self, fid='6fdd', sfid=None, name='EF.NAFKCA', rec_len=(None, None),
                 desc='NAF Key Centre Address', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._tlv = EF_NAFKCA.NAF_KeyCentreAddress

# TS 31.102 Section 4.2.90
class EF_NCP_IP(LinFixedEF):
    class DataDestAddrRange(TLV_IE, tag=0x83):
        _construct = Struct('type_of_address'/Enum(Byte, IPv4=0x21, IPv6=0x56),
                            'prefix_length'/Int8ub,
                            'prefix'/HexAdapter(GreedyBytes))

    class AccessPointName(TLV_IE, tag=0x80):
        # coded as per TS 23.003
        _construct = HexAdapter(GreedyBytes)

    class Login(TLV_IE, tag=0x81):
        # as per SMS DCS TS 23.038
        _construct = GsmStringAdapter(GreedyBytes)

    class Password(TLV_IE, tag=0x82):
        # as per SMS DCS TS 23.038
        _construct = GsmStringAdapter(GreedyBytes)

    class BearerDescription(TLV_IE, tag=0x84):
        # Bearer descriptionTLV DO as per TS 31.111
        pass

    class EF_NCP_IP_Collection(TLV_IE_Collection,
                               nested=[AccessPointName, Login, Password, BearerDescription]):
        pass
    def __init__(self, fid='6fe2', sfid=None, name='EF.NCP-IP', rec_len=(None, None),
                 desc='Network Connectivity Parameters for USIM IP connections', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._tlv = EF_NCP_IP.EF_NCP_IP_Collection

# TS 31.102 Section 4.2.91
class EF_EPSLOCI(TransparentEF):
    def __init__(self, fid='6fe3', sfid=0x1e, name='EF.EPSLOCI',
                 desc='EPS Location Information', size=(18,18), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        upd_status_constr = Enum(
            Byte, updated=0, not_updated=1, roaming_not_allowed=2)
        self._construct = Struct('guti'/HexAdapter(Bytes(12)),
                                 'last_visited_registered_tai'/HexAdapter(Bytes(5)),
                                 'eps_update_status'/upd_status_constr)

# TS 31.102 Section 4.2.92
class EF_EPSNSC(LinFixedEF):
    class KSI_ASME(BER_TLV_IE, tag=0x80):
        _construct = Int8ub

    class K_ASME(BER_TLV_IE, tag=0x81):
        _construct = HexAdapter(GreedyBytes)

    class UplinkNASCount(BER_TLV_IE, tag=0x82):
        _construct = Int32ub

    class DownlinkNASCount(BER_TLV_IE, tag=0x83):
        _construct = Int32ub

    class IDofNASAlgorithms(BER_TLV_IE, tag=0x84):
        _construct = HexAdapter(GreedyBytes)

    class EPS_NAS_Security_Context(BER_TLV_IE, tag=0xa0,
                                   nested=[KSI_ASME, K_ASME, UplinkNASCount, DownlinkNASCount,
                                           IDofNASAlgorithms]):
        pass
    def __init__(self, fid='6fe4', sfid=0x18, name='EF.EPSNSC', rec_len=(54, 128),
                 desc='EPS NAS Security Context', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._tlv = EF_EPSNSC.EPS_NAS_Security_Context

# TS 31.102 Section 4.2.96
class EF_PWS(TransparentEF):
    def __init__(self, fid='6fec', sfid=None, name='EF.PWS', desc='Public Warning System', size=(1, 1), **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        pws_config = FlagsEnum(
            Byte, ignore_pws_in_hplmn_and_equivalent=1, ignore_pws_in_vplmn=2)
        self._construct = Struct('pws_configuration'/pws_config)

# TS 31.102 Section 4.2.101
class EF_IPS(CyclicEF):
    def __init__(self, fid='6ff1', sfid=None, name='EF.IPS', rec_len=(4, 4),
                 desc='IMEI(SV) Pairing Status', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len, **kwargs)
        self._construct = Struct('status'/PaddedString(2, 'ascii'),
                                 'link_to_ef_ipd'/Int8ub, 'rfu'/Byte)

# TS 31.102 Section 4.2.103
class EF_ePDGId(TransparentEF):
    class ePDGId(BER_TLV_IE, tag=0x80, nested=[]):
        _construct = Struct('type_of_ePDG_address'/Enum(Byte, FQDN=0, IPv4=1, IPv6=2),
                            'ePDG_address'/Switch(this.type_of_address,
                                                  {'FQDN': GreedyString("utf8"),
                                                   'IPv4': HexAdapter(GreedyBytes),
                                                   'IPv6': HexAdapter(GreedyBytes)}))

    def __init__(self, fid='6ff3', sfid=None, name='EF.eDPDGId', desc='Home ePDG Identifier', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_ePDGId.ePDGId

# TS 31.102 Section 4.2.106
class EF_FromPreferred(TransparentEF):
    def __init__(self, fid='6ff7', sfid=None, name='EF.FromPreferred', size=(1, 1),
                 desc='From Preferred', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self._construct = BitStruct('rfu'/BitsRFU(7), 'from_preferred'/Bit)


######################################################################
# DF.GSM-ACCESS
######################################################################

class DF_GSM_ACCESS(CardDF):
    def __init__(self, fid='5F3B', name='DF.GSM-ACCESS', desc='GSM Access', **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, service=27, **kwargs)
        files = [
            EF_Kc(fid='4f20', sfid=0x01, service=27),
            EF_Kc(fid='4f52', sfid=0x02, name='EF.KcGPRS', desc='GPRS Ciphering key KcGPRS', service=27),
            EF_CPBCCH(fid='4f63', service=39),
            EF_InvScan(fid='4f64', service=40),
        ]
        self.add_files(files)


######################################################################
# DF.5GS
######################################################################

# TS 31.102 Section 4.4.11.2
class EF_5GS3GPPLOCI(TransparentEF):
    def __init__(self, fid='4f01', sfid=0x01, name='EF.5GS3GPPLOCI', size=(20, 20),
                 desc='5S 3GP location information', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        upd_status_constr = Enum(
            Byte, updated=0, not_updated=1, roaming_not_allowed=2)
        self._construct = Struct('5g_guti'/HexAdapter(Bytes(13)),
                                 'last_visited_registered_tai_in_5gs'/HexAdapter(Bytes(6)),
                                 '5gs_update_status'/upd_status_constr)

# TS 31.102 Section 4.4.11.7
class EF_UAC_AIC(TransparentEF):
    def __init__(self, fid='4f06', sfid=0x06, name='EF.UAC_AIC', size=(4, 4),
                 desc='UAC Access Identities Configuration', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        cfg_constr = FlagsEnum(Byte, multimedia_priority_service=1,
                               mission_critical_service=2)
        self._construct = Struct('uac_access_id_config'/cfg_constr)

# TS 31.102 Section 4.4.11.9
class EF_OPL5G(LinFixedEF):
    def __init__(self, fid='6f08', sfid=0x08, name='EF.OPL5G', desc='5GS Operator PLMN List', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=(10, None), **kwargs)
        Tai = Struct('mcc_mnc'/BcdAdapter(Bytes(3)), 'tac_min'/HexAdapter(Bytes(3)),
                     'tac_max'/HexAdapter(Bytes(3)))
        self._construct = Struct('tai'/Tai, 'pnn_record_id'/Int8ub)

# TS 31.102 Section 4.4.11.10
class EF_SUPI_NAI(TransparentEF):
    class NetworkSpecificIdentifier(TLV_IE, tag=0x80):
        # RFC 7542 encoded as UTF-8 string
        _construct = GreedyString("utf8")

    class GlobalLineIdentifier(TLV_IE, tag=0x81):
        # TS 23.003 clause 28.16.2
        pass

    class GlobalCableIdentifier(TLV_IE, tag=0x82):
        # TS 23.003 clause 28.15.2
        pass

    class NAI_TLV_Collection(TLV_IE_Collection,
                             nested=[NetworkSpecificIdentifier, GlobalLineIdentifier, GlobalCableIdentifier]):
        pass
    def __init__(self, fid='4f09', sfid=0x09, name='EF.SUPI_NAI',
                 desc='SUPI as Network Access Identifier', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_SUPI_NAI.NAI_TLV_Collection


class EF_TN3GPPSNN(TransparentEF):
    class ServingNetworkName(BER_TLV_IE, tag=0x80):
        _construct = GreedyString("utf8")
    def __init__(self, fid='4f0c', sfid=0x0c, name='EF.TN3GPPSNN',
                 desc='Trusted non-3GPP Serving network names list', **kwargs):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_TN3GPPSNN.ServingNetworkName

# TS 31.102 Section 4.4.5
class DF_WLAN(CardDF):
    def __init__(self, fid='5f40', name='DF.WLAN', desc='Files for WLAN purpose', **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, **kwargs)
        files = [
            TransparentEF('4f41', 0x01, 'EF.Pseudo', 'Pseudonym', service=59),
            TransparentEF('4f42', 0x02, 'EF.UPLMNWLAN',
                          'User controlled PLMN selector for I-WLAN Access', service=60),
            TransparentEF('4f43', 0x03, 'EF.OPLMNWLAN',
                          'Operator controlled PLMN selector for I-WLAN Access', service=61),
            LinFixedEF('4f44', 0x04, 'EF.UWSIDL',
                       'User controlled WLAN Specific Identifier List', service=62),
            LinFixedEF('4f45', 0x05, 'EF.OWSIDL',
                       'Operator controlled WLAN Specific Identifier List', service=63),
            TransparentEF('4f46', 0x06, 'EF.WRI',
                          'WLAN Reauthentication Identity', service=66),
            LinFixedEF('4f47', 0x07, 'EF.HWSIDL',
                       'Home I-WLAN Specific Identifier List', service=81),
            TransparentEF('4f48', 0x08, 'EF.WEHPLMNPI',
                          'I-WLAN Equivalent HPLMN Presentation Indication', service=82),
            TransparentEF('4f49', 0x09, 'EF.WHPI',
                          'I-WLAN HPLMN Priority Indication', service=83),
            TransparentEF('4f4a', 0x0a, 'EF.WLRPLMN',
                          'I-WLAN Last Registered PLMN', service=84),
            TransparentEF('4f4b', 0x0b, 'EF.HPLMNDAI',
                          'HPLMN Direct Access Indicator', service=88),
        ]
        self.add_files(files)

# TS 31.102 Section 4.4.6
class DF_HNB(CardDF):
    def __init__(self, fid='5f50', name='DF.HNB', desc='Files for HomeNodeB purpose', **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, **kwargs)
        files = [
            LinFixedEF('4f81', 0x01, 'EF.ACSGL', 'Allowed CSG Lists', service=86),
            LinFixedEF('4f82', 0x02, 'EF.CSGTL', 'CSG Types', service=86),
            LinFixedEF('4f83', 0x03, 'EF.HNBN', 'Home NodeB Name', service=86),
            LinFixedEF('4f84', 0x04, 'EF.OCSGL', 'Operator CSG Lists', service=90),
            LinFixedEF('4f85', 0x05, 'EF.OCSGT', 'Operator CSG Type', service=90),
            LinFixedEF('4f86', 0x06, 'EF.OHNBN', 'Operator Home NodeB Name', service=90),
        ]
        self.add_files(files)

# TS 31.102 Section 4.4.8
class DF_ProSe(CardDF):
    def __init__(self, fid='5f90', name='DF.ProSe', desc='Files for ProSe purpose', **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, **kwargs)
        files = [
            LinFixedEF('4f01', 0x01, 'EF.PROSE_MON',
                       'ProSe Monitoring Parameters'),
            LinFixedEF('4f02', 0x02, 'EF.PROSE_ANN',
                       'ProSe Announcing Parameters'),
            LinFixedEF('4f03', 0x03, 'EF.PROSEFUNC', 'HPLMN ProSe Function'),
            TransparentEF('4f04', 0x04, 'EF.PROSE_RADIO_COM',
                          'ProSe Direct Communication Radio Parameters'),
            TransparentEF('4f05', 0x05, 'EF.PROSE_RADIO_MON',
                          'ProSe Direct Discovery Monitoring Radio Parameters'),
            TransparentEF('4f06', 0x06, 'EF.PROSE_RADIO_ANN',
                          'ProSe Direct Discovery Announcing Radio Parameters'),
            LinFixedEF('4f07', 0x07, 'EF.PROSE_POLICY',
                       'ProSe Policy Parameters'),
            LinFixedEF('4f08', 0x08, 'EF.PROSE_PLMN', 'ProSe PLMN Parameters'),
            TransparentEF('4f09', 0x09, 'EF.PROSE_GC', 'ProSe Group Counter'),
            TransparentEF('4f10', 0x10, 'EF.PST', 'ProSe Service Table'),
            TransparentEF('4f11', 0x11, 'EF.UIRC',
                          'ProSe UsageInformationReportingConfiguration'),
            LinFixedEF('4f12', 0x12, 'EF.PROSE_GM_DISCOVERY',
                       'ProSe Group Member Discovery Parameters'),
            LinFixedEF('4f13', 0x13, 'EF.PROSE_RELAY',
                       'ProSe Relay Parameters'),
            TransparentEF('4f14', 0x14, 'EF.PROSE_RELAY_DISCOVERY',
                          'ProSe Relay Discovery Parameters'),
        ]
        self.add_files(files)


class DF_USIM_5GS(CardDF):
    def __init__(self, fid='5FC0', name='DF.5GS', desc='5GS related files', **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, **kwargs)
        files = [
            # I'm looking at 31.102 R16.6
            EF_5GS3GPPLOCI(service=122),
            EF_5GS3GPPLOCI('4f02', 0x02, 'EF.5GSN3GPPLOCI',
                           '5GS non-3GPP location information', service=122),
            EF_5GS3GPPNSC(service=122),
            EF_5GS3GPPNSC('4f04', 0x04, 'EF.5GSN3GPPNSC',
                          '5GS non-3GPP Access NAS Security Context', service=122),
            EF_5GAUTHKEYS(service=123),
            EF_UAC_AIC(service=126),
            EF_SUCI_Calc_Info(service=124),
            EF_OPL5G(service=129),
            EF_SUPI_NAI(service=130),
            TransparentEF('4F0A', 0x0a, 'EF.Routing_Indicator',
                          'Routing Indicator', size=(4, 4), service=124),
            TransparentEF('4F0B', 0x0b, 'EF.URSP',
                          'UE Route Selector Policies per PLMN', service=132),
            EF_TN3GPPSNN(service=133),
        ]
        self.add_files(files)


class ADF_USIM(CardADF):
    def __init__(self, aid='a0000000871002', name='ADF.USIM', fid=None, sfid=None,
                 desc='USIM Application'):
        super().__init__(aid=aid, fid=fid, sfid=sfid, name=name, desc=desc)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [self.AddlShellCommands()]

        files = [
            EF_LI(sfid=0x02),
            EF_IMSI(sfid=0x07),
            EF_Keys(),
            EF_Keys('6f09', 0x09, 'EF.KeysPS',
                    desc='Ciphering and Integrity Keys for PS domain'),
            EF_xPLMNwAcT('6f60', 0x0a, 'EF.PLMNwAcT',
                         'User controlled PLMN Selector with Access Technology', service=20),
            EF_HPPLMN(),
            EF_ACMmax(service=13),
            EF_UST(),
            CyclicEF('6f39', None, 'EF.ACM',
                     'Accumulated call meter', rec_len=(3, 3), service=13),
            TransparentEF('6f3e', None, 'EF.GID1', 'Group Identifier Level 1', service=17),
            TransparentEF('6f3f', None, 'EF.GID2', 'Group Identifier Level 2', service=18),
            EF_SPN(service=19),
            TransparentEF('6f41', None, 'EF.PUCT',
                          'Price per unit and currency table', size=(5, 5), service=13),
            EF_CBMI(service=15),
            EF_ACC(sfid=0x06),
            EF_PLMNsel('6f7b', 0x0d, 'EF.FPLMN',
                       'Forbidden PLMNs', size=(12, None)),
            EF_LOCI(),
            EF_AD(),
            EF_CBMID(sfid=0x0e, service=29),
            EF_ECC(),
            EF_CBMIR(service=16),
            EF_PSLOCI(),
            EF_ADN('6f3b', None, 'EF.FDN', 'Fixed Dialling Numbers', service=[2, 89]),
            EF_SMS('6f3c', None, service=10),
            EF_MSISDN(service=21),
            EF_SMSP(service=12),
            EF_SMSS(service=10),
            EF_ADN('6f49', None, 'EF.SDN', 'Service Dialling Numbers', service=[4, 89]),
            EF_EXT('6f4b', None, 'EF.EXT2', 'Extension2 (FDN)', service=3),
            EF_EXT('6f4c', None, 'EF.EXT3', 'Extension2 (SDN)', service=5),
            EF_SMSR(service=11),
            EF_ICI(service=9),
            EF_OCI(service=8),
            EF_ICT(service=9),
            EF_ICT('6f83', None, 'EF.OCT', 'Outgoing Call Timer', service=8),
            EF_EXT('6f4e', None, 'EF.EXT5', 'Extension5 (ICI/OCI/MSISDN)', service=44),
            EF_CCP2(service=14),
            EF_eMLPP(service=24),
            EF_AAeM(service=25),
            # EF_Hiddenkey
            EF_ADN('6f4d', None, 'EF.BDN', 'Barred Dialling Numbers', service=6),
            EF_EXT('6f55', None, 'EF.EXT4', 'Extension4 (BDN/SSC)', service=7),
            EF_CMI(service=6),
            EF_EST(service=[2, 6, 34, 35]),
            EF_ACL(service=35),
            EF_DCK(service=36),
            EF_CNL(service=37),
            EF_START_HFN(),
            EF_THRESHOLD(),
            EF_xPLMNwAcT('6f61', 0x11, 'EF.OPLMNwAcT', 'User controlled PLMN Selector with Access Technology', service=42),
            EF_xPLMNwAcT('6f62', 0x13, 'EF.HPLMNwAcT', 'HPLMN Selector with Access Technology', service=43),
            EF_ARR('6f06', 0x17),
            EF_RPLMNAcT(),
            TransparentEF('6fc4', None, 'EF.NETPAR', 'Network Parameters'),
            EF_PNN('6fc5', 0x19, service=45),
            EF_OPL(service=46),
            EF_ADN('6fc7', None, 'EF.MBDN', 'Mailbox Dialling Numbers', service=47),
            EF_EXT('6fc8', None, 'EF.EXT6', 'Extension6 (MBDN)'),
            EF_MBI(service=47),
            EF_MWIS(service=48),
            EF_ADN('6fcb', None, 'EF.CFIS', 'Call Forwarding Indication Status', service=49),
            EF_EXT('6fcc', None, 'EF.EXT7', 'Extension7 (CFIS)'),
            TransparentEF('6fcd', None, 'EF.SPDI', 'Service Provider Display Information', service=51),
            EF_MMSN(service=52),
            EF_EXT('6fcf', None, 'EF.EXT8', 'Extension8 (MMSN)', service=53),
            EF_MMSICP(service=52),
            EF_MMSUP(service=52),
            EF_MMSUCP(service=(52, 55)),
            EF_NIA(service=56),
            EF_VGCS(service=57),
            EF_VGCSS(service=57),
            EF_VGCS('6fb3', None, 'EF.VBS', 'Voice Broadcast Service', service=58),
            EF_VGCSS('6fb4', None, 'EF.VBSS', 'Voice Broadcast Service Status', service=58),
            EF_VGCSCA(service=64),
            EF_VGCSCA('6fd5', None, 'EF.VBCSCA', 'Voice Broadcast Service Ciphering Algorithm', service=65),
            EF_GBABP(service=68),
            EF_MSK(service=69),
            EF_MUK(service=69),
            EF_GBANL(service=68),
            EF_PLMNsel('6fd9', 0x1d, 'EF.EHPLMN', 'Equivalent HPLMN', size=(12, None), service=71),
            EF_EHPLMNPI(service=(71, 73)),
            # EF_LRPLMNSI ('6fdc', service=74)
            EF_NAFKCA(service=(68, 76)),
            TransparentEF('6fde', None, 'EF.SPNI', 'Service Provider Name Icon', service=78),
            LinFixedEF('6fdf', None, 'EF.PNNI', 'PLMN Network Name Icon', service=79),
            EF_NCP_IP(service=80),
            EF_EPSLOCI('6fe3', 0x1e, 'EF.EPSLOCI', 'EPS location information', service=85),
            EF_EPSNSC(service=85),
            TransparentEF('6fe6', None, 'EF.UFC', 'USAT Facility Control', size=(1, 16)),
            TransparentEF('6fe8', None, 'EF.NASCONFIG', 'Non Access Stratum Configuration', service=96),
            # UICC IARI (only in cards that have no ISIM) service=95
            EF_PWS(service=97),
            LinFixedEF('6fed', None, 'EF.FDNURI', 'Fixed Dialling Numbers URI', service=(2, 99)),
            LinFixedEF('6fee', None, 'EF.BDNURI', 'Barred Dialling Numbers URI', service=(6, 99)),
            LinFixedEF('6fef', None, 'EF.SDNURI', 'Service Dialling Numbers URI', service=(4, 99)),
            # EF_IWL (IMEI(SV) White List)
            EF_IPS(),
            EF_ePDGId(service=(106, 107)),
            # FIXME: from EF_ePDGSelection onwards
            EF_FromPreferred(service=114),
            # FIXME: DF_SoLSA service=23
            DF_PHONEBOOK(),
            DF_GSM_ACCESS(),
            DF_WLAN(service=[59, 60, 61, 62, 63, 66, 81, 82, 83, 84, 88]),
            DF_HNB(service=[86, 90]),
            DF_ProSe(service=101),
            # FIXME: DF_ACDC service=108
            # FIXME: DF_TV service=116
            DF_USIM_5GS(service=[122, 123, 124, 125, 126, 127, 129, 130]),
        ]
        self.add_files(files)

    def decode_select_response(self, data_hex):
        return pySim.ts_102_221.CardProfileUICC.decode_select_response(data_hex)

    @with_default_category('Application-Specific Commands')
    class AddlShellCommands(CommandSet):
        def __init__(self):
            super().__init__()

        authenticate_parser = argparse.ArgumentParser()
        authenticate_parser.add_argument('rand', help='Random challenge')
        authenticate_parser.add_argument('autn', help='Authentication Nonce')
        #authenticate_parser.add_argument('--context', help='Authentication context', default='3G')

        @cmd2.with_argparser(authenticate_parser)
        def do_authenticate(self, opts):
            """Perform Authentication and Key Agreement (AKA)."""
            (data, sw) = self._cmd.card._scc.authenticate(opts.rand, opts.autn)
            self._cmd.poutput_json(data)

        term_prof_parser = argparse.ArgumentParser()
        term_prof_parser.add_argument('PROFILE', help='Hexstring of encoded terminal profile')

        @cmd2.with_argparser(term_prof_parser)
        def do_terminal_profile(self, arg):
            """Send a TERMINAL PROFILE command to the card.
            This is used to inform the card about which optional
            features the terminal (modem/phone) supports, particularly
            in the context of SIM Toolkit, Proactive SIM and OTA.  You
            must specify a hex-string with the encoded terminal profile
            you want to send to the card."""
            (data, sw) = self._cmd.card._scc.terminal_profile(arg)
            self._cmd.poutput('SW: %s, data: %s' % (sw, data))

        envelope_parser = argparse.ArgumentParser()
        envelope_parser.add_argument('PAYLOAD', help='Hexstring of encoded payload to ENVELOPE')

        @cmd2.with_argparser(envelope_parser)
        def do_envelope(self, arg):
            """Send an ENVELOPE command to the card.  This is how a
            variety of information is communicated from the terminal
            (modem/phone) to the card, particularly in the context of
            SIM Toolkit, Proactive SIM and OTA."""
            (data, sw) = self._cmd.card._scc.envelope(arg)
            self._cmd.poutput('SW: %s, data: %s' % (sw, data))

        envelope_sms_parser = argparse.ArgumentParser()
        envelope_sms_parser.add_argument('TPDU', help='Hexstring of encoded SMS TPDU')

        @cmd2.with_argparser(envelope_sms_parser)
        def do_envelope_sms(self, arg):
            """Send an ENVELOPE(SMS-PP-Download) command to the card.
            This emulates a terminal (modem/phone) having received a SMS
            with a PID of 'SMS for the SIM card'.  You can use this
            command in the context of testing OTA related features
            without a modem/phone or a cellular netwokr."""
            tpdu_ie = SMS_TPDU()
            tpdu_ie.from_bytes(h2b(arg))
            dev_ids = DeviceIdentities(
                decoded={'source_dev_id': 'network', 'dest_dev_id': 'uicc'})
            sms_dl = SMSPPDownload(children=[dev_ids, tpdu_ie])
            (data, sw) = self._cmd.card._scc.envelope(b2h(sms_dl.to_tlv()))
            self._cmd.poutput('SW: %s, data: %s' % (sw, data))


# TS 31.102 Section 7.3
sw_usim = {
    'Security management': {
        '9862': 'Authentication error, incorrect MAC',
        '9864': 'Authentication error, security context not supported',
        '9865': 'Key freshness failure',
        '9866': 'Authentication error, no memory space available',
        '9867': 'Authentication error, no memory space available in EF MUK',
    }
}


class CardApplicationUSIM(CardApplication):
    def __init__(self):
        super().__init__('USIM', adf=ADF_USIM(), sw=sw_usim)
