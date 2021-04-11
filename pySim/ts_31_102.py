# -*- coding: utf-8 -*-

"""
Various constants from ETSI TS 131 102
"""

#
# Copyright (C) 2020 Supreeth Herle <herlesupreeth@gmail.com>
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

# Mapping between USIM Service Number and its description
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

######################################################################
# ADF.USIM
######################################################################

from struct import unpack, pack
from construct import *
from pySim.construct import LV, HexAdapter, BcdAdapter
from pySim.filesystem import *
from pySim.ts_102_221 import EF_ARR
from pySim.ts_51_011 import EF_IMSI, EF_xPLMNwAcT, EF_SPN, EF_CBMI, EF_ACC, EF_PLMNsel, EF_AD
from pySim.ts_51_011 import EF_CBMID, EF_CBMIR, EF_ADN, EF_SMS, EF_MSISDN, EF_SMSP, EF_SMSS
from pySim.ts_51_011 import EF_SMSR, EF_DCK, EF_EXT, EF_CNL, EF_OPL, EF_MBI, EF_MWIS
from pySim.ts_51_011 import EF_MMSN, EF_MMSICP, EF_MMSUP, EF_MMSUCP, EF_VGCS, EF_VGCSS, EF_NIA
from pySim.ts_51_011 import EF_ACMmax, EF_AAeM, EF_eMLPP, EF_CMI

import pySim.ts_102_221

# TS 31.102 4.4.11.8
class EF_SUCI_Calc_Info(TransparentEF):
    def __init__(self, fid="4f07", sfid=0x07, name='EF.SUCI_Calc_Info', size={2, None},
        desc='SUCI Calc Info'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)

    def _encode_prot_scheme_id_list(self, in_list):
        out_bytes = [0xa0]
        out_bytes.append(len(in_list)*2) # two byte per entry

        # position in list determines priority; high-priority items (low index) come first
        for scheme in sorted(in_list, key=lambda item: item["priority"]):
            out_bytes.append(scheme["identifier"])
            out_bytes.append(scheme["key_index"])

        return out_bytes

    def _encode_hnet_pubkey_list(self, hnet_pubkey_list):
        out_bytes = [0xa1] # pubkey list tag
        out_bytes.append(0x00) # length filled later
        length = 0

        for key in hnet_pubkey_list:
            out_bytes.append(0x80) # identifier tag
            out_bytes.append(0x01) # TODO size, fixed to 1 byte
            out_bytes.append(key["hnet_pubkey_identifier"])
            out_bytes.append(0x81) # key tag
            out_bytes.append(len(key["hnet_pubkey"])//2)
            length += 5+len(key["hnet_pubkey"])//2

            pubkey_bytes = h2b(key["hnet_pubkey"])
            out_bytes += pubkey_bytes

        # fill length
        out_bytes[1] = length
        return out_bytes

    def _encode_hex(self, in_json):
        out_bytes = self._encode_prot_scheme_id_list(in_json['prot_scheme_id_list'])
        out_bytes += self._encode_hnet_pubkey_list(in_json['hnet_pubkey_list'])
        return "".join(["%02X" % i for i in out_bytes])

    def _decode_prot_scheme_id_list(self, in_bytes):
        prot_scheme_id_list = []
        pos = 0
        # two bytes per entry
        while pos < len(in_bytes):
            prot_scheme = {
                'priority':   pos//2, # first in list: high priority
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
            hnet_pubkey_id_len = in_bytes[pos] # TODO might be more than 1 byte?
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
        return self._decode_hex(b2h(in_hex))

    def _decode_hex(self, in_hex):
        in_bytes = h2b(in_hex)
        pos = 0

        if in_bytes[pos] != 0xa0:
            print("missing Protection Scheme Identifier List data object tag")
            return {}
        pos += 1

        prot_scheme_id_list_len = in_bytes[pos] # TODO maybe more than 1 byte
        pos += 1
        # decode Protection Scheme Identifier List data object
        prot_scheme_id_list = self._decode_prot_scheme_id_list(in_bytes[pos:pos+prot_scheme_id_list_len])
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
    def __init__(self, fid='6f05', sfid=None, name='EF.LI', size={2,None}, rec_len=2,
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
    def __init__(self, fid='6f08', sfid=0x08, name='EF.Keys', size={33,33},
                 desc='Ciphering and Integrity Keys'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('ksi'/Int8ub, 'ck'/HexAdapter(Bytes(16)), 'ik'/HexAdapter(Bytes(16)))

# TS 31.103 Section 4.2.7
class EF_UST(TransparentEF):
    def __init__(self, fid='6f38', sfid=0x04, name='EF.UST', desc='USIM Service Table', size={1,17}):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, size=size)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [self.AddlShellCommands()]
    def _decode_bin(self, in_bin):
        ret = []
        for i in range (0, len(in_bin)):
            byte = in_bin[i]
            for bitno in range(0,7):
                if byte & (1 << bitno):
                    ret.append(i * 8 + bitno + 1)
        return ret
    def _encode_bin(self, in_json):
        # FIXME: size this to length of file
        ret = bytearray(20)
        for srv in in_json:
            print("srv=%d"%srv)
            srv = srv-1
            byte_nr = srv // 8
            # FIXME: detect if service out of range was selected
            bit_nr = srv % 8
            ret[byte_nr] |= (1 << bit_nr)
        return ret
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

# TS 31.103 Section 4.2.7 - *not* the same as DF.GSM/EF.ECC!
class EF_ECC(LinFixedEF):
    def __init__(self, fid='6fb7', sfid=0x01, name='EF.ECC',
                 desc='Emergency Call Codes'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={4,20})

# TS 31.102 Section 4.2.17
class EF_LOCI(TransparentEF):
    def __init__(self, fid='6f7e', sfid=0x0b, name='EF.LOCI', desc='Location information', size={11,11}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('tmsi'/HexAdapter(Bytes(4)), 'lai'/HexAdapter(Bytes(5)), 'rfu'/Int8ub,
                                 'lu_status'/Int8ub)

# TS 31.102 Section 4.2.23
class EF_PSLOCI(TransparentEF):
    def __init__(self, fid='6f73', sfid=0x0c, name='EF.PSLOCI', desc='PS Location information', size={14,14}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('ptmsi'/HexAdapter(Bytes(4)), 'ptmsi_sig'/HexAdapter(Bytes(3)),
                                 'rai'/HexAdapter(Bytes(6)), 'rau_status'/Int8ub)

# TS 31.102 Section 4.2.33
class EF_ICI(CyclicEF):
    def __init__(self, fid='6f80', sfid=0x14, name='EF.ICI', rec_len={28,48},
                 desc='Incoming Call Information'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('alpha_id'/Bytes(this._.total_len-28),
                                 'len_of_bcd_contents'/Int8ub,
                                 'ton_npi'/Int8ub,
                                 'call_number'/BcdAdapter(Bytes(10)),
                                 'cap_cfg2_record_id'/Int8ub,
                                 'ext5_record_id'/Int8ub,
                                 'date_and_time'/BcdAdapter(Bytes(7)),
                                 'duration'/Int24ub,
                                 'status'/Byte,
                                 'link_to_phonebook'/Bytes(3))

# TS 31.102 Section 4.2.34
class EF_OCI(CyclicEF):
    def __init__(self, fid='6f81', sfid=0x15, name='EF.OCI', rec_len={27,47},
                 desc='Outgoing Call Information'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('alpha_id'/Bytes(this._.total_len-27),
                                 'len_of_bcd_contents'/Int8ub,
                                 'ton_npi'/Int8ub,
                                 'call_number'/BcdAdapter(Bytes(10)),
                                 'cap_cfg2_record_id'/Int8ub,
                                 'ext5_record_id'/Int8ub,
                                 'date_and_time'/BcdAdapter(Bytes(7)),
                                 'duration'/Int24ub,
                                 'link_to_phonebook'/Bytes(3))

# TS 31.102 Section 4.2.35
class EF_ICT(CyclicEF):
    def __init__(self, fid='6f82', sfid=None, name='EF.ICT', rec_len={3,3},
                 desc='Incoming Call Timer'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('accumulated_call_timer'/Int24ub)

# TS 31.102 Section 4.2.38
class EF_CCP2(LinFixedEF):
    def __init__(self, fid='6f4f', sfid=0x16, name='EF.CCP2', desc='Capability Configuration Parameters 2'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len={15,None})

# TS 31.102 Section 4.2.48
class EF_ACL(TransparentEF):
    def __init__(self, fid='6f57', sfid=None, name='EF.ACL', size={32,None},
                 desc='Access Point Name Control List'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('num_of_apns'/Int8ub, 'tlvs'/GreedyBytes)

# TS 31.102 Section 4.2.51
class EF_START_HFN(TransparentEF):
    def __init__(self, fid='6f5b', sfid=0x0f, name='EF.START-HFN', size={6,6},
                 desc='Initialisation values for Hyperframe number'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('start_cs'/Int24ub, 'start_ps'/Int24ub)

# TS 31.102 Section 4.2.52
class EF_THRESHOLD(TransparentEF):
    def __init__(self, fid='6f5c', sfid=0x10, name='EF.THRESHOLD', size={3,3},
                 desc='Maximum value of START'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('max_start'/Int24ub)

# TS 31.102 Section 4.2.77
class EF_VGCSCA(TransRecEF):
    def __init__(self, fid='6fd4', sfid=None, name='EF.VGCSCA', size={2,100}, rec_len=2,
                 desc='Voice Group Call Service Ciphering Algorithm'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
        self._construct = Struct('alg_v_ki_1'/Int8ub, 'alg_v_ki_2'/Int8ub)

# TS 31.102 Section 4.2.79
class EF_GBABP(TransparentEF):
    def __init__(self, fid='6fd6', sfid=None, name='EF.GBABP', size={3,50},
                 desc='GBA Bootstrapping parameters'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('rand'/LV, 'b_tid'/LV, 'key_lifetime'/LV)

# TS 31.102 Section 4.2.80
class EF_MSK(LinFixedEF):
    def __init__(self, fid='6fd7', sfid=None, name='EF.MSK', desc='MBMS Service Key List'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len={20,None})
        msk_ts_constr = Struct('msk_id'/Int32ub, 'timestamp_counter'/Int32ub)
        self._construct = Struct('key_domain_id'/Bytes(3),
                                 'num_msk_id'/Int8ub,
                                 'msk_ids'/msk_ts_constr[this.num_msk_id])

# TS 31.102 Section 4.2.85
class EF_EHPLMNPI(TransparentEF):
    def __init__(self, fid='6fdb', sfid=None, name='EF.EHPLMNPI', size={1,1},
                 desc='Equivalent HPLMN Presentation Indication'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('presentation_ind'/
                                 Enum(Byte, no_preference=0, display_highest_prio_only=1, display_all=2))
# TS 31.102 Section 4.2.91
class EF_EPSLOCI(TransparentEF):
    def __init__(self, fid='6fe3', sfid=0x1e, name='EF.EPSLOCI', size={18,18},
                 desc='EPS Location Information'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        upd_status_constr = Enum(Byte, updated=0, not_updated=1, roaming_not_allowed=2)
        self._construct = Struct('guti'/Bytes(12), 'last_visited_registered_tai'/Bytes(5),
                                 'eps_update_status'/upd_status_constr)

# TS 31.102 Section 4.2.96
class EF_PWS(TransparentEF):
    def __init__(self, fid='6fec', sfid=None, name='EF.PWS', desc='Public Warning System', size={1,1}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        pws_config = FlagsEnum(Byte, ignore_pws_in_hplmn_and_equivalent=1, ignore_pws_in_vplmn=2)
        self._construct = Struct('pws_configuration'/pws_config)

# TS 31.102 Section 4.2.101
class EF_IPS(CyclicEF):
    def __init__(self, fid='6ff1', sfid=None, name='EF.IPS', rec_len={4,4},
                 desc='IMEI(SV) Pairing Status'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('status'/PaddedString(2, 'ascii'),
                                 'link_to_ef_ipd'/Int8ub, 'rfu'/Byte)

######################################################################
# DF.5GS
######################################################################

# TS 31.102 Section 4.4.11.2
class EF_5GS3GPPLOCI(TransparentEF):
    def __init__(self, fid='4f01', sfid=0x01, name='EF.5GS3GPPLOCI', size={20,20},
                 desc='5S 3GP location information'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        upd_status_constr = Enum(Byte, updated=0, not_updated=1, roaming_not_allowed=2)
        self._construct = Struct('5g_guti'/Bytes(13), 'last_visited_registered_tai_in_5gs'/Bytes(6),
                                 '5gs_update_status'/upd_status_constr)

# TS 31.102 Section 4.4.11.7
class EF_UAC_AIC(TransparentEF):
    def __init__(self, fid='4f06', sfid=0x06, name='EF.UAC_AIC', size={4,4},
                 desc='UAC Access Identities Configuration'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        cfg_constr = FlagsEnum(Byte, multimedia_priority_service=1,
                                     mission_critical_service=2)
        self._construct = Struct('uac_access_id_config'/cfg_constr)

# TS 31.102 Section 4.4.11.10
class EF_OPL5G(LinFixedEF):
    def __init__(self, fid='6f08', sfid=0x08, name='EF.OPL5G', desc='5GS Operator PLMN List'):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len={10,None})
        self._construct = Struct('tai'/Bytes(9), 'pnn_record_id'/Int8ub)

class DF_USIM_5GS(CardDF):
    def __init__(self, fid='5FC0', name='DF.5GS', desc='5GS related files'):
        super().__init__(fid=fid, name=name, desc=desc)
        files = [
          # I'm looking at 31.102 R15.9
          EF_5GS3GPPLOCI(),
          EF_5GS3GPPLOCI('4f02', 0x02, 'EF.5GSN3GPPLOCI', '5GS non-3GPP location information'),
          LinFixedEF('4F03', 0x03, 'EF.5GS3GPPNSC', '5GS 3GPP Access NAS Security Context', rec_len={57,None}),
          LinFixedEF('4F04', 0x04, 'EF.5GSN3GPPNSC', '5GS non-3GPP Access NAS Security Context', rec_len={57,None}),
          TransparentEF('4F05', 0x05, 'EF.5GAUTHKEYS', '5G authentication keys', size={68, None}),
          EF_UAC_AIC(),
          EF_SUCI_Calc_Info(),
          EF_OPL5G(),
          TransparentEF('4F09', 0x09, 'EF.NSI', 'Network Specific Identifier'),
          TransparentEF('4F0A', 0x0a, 'EF.Routing_Indicator', 'Routing Indicator', size={4,4}),
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
          EF_Keys('6f09', 0x09, 'EF.KeysPS', desc='Ciphering and Integrity Keys for PS domain'),
          EF_xPLMNwAcT('6f60', 0x0a, 'EF.PLMNwAcT',
                       'User controlled PLMN Selector with Access Technology'),
          TransparentEF('6f31', 0x12, 'EF.HPPLMN', 'Higher Priority PLMN search period'),
          EF_ACMmax(),
          EF_UST(),
          CyclicEF('6f39', None, 'EF.ACM', 'Accumulated call meter', rec_len={3,3}),
          TransparentEF('6f3e', None, 'EF.GID1', 'Group Identifier Level 1'),
          TransparentEF('6f3f', None, 'EF.GID2', 'Group Identifier Level 2'),
          EF_SPN(),
          TransparentEF('6f41', None, 'EF.PUCT', 'Price per unit and currency table', size={5,5}),
          EF_CBMI(),
          EF_ACC(sfid=0x06),
          EF_PLMNsel('6f7b', 0x0d, 'EF.FPLMN', 'Forbidden PLMNs', size={12,None}),
          EF_LOCI(),
          EF_AD(sfid=0x03),
          EF_CBMID(sfid=0x0e),
          EF_ECC(),
          EF_CBMIR(),
          EF_PSLOCI(),
          EF_ADN('6f3b', None, 'EF.FDN', 'Fixed Dialling Numbers'),
          EF_SMS('6f3c', None),
          EF_MSISDN(),
          EF_SMSP(),
          EF_SMSS(),
          EF_ADN('6f49', None, 'EF.SDN', 'Service Dialling Numbers'),
          EF_EXT('6f4b', None, 'EF.EXT2', 'Extension2 (FDN)'),
          EF_EXT('6f4c', None, 'EF.EXT3', 'Extension2 (SDN)'),
          EF_SMSR(),
          EF_ICI(),
          EF_OCI(),
          EF_ICT(),
          EF_ICT('6f83', None, 'EF.OCT', 'Outgoing Call Timer'),
          EF_EXT('6f4e', None, 'EF.EXT5', 'Extension5 (ICI/OCI/MSISDN)'),
          EF_CCP2(),
          EF_eMLPP(),
          EF_AAeM(),
          # EF_Hiddenkey
          EF_ADN('6f4d', None, 'EF.BDN', 'Barred Dialling Numbers'),
          EF_EXT('6f55', None, 'EF.EXT4', 'Extension4 (BDN/SSC)'),
          EF_CMI(),
          EF_UST('6f56', 0x05, 'EF.EST', 'Enabled Services Table', size={1,None}),
          EF_ACL(),
          EF_DCK(),
          EF_CNL(),
          EF_START_HFN(),
          EF_THRESHOLD(),
          EF_xPLMNwAcT('6f61', 0x11, 'EF.OPLMNwAcT',
                       'User controlled PLMN Selector with Access Technology'),
          EF_ARR('6f06', 0x17),
          TransparentEF('6fc4', None, 'EF.NETPAR', 'Network Parameters'),
          LinFixedEF('6fc5', 0x19, 'EF.PNN', 'PLMN Network Name'),
          EF_OPL(),
          EF_ADN('6fc7', None, 'EF.MBDN', 'Mailbox Dialling Numbers'),
          EF_MBI(),
          EF_MWIS(),
          EF_ADN('6fcb', None, 'EF.CFIS', 'Call Forwarding Indication Status'),
          EF_EXT('6fcc', None, 'EF.EXT7', 'Extension7 (CFIS)'),
          TransparentEF('6fcd', None, 'EF.SPDI', 'Service Provider Display Information'),
          EF_MMSN(),
          EF_EXT('6fcf', None, 'EF.EXT8', 'Extension8 (MMSN)'),
          EF_MMSICP(),
          EF_MMSUP(),
          EF_MMSUCP(),
          EF_NIA(),
          EF_VGCS(),
          EF_VGCSS(),
          EF_VGCS('6fb3', None, 'EF.VBS', 'Voice Broadcast Service'),
          EF_VGCSS('6fb4', None, 'EF.VBSS', 'Voice Broadcast Service Status'),
          EF_VGCSCA(),
          EF_VGCSCA('6fd5', None, 'EF.VBCSCA', 'Voice Broadcast Service Ciphering Algorithm'),
          EF_GBABP(),
          EF_MSK(),
          LinFixedEF('6fd8', None, 'EF.MUK', 'MBMS User Key'),
          LinFixedEF('6fda', None, 'EF.GBANL', 'GBA NFA List'),
          EF_PLMNsel('6fd9', 0x1d, 'EF.EHPLMN', 'Equivalent HPLMN', size={12,None}),
          EF_EHPLMNPI(),
          LinFixedEF('6fdd', None, 'EF.NAFKCA', 'NAF Key Centre Address'),
          TransparentEF('6fde', None, 'EF.SPNI', 'Service Provider Name Icon'),
          LinFixedEF('6fdf', None, 'EF.PNNI', 'PLMN Network Name Icon'),
          LinFixedEF('6fe2', None, 'EF.NCP-IP', 'Network Connectivity Parameters for USIM IP connections'),
          EF_EPSLOCI('6fe3', 0x1e, 'EF.EPSLOCI', 'EPS location information'),
          LinFixedEF('6fe4', 0x18, 'EF.EPSNSC', 'EPS NAS Security Context', rec_len={54,128}),
          TransparentEF('6fe6', None, 'EF.UFC', 'USAT Facility Control', size={1,16}),
          TransparentEF('6fe8', None, 'EF.NASCONFIG', 'Non Access Stratum Configuration'),
          # UICC IARI (only in cards that have no ISIM)
          EF_PWS(),
          LinFixedEF('6fed', None, 'EF.FDNURI', 'Fixed Dialling Numbers URI'),
          LinFixedEF('6fee', None, 'EF.BDNURI', 'Barred Dialling Numbers URI'),
          LinFixedEF('6fef', None, 'EF.SDNURI', 'Service Dialling Numbers URI'),
          EF_IPS(),
          # FIXME: from EF_ePDGid onwards
          # FIXME: DF_SoLSA
          # FIXME: DF_PHONEBOOK
          # FIXME: DF_GSM_ACCESS
          # FIXME: DF_WLAN
          # FIXME: DF_HNB
          # FIXME: DF_ProSe
          # FIXME: DF_ACDC
          # FIXME: DF_TV
          DF_USIM_5GS(),
          ]
        self.add_files(files)

    def decode_select_response(self, data_hex):
        return pySim.ts_102_221.decode_select_response(data_hex)

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

CardApplicationUSIM = CardApplication('USIM', adf=ADF_USIM(), sw=sw_usim)
