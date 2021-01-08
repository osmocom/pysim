# -*- coding: utf-8 -*-

""" Various constants from ETSI TS 151.011 +
Representation of the GSM SIM/USIM/ISIM filesystem hierarchy.

The File (and its derived classes) uses the classes of pySim.filesystem in
order to describe the files specified in the relevant ETSI + 3GPP specifications.
"""

#
# Copyright (C) 2017 Alexander.Chemeris <Alexander.Chemeris@gmail.com>
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

MF_num = '3F00'

DF_num = {
'TELECOM': '7F10',

'GSM': '7F20',
'IS-41': '7F22',
'FP-CTS': '7F23',

'GRAPHICS': '5F50',

'IRIDIUM': '5F30',
'GLOBST': '5F31',
'ICO': '5F32',
'ACeS': '5F33',

'EIA/TIA-553': '5F40',
'CTS': '5F60',
'SOLSA': '5F70',

'MExE': '5F3C',
}

EF_num = {
# MF
'ICCID': '2FE2',
'ELP': '2F05',
'DIR': '2F00',

# DF_TELECOM
'ADN': '6F3A',
'FDN': '6F3B',
'SMS': '6F3C',
'CCP': '6F3D',
'MSISDN': '6F40',
'SMSP': '6F42',
'SMSS': '6F43',
'LND': '6F44',
'SMSR': '6F47',
'SDN': '6F49',
'EXT1': '6F4A',
'EXT2': '6F4B',
'EXT3': '6F4C',
'BDN': '6F4D',
'EXT4': '6F4E',
'CMI': '6F58',
'ECCP': '6F4F',

# DF_GRAPHICS
'IMG': '4F20',

# DF_SoLSA
'SAI': '4F30',
'SLL': '4F31',

# DF_MExE
'MExE-ST': '4F40',
'ORPK': '4F41',
'ARPK': '4F42',
'TPRPK': '4F43',

# DF_GSM
'LP': '6F05',
'IMSI': '6F07',
'Kc': '6F20',
'DCK': '6F2C',
'PLMNsel': '6F30',
'HPPLMN': '6F31',
'CNL': '6F32',
'ACMmax': '6F37',
'SST': '6F38',
'ACM': '6F39',
'GID1': '6F3E',
'GID2': '6F3F',
'PUCT': '6F41',
'CBMI': '6F45',
'SPN': '6F46',
'CBMID': '6F48',
'BCCH': '6F74',
'ACC': '6F78',
'FPLMN': '6F7B',
'LOCI': '6F7E',
'AD': '6FAD',
'PHASE': '6FAE',
'VGCS': '6FB1',
'VGCSS': '6FB2',
'VBS': '6FB3',
'VBSS': '6FB4',
'eMLPP': '6FB5',
'AAeM': '6FB6',
'ECC': '6FB7',
'CBMIR': '6F50',
'NIA': '6F51',
'KcGPRS': '6F52',
'LOCIGPRS': '6F53',
'SUME': '6F54',
'PLMNwAcT': '6F60',
'OPLMNwAcT': '6F61',
# Figure 8 names it HPLMNAcT, but in the text it's names it HPLMNwAcT
'HPLMNAcT': '6F62',
'HPLMNwAcT': '6F62',
'CPBCCH': '6F63',
'INVSCAN': '6F64',
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
}

DF = {
'TELECOM':  [MF_num, DF_num['TELECOM']],

'GSM':      [MF_num, DF_num['GSM']],
'IS-41':    [MF_num, DF_num['IS-41']],
'FP-CTS':   [MF_num, DF_num['FP-CTS']],

'GRAPHICS': [MF_num, DF_num['GRAPHICS']],

'IRIDIUM':  [MF_num, DF_num['IRIDIUM']],
'GLOBST':   [MF_num, DF_num['GLOBST']],
'ICO':      [MF_num, DF_num['ICO']],
'ACeS':     [MF_num, DF_num['ACeS']],

'EIA/TIA-553': [MF_num, DF_num['EIA/TIA-553']],
'CTS':      [MF_num, DF_num['CTS']],
'SoLSA':    [MF_num, DF_num['SOLSA']],

'MExE':     [MF_num, DF_num['MExE']],
}


EF = {
'ICCID':  [MF_num, EF_num['ICCID']],
'ELP':    [MF_num, EF_num['ELP']],
'DIR':    [MF_num, EF_num['DIR']],

'ADN':    DF['TELECOM']+[EF_num['ADN']],
'FDN':    DF['TELECOM']+[EF_num['FDN']],
'SMS':    DF['TELECOM']+[EF_num['SMS']],
'CCP':    DF['TELECOM']+[EF_num['CCP']],
'MSISDN': DF['TELECOM']+[EF_num['MSISDN']],
'SMSP':   DF['TELECOM']+[EF_num['SMSP']],
'SMSS':   DF['TELECOM']+[EF_num['SMSS']],
'LND':    DF['TELECOM']+[EF_num['LND']],
'SMSR':   DF['TELECOM']+[EF_num['SMSR']],
'SDN':    DF['TELECOM']+[EF_num['SDN']],
'EXT1':   DF['TELECOM']+[EF_num['EXT1']],
'EXT2':   DF['TELECOM']+[EF_num['EXT2']],
'EXT3':   DF['TELECOM']+[EF_num['EXT3']],
'BDN':    DF['TELECOM']+[EF_num['BDN']],
'EXT4':   DF['TELECOM']+[EF_num['EXT4']],
'CMI':    DF['TELECOM']+[EF_num['CMI']],
'ECCP':   DF['TELECOM']+[EF_num['ECCP']],

'IMG':    DF['GRAPHICS']+[EF_num['IMG']],

'SAI':    DF['SoLSA']+[EF_num['SAI']],
'SLL':    DF['SoLSA']+[EF_num['SLL']],

'MExE-ST': DF['MExE']+[EF_num['MExE-ST']],
'ORPK':   DF['MExE']+[EF_num['ORPK']],
'ARPK':   DF['MExE']+[EF_num['ARPK']],
'TPRPK':  DF['MExE']+[EF_num['TPRPK']],

'LP':     DF['GSM']+[EF_num['LP']],
'IMSI':   DF['GSM']+[EF_num['IMSI']],
'Kc':     DF['GSM']+[EF_num['Kc']],
'DCK':    DF['GSM']+[EF_num['DCK']],
'PLMNsel': DF['GSM']+[EF_num['PLMNsel']],
'HPPLMN': DF['GSM']+[EF_num['HPPLMN']],
'CNL':    DF['GSM']+[EF_num['CNL']],
'ACMmax': DF['GSM']+[EF_num['ACMmax']],
'SST':    DF['GSM']+[EF_num['SST']],
'ACM':    DF['GSM']+[EF_num['ACM']],
'GID1':   DF['GSM']+[EF_num['GID1']],
'GID2':   DF['GSM']+[EF_num['GID2']],
'PUCT':   DF['GSM']+[EF_num['PUCT']],
'CBMI':   DF['GSM']+[EF_num['CBMI']],
'SPN':    DF['GSM']+[EF_num['SPN']],
'CBMID':  DF['GSM']+[EF_num['CBMID']],
'BCCH':   DF['GSM']+[EF_num['BCCH']],
'ACC':    DF['GSM']+[EF_num['ACC']],
'FPLMN':  DF['GSM']+[EF_num['FPLMN']],
'LOCI':   DF['GSM']+[EF_num['LOCI']],
'AD':     DF['GSM']+[EF_num['AD']],
'PHASE':  DF['GSM']+[EF_num['PHASE']],
'VGCS':   DF['GSM']+[EF_num['VGCS']],
'VGCSS':  DF['GSM']+[EF_num['VGCSS']],
'VBS':    DF['GSM']+[EF_num['VBS']],
'VBSS':   DF['GSM']+[EF_num['VBSS']],
'eMLPP':  DF['GSM']+[EF_num['eMLPP']],
'AAeM':   DF['GSM']+[EF_num['AAeM']],
'ECC':    DF['GSM']+[EF_num['ECC']],
'CBMIR':  DF['GSM']+[EF_num['CBMIR']],
'NIA':    DF['GSM']+[EF_num['NIA']],
'KcGPRS': DF['GSM']+[EF_num['KcGPRS']],
'LOCIGPRS': DF['GSM']+[EF_num['LOCIGPRS']],
'SUME':   DF['GSM']+[EF_num['SUME']],
'PLMNwAcT': DF['GSM']+[EF_num['PLMNwAcT']],
'OPLMNwAcT': DF['GSM']+[EF_num['OPLMNwAcT']],
# Figure 8 names it HPLMNAcT, but in the text it's names it HPLMNwAcT
'HPLMNAcT': DF['GSM']+[EF_num['HPLMNAcT']],
'HPLMNwAcT': DF['GSM']+[EF_num['HPLMNAcT']],
'CPBCCH': DF['GSM']+[EF_num['CPBCCH']],
'INVSCAN': DF['GSM']+[EF_num['INVSCAN']],
'PNN':    DF['GSM']+[EF_num['PNN']],
'OPL':    DF['GSM']+[EF_num['OPL']],
'MBDN':   DF['GSM']+[EF_num['MBDN']],
'EXT6':   DF['GSM']+[EF_num['EXT6']],
'MBI':    DF['GSM']+[EF_num['MBI']],
'MWIS':   DF['GSM']+[EF_num['MWIS']],
'CFIS':   DF['GSM']+[EF_num['CFIS']],
'EXT7':   DF['GSM']+[EF_num['EXT7']],
'SPDI':   DF['GSM']+[EF_num['SPDI']],
'MMSN':   DF['GSM']+[EF_num['MMSN']],
'EXT8':   DF['GSM']+[EF_num['EXT8']],
'MMSICP': DF['GSM']+[EF_num['MMSICP']],
'MMSUP':  DF['GSM']+[EF_num['MMSUP']],
'MMSUCP': DF['GSM']+[EF_num['MMSUCP']],
}

# Mapping between SIM Service Number and its description
EF_SST_map = {
	1: 'CHV1 disable function',
	2: 'Abbreviated Dialling Numbers (ADN)',
	3: 'Fixed Dialling Numbers (FDN)',
	4: 'Short Message Storage (SMS)',
	5: 'Advice of Charge (AoC)',
	6: 'Capability Configuration Parameters (CCP)',
	7: 'PLMN selector',
	8: 'RFU',
	9: 'MSISDN',
	10: 'Extension1',
	11: 'Extension2',
	12: 'SMS Parameters',
	13: 'Last Number Dialled (LND)',
	14: 'Cell Broadcast Message Identifier',
	15: 'Group Identifier Level 1',
	16: 'Group Identifier Level 2',
	17: 'Service Provider Name',
	18: 'Service Dialling Numbers (SDN)',
	19: 'Extension3',
	20: 'RFU',
	21: 'VGCS Group Identifier List (EFVGCS and EFVGCSS)',
	22: 'VBS Group Identifier List (EFVBS and EFVBSS)',
	23: 'enhanced Multi-Level Precedence and Pre-emption Service',
	24: 'Automatic Answer for eMLPP',
	25: 'Data download via SMS-CB',
	26: 'Data download via SMS-PP',
	27: 'Menu selection',
	28: 'Call control',
	29: 'Proactive SIM',
	30: 'Cell Broadcast Message Identifier Ranges',
	31: 'Barred Dialling Numbers (BDN)',
	32: 'Extension4',
	33: 'De-personalization Control Keys',
	34: 'Co-operative Network List',
	35: 'Short Message Status Reports',
	36: 'Network\'s indication of alerting in the MS',
	37: 'Mobile Originated Short Message control by SIM',
	38: 'GPRS',
	39: 'Image (IMG)',
	40: 'SoLSA (Support of Local Service Area)',
	41: 'USSD string data object supported in Call Control',
	42: 'RUN AT COMMAND command',
	43: 'User controlled PLMN Selector with Access Technology',
	44: 'Operator controlled PLMN Selector with Access Technology',
	45: 'HPLMN Selector with Access Technology',
	46: 'CPBCCH Information',
	47: 'Investigation Scan',
	48: 'Extended Capability Configuration Parameters',
	49: 'MExE',
	50: 'Reserved and shall be ignored',
	51: 'PLMN Network Name',
	52: 'Operator PLMN List',
	53: 'Mailbox Dialling Numbers',
	54: 'Message Waiting Indication Status',
	55: 'Call Forwarding Indication Status',
	56: 'Service Provider Display Information',
	57: 'Multimedia Messaging Service (MMS)',
	58: 'Extension 8',
	59: 'MMS User Connectivity Parameters',
}

# 10.3.18 "EF.AD (Administrative data) "
EF_AD_mode_map = {
	'00' : 'normal operation',
	'80' : 'type approval operations',
	'01' : 'normal operation + specific facilities',
	'81' : 'type approval operations + specific facilities',
	'02' : 'maintenance (off line)',
	'04' : 'cell test operation',
}


from pySim.utils import *
from struct import pack, unpack

from pySim.filesystem import *
import pySim.ts_102_221

######################################################################
# DF.TELECOM
######################################################################

# TS 51.011 Section 10.5.1
class EF_ADN(LinFixedEF):
    def __init__(self, fid='6f3a', sfid=None, name='EF.ADN', desc='Abbreviated Dialing Numbers'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={14, 30})
    def _decode_record_bin(self, raw_bin_data):
        alpha_id_len = len(raw_bin_data) - 14
        alpha_id = raw_bin_data[:alpha_id_len]
        u = unpack('!BB10sBB', raw_bin_data[-14:])
        return {'alpha_id': alpha_id, 'len_of_bcd': u[0], 'ton_npi': u[1],
                'dialing_nr': u[2], 'cap_conf_id': u[3], 'ext1_record_id': u[4]}

# TS 51.011 Section 10.5.5
class EF_MSISDN(LinFixedEF):
    def __init__(self, fid='6f4f', sfid=None, name='EF.MSISDN', desc='MSISDN'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={15, None})
    def _decode_record_hex(self, raw_hex_data):
        return {'msisdn': dec_msisdn(raw_hex_data)}
    def _encode_record_hex(self, abstract):
        return enc_msisdn(abstract['msisdn'])

# TS 51.011 Section 10.5.6
class EF_SMSP(LinFixedEF):
    def __init__(self, fid='6f42', sfid=None, name='EF.SMSP', desc='Short message service parameters'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={28, None})

class DF_TELECOM(CardDF):
    def __init__(self, fid='7f10', name='DF.TELECOM', desc=None):
        super().__init__(fid=fid, name=name, desc=desc)
        files = [
          EF_ADN(),
          # FDN, SMS, CCP, ECCP
          EF_MSISDN(),
          EF_SMSP(),
          # SMSS, LND, SDN, EXT1, EXT2, EXT3, BDN, EXT4, SMSR, CMI
          ]
        self.add_files(files)

    def decode_select_response(self, data_hex):
        return decode_select_response(data_hex)

######################################################################
# DF.GSM
######################################################################

# TS 51.011 Section 10.3.1
class EF_LP(TransRecEF):
    def __init__(self, fid='6f05', sfid=None, name='EF.LP', size={1,None}, rec_len=1,
                 desc='Language Preference'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
    def _decode_record_bin(self, in_bin):
        return b2h(in_bin)
    def _encode_record_bin(self, in_json):
        return h2b(in_json)

# TS 51.011 Section 10.3.2
class EF_IMSI(TransparentEF):
    def __init__(self, fid='6f07', sfid=None, name='EF.IMSI', desc='IMSI', size={9,9}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
    def _decode_hex(self, raw_hex):
        return {'imsi': dec_imsi(raw_hex)}
    def _encode_hex(self, abstract):
        return enc_imsi(abstract['imsi'])

# TS 51.011 Section 10.3.4
class EF_PLMNsel(TransRecEF):
    def __init__(self, fid='6f30', sfid=None, name='EF.PLMNsel', desc='PLMN selector',
                 size={24,None}, rec_len=3):
        super().__init__(fid, name=name, sfid=sfid, desc=desc, size=size, rec_len=rec_len)
    def _decode_record_hex(self, in_hex):
        if in_hex[:6] == "ffffff":
            return None
        else:
            return dec_plmn(in_hex)
    def _encode_record_hex(self, in_json):
        if in_json == None:
            return "ffffff"
        else:
            return enc_plmn(in_json['mcc'], in_json['mnc'])

# TS 51.011 Section 10.3.7
class EF_ServiceTable(TransparentEF):
    def __init__(self, fid, sfid, name, desc, size, table):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self.table = table
    def _decode_bin(self, raw_bin):
        ret = {}
        for i in range(0, len(raw_bin)*4):
            service_nr = i+1
            byte = int(raw_bin[i//4])
            bit_offset = (i % 4) * 2
            bits = (byte >> bit_offset) & 3
            ret[service_nr] = {
                     'description': self.table[service_nr] or None,
                     'allocated': True if bits & 1 else False,
                     'activated': True if bits & 2 else False,
                     }
        return ret
    # TODO: encoder

# TS 51.011 Section 10.3.11
class EF_SPN(TransparentEF):
    def __init__(self, fid='6f46', sfid=None, name='EF.SPN', desc='Service Provider Name', size={17,17}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
    def _decode_hex(self, raw_hex):
        return {'spn': dec_spn(raw_hex)}
    def _encode_hex(self, abstract):
        return enc_spn(abstract['spn'])

# TS 51.011 Section 10.3.13
class EF_CBMI(TransRecEF):
    def __init__(self, fid='6f45', sfid=None, name='EF.CBMI', size={2,None}, rec_len=2,
                 desc='Cell Broadcast message identifier selection'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)

# TS 51.011 Section 10.3.15
class EF_ACC(TransparentEF):
    def __init__(self, fid='6f78', sfid=None, name='EF.ACC', desc='Access Control Class', size={2,2}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
    def _decode_bin(self, raw_bin):
        return {'acc': unpack('!H', raw_bin)[0]}
    def _encode_bin(self, abstract):
        return pack('!H', abstract['acc'])

# TS 51.011 Section 10.3.18
class EF_AD(TransparentEF):
    OP_MODE = {
            0x00: 'normal operation',
            0x80: 'type approval operations',
            0x01: 'normal operation + specific facilities',
            0x81: 'type approval + specific facilities',
            0x02: 'maintenance (off line)',
            0x04: 'cell test operation',
        }
    def __init__(self, fid='6fad', sfid=None, name='EF.AD', desc='Administrative Data', size={3,4}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
    def _decode_bin(self, raw_bin):
        u = unpack('!BH', raw_bin[:3])

# TS 51.011 Section 10.3.13
class EF_CBMID(EF_CBMI):
    def __init__(self, fid='6f48', sfid=None, name='EF.CBMID', size={2,None}, rec_len=2,
                 desc='Cell Broadcast Message Identifier for Data Download'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)

# TS 51.011 Section 10.3.26
class EF_ECC(LinFixedEF):
    def __init__(self, fid='6fb7', sfid=None, name='EF.ECC', desc='Emergency Call Codes'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={4, 20})

# TS 51.011 Section 10.3.28
class EF_CBMIR(TransRecEF):
    def __init__(self, fid='6f50', sfid=None, name='EF.CBMIR', size={4,None}, rec_len=4,
                 desc='Cell Broadcast message identifier range selection'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)


# TS 51.011 Section 10.3.35..37
class EF_xPLMNwAcT(TransRecEF):
    def __init__(self, fid, sfid=None, name=None, desc=None, size={40,None}, rec_len=5):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
    def _decode_record_hex(self, in_hex):
        if in_hex[:6] == "ffffff":
            return None
        else:
            return dec_xplmn_w_act(in_hex)
    def _encode_record_hex(self, in_json):
        if in_json == None:
            return "ffffff0000"
        else:
            hplmn = enc_plmn(in_json['mcc'], in_json['mnc'])
            act = self.enc_act(in_json['act'])
            return hplmn + act
    @staticmethod
    def enc_act(in_list):
        u16 = 0
        # first the simple ones
        if 'UTRAN' in in_list:
            u16 |= 0x8000
        if 'NG-RAN' in in_list:
            u16 |= 0x0800
        if 'GSM COMPACT' in in_list:
            u16 |= 0x0040
        if 'cdma2000 HRPD' in in_list:
            u16 |= 0x0020
        if 'cdma2000 1xRTT' in in_list:
            u16 |= 0x0010
        # E-UTRAN
        if 'E-UTRAN WB-S1' and 'E-UTRAN NB-S1' in in_list:
            u16 |= 0x7000   # WB-S1 and NB-S1
        elif 'E-UTRAN NB-S1' in in_list:
            u16 |= 0x6000   # only WB-S1
        elif 'E-UTRAN NB-S1' in in_list:
            u16 |= 0x5000   # only NB-S1
        # GSM mess
        if 'GSM' in in_list and 'EC-GSM-IoT' in in_list:
            u16 |= 0x008C
        elif 'GSM' in in_list:
            u16 |= 0x0084
        elif 'EC-GSM-IuT' in in_list:
            u16 |= 0x0088
        return '%04X'%(u16)


class DF_GSM(CardDF):
    def __init__(self, fid='7f20', name='DF.GSM', desc='GSM Network related files'):
        super().__init__(fid=fid, name=name, desc=desc)
        files = [
          EF_LP(),
          EF_IMSI(),
          TransparentEF('5f20', None, 'EF.Kc', 'Ciphering key Kc'),
          EF_PLMNsel(),
          TransparentEF('6f31', None, 'EF.HPPLMN', 'Higher Priority PLMN search period'),
          # ACMmax
          EF_ServiceTable('6f37', None, 'EF.SST', 'SIM service table', table=EF_SST_map, size={2,16}),
          CyclicEF('6f39', None, 'EF.ACM', 'Accumulated call meter', rec_len={4,3}),
          TransparentEF('6f3e', None, 'EF.GID1', 'Group Identifier Level 1'),
          TransparentEF('6f3f', None, 'EF.GID2', 'Group Identifier Level 2'),
          EF_SPN(),
          TransparentEF('6f41', None, 'EF.PUCT', 'Price per unit and currency table', size={5,5}),
          EF_CBMI(),
          TransparentEF('6f7f', None, 'EF.BCCH', 'Broadcast control channels', size={16,16}),
          EF_ACC(),
          EF_PLMNsel('6f7b', None, 'EF.FPLMN', 'Forbidden PLMNs', size={12,12}),
          TransparentEF('6f7e', None, 'EF.LOCI', 'Locationn information', size={11,11}),
          EF_AD(),
          TransparentEF('6fa3', None, 'EF.Phase', 'Phase identification', size={1,1}),
        # TODO EF.VGCS VGCSS, VBS, VBSS, eMLPP, AAeM
          EF_CBMID(),
          EF_ECC(),
          EF_CBMIR(),
          # DCK, CNL, NIA, KcGRS, LOCIGPRS, SUME
          EF_xPLMNwAcT('6f60', None, 'EF.PLMNwAcT',
                                   'User controlled PLMN Selector with Access Technology'),
          EF_xPLMNwAcT('6f61', None, 'EF.OPLMNwAcT',
                                   'Operator controlled PLMN Selector with Access Technology'),
          EF_xPLMNwAcT('6f62', None, 'EF.HPLMNwAcT', 'HPLMN Selector with Access Technology'),
          # CPBCCH, InvScan, PNN, OPL, MBDN, MBI, MWIS, CFIS, EXT5, EXT6, EXT7, SPDI, MMSN, EXT8
          # MMSICP, MMSUP, MMSUCP
          ]
        self.add_files(files)

    def decode_select_response(self, data_hex):
        return decode_select_response(data_hex)

def decode_select_response(resp_hex):
    resp_bin = h2b(resp_hex)
    if resp_bin[0] == 0x62:
        return pySim.ts_102_221.decode_select_response(resp_hex)
    struct_of_file_map = {
        0: 'transparent',
        1: 'linear_fixed',
        3: 'cyclic'
        }
    type_of_file_map = {
        1: 'mf',
        2: 'df',
        4: 'working_ef'
        }
    ret = {
        'file_descriptor': {},
        'proprietary_info': {},
        }
    ret['file_id'] = b2h(resp_bin[4:6])
    ret['proprietary_info']['available_memory'] = int.from_bytes(resp_bin[2:4], 'big')
    file_type = type_of_file_map[resp_bin[6]] if resp_bin[6] in type_of_file_map else resp_bin[6]
    ret['file_descriptor']['file_type'] = file_type
    if file_type in ['mf', 'df']:
        ret['file_characteristics'] = b2h(resp_bin[13])
        ret['num_direct_child_df'] = int(resp_bin[14], 16)
        ret['num_direct_child_ef'] = int(resp_bin[15], 16)
        ret['num_chv_unbkock_adm_codes'] = int(resp_bin[16])
        # CHV / UNBLOCK CHV stats
    elif file_type in ['working_ef']:
        file_struct = struct_of_file_map[resp_bin[13]] if resp_bin[13] in struct_of_file_map else resp_bin[13]
        ret['file_descriptor']['structure'] = file_struct
        ret['access_conditions'] = b2h(resp_bin[8:10])
        if resp_bin[11] & 0x01 == 0:
            ret['life_cycle_status_int'] = 'operational_activated'
        elif resp_bin[11] & 0x04:
            ret['life_cycle_status_int'] = 'operational_deactivated'
        else:
            ret['life_cycle_status_int'] = 'terminated'

    return ret

CardProfileSIM = CardProfile('SIM', desc='GSM SIM Card', files_in_mf=[DF_TELECOM(), DF_GSM()])
