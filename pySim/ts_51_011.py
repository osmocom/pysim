# -*- coding: utf-8 -*-

# without this, pylint will fail when inner classes are used
# within the 'nested' kwarg of our TlvMeta metaclass on python 3.7 :(
# pylint: disable=undefined-variable

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

from pySim.utils import *
from pySim.tlv import *
from struct import pack, unpack
from construct import *
from construct import Optional as COptional
from pySim.construct import *
import enum

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
class EF_SMS(LinFixedEF):
    def __init__(self, fid='6f3c', sfid=None, name='EF.SMS', desc='Short messages'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={176,176})
    def _decode_record_bin(self, raw_bin_data):
        def decode_status(status):
            if status & 0x01 == 0x00:
                return (None, 'free_space')
            elif status & 0x07 == 0x01:
                return ('mt', 'message_read')
            elif status & 0x07 == 0x03:
                return ('mt', 'message_to_be_read')
            elif status & 0x07 == 0x07:
                return ('mo', 'message_to_be_sent')
            elif status & 0x1f == 0x05:
                return ('mo', 'sent_status_not_requested')
            elif status & 0x1f == 0x0d:
                return ('mo', 'sent_status_req_but_not_received')
            elif status & 0x1f == 0x15:
                return ('mo', 'sent_status_req_rx_not_stored_smsr')
            elif status & 0x1f == 0x1d:
                return ('mo', 'sent_status_req_rx_stored_smsr')
            else:
                return (None, 'rfu')

        status = decode_status(raw_bin_data[0])
        remainder = raw_bin_data[1:]
        return {'direction': status[0], 'status': status[1], 'remainder': b2h(remainder)}


# TS 51.011 Section 10.5.5
class EF_MSISDN(LinFixedEF):
    def __init__(self, fid='6f40', sfid=None, name='EF.MSISDN', desc='MSISDN'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={15, 34})
    def _decode_record_hex(self, raw_hex_data):
        return {'msisdn': dec_msisdn(raw_hex_data)}
    def _encode_record_hex(self, abstract):
        msisdn = abstract['msisdn']
        if type(msisdn) == str:
            encoded_msisdn = enc_msisdn(msisdn)
        else:
            encoded_msisdn = enc_msisdn(msisdn[2],msisdn[0],msisdn[1])
        alpha_identifier = (list(self.rec_len)[0] - len(encoded_msisdn) // 2) * "ff"
        return alpha_identifier + encoded_msisdn

# TS 51.011 Section 10.5.6
class EF_SMSP(LinFixedEF):
    def __init__(self, fid='6f42', sfid=None, name='EF.SMSP', desc='Short message service parameters'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len={28, None})

# TS 51.011 Section 10.5.7
class EF_SMSS(TransparentEF):
    class MemCapAdapter(Adapter):
        def _decode(self, obj, context, path):
            return False if obj & 1 else True
        def _encode(self, obj, context, path):
            return 0 if obj else 1
    def __init__(self, fid='6f43', sfid=None, name='EF.SMSS', desc='SMS status', size={2,8}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('last_used_tpmr'/Int8ub, 'memory_capacity_exceeded'/self.MemCapAdapter(Int8ub))

# TS 51.011 Section 10.5.8
class EF_SMSR(LinFixedEF):
    def __init__(self, fid='6f47', sfid=None, name='EF.SMSR', desc='SMS status reports', rec_len={30,30}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('sms_record_id'/Int8ub, 'sms_status_report'/HexAdapter(Bytes(29)))

class EF_EXT(LinFixedEF):
    def __init__(self, fid, sfid=None, name='EF.EXT', desc='Extension', rec_len={13,13}):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('record_type'/Int8ub, 'extension_data'/HexAdapter(Bytes(11)), 'identifier'/Int8ub)

# TS 51.011 Section 10.5.16
class EF_CMI(LinFixedEF):
    def __init__(self, fid='6f58', sfid=None, name='EF.CMI', rec_len={2,21},
                 desc='Comparison Method Information'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('alpha_id'/Bytes(this._.total_len-1), 'comparison_method_id'/Int8ub)

class DF_TELECOM(CardDF):
    def __init__(self, fid='7f10', name='DF.TELECOM', desc=None):
        super().__init__(fid=fid, name=name, desc=desc)
        files = [
          EF_ADN(),
          EF_ADN(fid='6f3b', name='EF_FDN', desc='Fixed dialling numbers'),
          EF_SMS(),
          LinFixedEF(fid='6f3d', name='EF.CCP', desc='Capability Configuration Parameters', rec_len={14,14}),
          LinFixedEF(fid='6f4f', name='EF.ECCP', desc='Extended Capability Configuration Parameters', rec_len={15,32}),
          EF_MSISDN(),
          EF_SMSP(),
          EF_SMSS(),
          # LND, SDN
          EF_EXT('6f4a', None, 'EF.EXT1', 'Extension1 (ADN/SSC)'),
          EF_EXT('6f4b', None, 'EF.EXT2', 'Extension2 (FDN/SSC)'),
          EF_EXT('6f4c', None, 'EF.EXT3', 'Extension3 (SDN)'),
          EF_ADN(fid='6f4d', name='EF.BDN', desc='Barred Dialling Numbers'),
          EF_EXT('6f4e', None, 'EF.EXT4', 'Extension4 (BDN/SSC)'),
          EF_SMSR(),
          EF_CMI(),
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

# TS 51.011 Section 10.3.6
class EF_ACMmax(TransparentEF):
    def __init__(self, fid='6f37', sfid=None, name='EF.ACMmax', size={3,3},
                 desc='ACM maximum value'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('acm_max'/Int24ub)

# TS 51.011 Section 10.3.7
class EF_ServiceTable(TransparentEF):
    def __init__(self, fid, sfid, name, desc, size, table):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self.table = table
    @staticmethod
    def _bit_byte_offset_for_service(service:int) -> (int, int):
        i = service - 1
        byte_offset = i//4
        bit_offset = (i % 4) * 2
        return (byte_offset, bit_offset)
    def _decode_bin(self, raw_bin):
        ret = {}
        for i in range(0, len(raw_bin)*4):
            service_nr = i+1
            byte = int(raw_bin[i//4])
            bit_offset = (i % 4) * 2
            bits = (byte >> bit_offset) & 3
            ret[service_nr] = {
                     'description': self.table[service_nr] if service_nr in self.table else None,
                     'allocated': True if bits & 1 else False,
                     'activated': True if bits & 2 else False,
                     }
        return ret
    def _encode_bin(self, in_json):
        # compute the required binary size
        bin_len = 0
        for srv in in_json.keys():
            service_nr = int(srv)
            (byte_offset, bit_offset) = EF_ServiceTable._bit_byte_offset_for_service(service_nr)
            if byte_offset >= bin_len:
                bin_len = byte_offset+1
        # encode the actual data
        out = bytearray(b'\x00' * bin_len)
        for srv in in_json.keys():
            service_nr = int(srv)
            (byte_offset, bit_offset) = EF_ServiceTable._bit_byte_offset_for_service(service_nr)
            bits = 0
            if in_json[srv]['allocated'] == True:
                bits |= 1
            if in_json[srv]['activated'] == True:
                bits |= 2
            out[byte_offset] |= ((bits & 3) << bit_offset)
        return out

# TS 51.011 Section 10.3.11
class EF_SPN(TransparentEF):
    def __init__(self, fid='6f46', sfid=None, name='EF.SPN', desc='Service Provider Name', size={17,17}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = BitStruct(
            # Byte 1
            'rfu'/BitsRFU(6),
            'hide_in_oplmn'/Flag,
            'show_in_hplmn'/Flag,
            # Bytes 2..17
            'spn'/Bytewise(GsmString(16))
        )

# TS 51.011 Section 10.3.13
class EF_CBMI(TransRecEF):
    def __init__(self, fid='6f45', sfid=None, name='EF.CBMI', size={2,None}, rec_len=2,
                 desc='Cell Broadcast message identifier selection'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
        self._construct = GreedyRange(Int16ub)

# TS 51.011 Section 10.3.15
class EF_ACC(TransparentEF):
    def __init__(self, fid='6f78', sfid=None, name='EF.ACC', desc='Access Control Class', size={2,2}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
    def _decode_bin(self, raw_bin):
        return {'acc': unpack('!H', raw_bin)[0]}
    def _encode_bin(self, abstract):
        return pack('!H', abstract['acc'])

# TS 51.011 Section 10.3.16
class EF_LOCI(TransparentEF):
    def __init__(self, fid='6f7e', sfid=None, name='EF.LOCI', desc='Location Information', size={11,11}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('tmsi'/Bytes(4), 'lai'/Bytes(5), 'tmsi_time'/Int8ub,
                                 'lu_status'/Enum(Byte, updated=0, not_updated=1, plmn_not_allowed=2,
                                                  location_area_not_allowed=3))

# TS 51.011 Section 10.3.18
class EF_AD(TransparentEF):
    class OP_MODE(enum.IntEnum):
        normal                                  = 0x00
        type_approval                           = 0x80
        normal_and_specific_facilities          = 0x01
        type_approval_and_specific_facilities   = 0x81
        maintenance_off_line                    = 0x02
        cell_test                               = 0x04
    #OP_MODE_DICT = {int(v) : str(v) for v in EF_AD.OP_MODE}
    #OP_MODE_DICT_REVERSED = {str(v) : int(v) for v in EF_AD.OP_MODE}

    def __init__(self, fid='6fad', sfid=None, name='EF.AD', desc='Administrative Data', size={3,4}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = BitStruct(
            # Byte 1
            'ms_operation_mode'/Bytewise(Enum(Byte, EF_AD.OP_MODE)),
            # Byte 2
            'rfu1'/Bytewise(ByteRFU),
            # Byte 3
            'rfu2'/BitsRFU(7),
            'ofm'/Flag,
            # Byte 4 (optional),
            'extensions'/COptional(Struct(
                'rfu3'/BitsRFU(4),
                'mnc_len'/BitsInteger(4),
                # Byte 5..N-4 (optional, RFU)
                'extensions'/Bytewise(GreedyBytesRFU)
            ))
        )

# TS 51.011 Section 10.3.20 / 10.3.22
class EF_VGCS(TransRecEF):
    def __init__(self, fid='6fb1', sfid=None, name='EF.VGCS', size={4,200}, rec_len=4,
                 desc='Voice Group Call Service'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
        self._construct = BcdAdapter(Bytes(4))

# TS 51.011 Section 10.3.21 / 10.3.23
class EF_VGCSS(TransparentEF):
    def __init__(self, fid='6fb2', sfid=None, name='EF.VGCSS', size={7,7},
                 desc='Voice Group Call Service Status'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = BitStruct('flags'/Bit[50], Padding(6, pattern=b'\xff'))

# TS 51.011 Section 10.3.24
class EF_eMLPP(TransparentEF):
    def __init__(self, fid='6fb5', sfid=None, name='EF.eMLPP', size={2,2},
                 desc='enhanced Multi Level Pre-emption and Priority'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        FlagsConstruct = FlagsEnum(Byte, A=1, B=2, zero=4, one=8, two=16, three=32, four=64)
        self._construct = Struct('levels'/FlagsConstruct, 'fast_call_setup_cond'/FlagsConstruct)

# TS 51.011 Section 10.3.25
class EF_AAeM(TransparentEF):
    def __init__(self, fid='6fb6', sfid=None, name='EF.AAeM', size={1,1},
                 desc='Automatic Answer for eMLPP Service'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        FlagsConstruct = FlagsEnum(Byte, A=1, B=2, zero=4, one=8, two=16, three=32, four=64)
        self._construct = Struct('auto_answer_prio_levels'/FlagsConstruct)

# TS 51.011 Section 10.3.26
class EF_CBMID(EF_CBMI):
    def __init__(self, fid='6f48', sfid=None, name='EF.CBMID', size={2,None}, rec_len=2,
                 desc='Cell Broadcast Message Identifier for Data Download'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
        self._construct = GreedyRange(Int16ub)

# TS 51.011 Section 10.3.27
class EF_ECC(TransRecEF):
    def __init__(self, fid='6fb7', sfid=None, name='EF.ECC', size={3,15}, rec_len=3,
                 desc='Emergency Call Codes'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
        self._construct = GreedyRange(BcdAdapter(Bytes(3)))

# TS 51.011 Section 10.3.28
class EF_CBMIR(TransRecEF):
    def __init__(self, fid='6f50', sfid=None, name='EF.CBMIR', size={4,None}, rec_len=4,
                 desc='Cell Broadcast message identifier range selection'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
        self._construct = GreedyRange(Struct('lower'/Int16ub, 'upper'/Int16ub))

# TS 51.011 Section 10.3.29
class EF_DCK(TransparentEF):
    def __init__(self, fid='6f2c', sfid=None, name='EF.DCK', size={16,16},
                 desc='Depersonalisation Control Keys'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('network'/BcdAdapter(Bytes(4)),
                                 'network_subset'/BcdAdapter(Bytes(4)),
                                 'service_provider'/BcdAdapter(Bytes(4)),
                                 'corporate'/BcdAdapter(Bytes(4)))
# TS 51.011 Section 10.3.30
class EF_CNL(TransRecEF):
    def __init__(self, fid='6f32', sfid=None, name='EF.CNL', size={6,None}, rec_len=6,
                 desc='Co-operative Network List'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
    def _decode_record_hex(self, in_hex):
        (in_plmn, sub, svp, corp) = unpack('!3sBBB', h2b(in_hex))
        res = dec_plmn(b2h(in_plmn))
        res['network_subset'] = sub
        res['service_provider_id'] = svp
        res['corporate_id'] = corp
        return res
    def _encode_record_hex(self, in_json):
        plmn = enc_plmn(in_json['mcc'], in_json['mnc'])
        return b2h(pack('!3sBBB',
                        h2b(plmn),
                        in_json['network_subset'],
                        in_json['service_provider_id'],
                        in_json['corporate_id']))

# TS 51.011 Section 10.3.31
class EF_NIA(LinFixedEF):
    def __init__(self, fid='6f51', sfid=None, name='EF.NIA', rec_len={1,32},
                 desc='Network\'s Indication of Alerting'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('alerting_category'/Int8ub, 'category'/GreedyBytes)

# TS 51.011 Section 10.3.32
class EF_Kc(TransparentEF):
    def __init__(self, fid='6f20', sfid=None, name='EF.Kc', desc='Ciphering key Kc', size={9,9}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('kc'/HexAdapter(Bytes(8)), 'cksn'/Int8ub)

# TS 51.011 Section 10.3.33
class EF_LOCIGPRS(TransparentEF):
    def __init__(self, fid='6f53', sfid=None, name='EF.LOCIGPRS', desc='GPRS Location Information', size={14,14}):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = Struct('ptmsi'/Bytes(4), 'ptmsi_sig'/Int8ub, 'rai'/Bytes(6),
                                 'rau_status'/Enum(Byte, updated=0, not_updated=1, plmn_not_allowed=2,
                                                   routing_area_not_allowed=3))

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
        if 'E-UTRAN' in in_list:
            u16 |= 0x4000
        if 'E-UTRAN WB-S1' in in_list:
            u16 |= 0x6000
        if 'E-UTRAN NB-S1' in in_list:
            u16 |= 0x5000
        # GSM mess
        if 'GSM' in in_list and 'EC-GSM-IoT' in in_list:
            u16 |= 0x008C
        elif 'GSM' in in_list:
            u16 |= 0x0084
        elif 'EC-GSM-IuT' in in_list:
            u16 |= 0x0088
        return '%04X'%(u16)

# TS 51.011 Section 10.3.38
class EF_CPBCCH(TransRecEF):
    def __init__(self, fid='6f63', sfid=None, name='EF.CPBCCH', size={2,14}, rec_len=2,
                 desc='CPBCCH Information'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size, rec_len=rec_len)
        self._construct = Struct('cpbcch'/Int16ub)

# TS 51.011 Section 10.3.39
class EF_InvScan(TransparentEF):
    def __init__(self, fid='6f64', sfid=None, name='EF.InvScan', size={1,1},
                 desc='IOnvestigation Scan'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._construct = FlagsEnum(Byte, in_limited_service_mode=1, after_successful_plmn_selection=2)

# TS 51.011 Section 4.2.58
class EF_PNN(LinFixedEF):
    class FullNameForNetwork(BER_TLV_IE, tag=0x43):
        # TS 24.008 10.5.3.5a
        pass
    class ShortNameForNetwork(BER_TLV_IE, tag=0x45):
        # TS 24.008 10.5.3.5a
        pass
    class NetworkNameCollection(TLV_IE_Collection, nested=[FullNameForNetwork, ShortNameForNetwork]):
        pass
    def __init__(self, fid='6fc5', sfid=None, name='EF.PNN', desc='PLMN Network Name'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc)
        self._tlv = EF_PNN.NetworkNameCollection

# TS 51.011 Section 10.3.42
class EF_OPL(LinFixedEF):
    def __init__(self, fid='6fc6', sfid=None, name='EF.OPL', rec_len={8,8}, desc='Operator PLMN List'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('lai'/Bytes(5), 'pnn_record_id'/Int8ub)

# TS 51.011 Section 10.3.44 + TS 31.102 4.2.62
class EF_MBI(LinFixedEF):
    def __init__(self, fid='6fc9', sfid=None, name='EF.MBI', rec_len={4,5}, desc='Mailbox Identifier'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('mbi_voicemail'/Int8ub, 'mbi_fax'/Int8ub, 'mbi_email'/Int8ub,
                                 'mbi_other'/Int8ub, 'mbi_videocall'/COptional(Int8ub))

# TS 51.011 Section 10.3.45 + TS 31.102 4.2.63
class EF_MWIS(LinFixedEF):
    def __init__(self, fid='6fca', sfid=None, name='EF.MWIS', rec_len={5,6},
                 desc='Message Waiting Indication Status'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('mwi_status'/FlagsEnum(Byte, voicemail=1, fax=2, email=4, other=8, videomail=16),
                                 'num_waiting_voicemail'/Int8ub,
                                 'num_waiting_fax'/Int8ub, 'num_waiting_email'/Int8ub,
                                 'num_waiting_other'/Int8ub, 'num_waiting_videomail'/COptional(Int8ub))

# TS 51.011 Section 10.3.66
class EF_SPDI(TransparentEF):
    class ServiceProviderPLMN(BER_TLV_IE, tag=0x80):
        # flexible numbers of 3-byte PLMN records
        _construct = GreedyRange(BcdAdapter(Bytes(3)))
    class SPDI(BER_TLV_IE, tag=0xA3, nested=[ServiceProviderPLMN]):
        pass
    def __init__(self, fid='6fcd', sfid=None, name='EF.SPDI',
            desc='Service Provider Display Information'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc)
        self._tlv = EF_SPDI.SPDI

# TS 51.011 Section 10.3.51
class EF_MMSN(LinFixedEF):
    def __init__(self, fid='6fce', sfid=None, name='EF.MMSN', rec_len={4,20}, desc='MMS Notification'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self._construct = Struct('mms_status'/Bytes(2), 'mms_implementation'/Bytes(1),
                                 'mms_notification'/Bytes(this._.total_len-4), 'ext_record_nr'/Byte)

# TS 51.011 Annex K.1
class MMS_Implementation(BER_TLV_IE, tag=0x80):
    _construct = FlagsEnum(Byte, WAP=1)

# TS 51.011 Section 10.3.53
class EF_MMSICP(TransparentEF):
    class MMS_Relay_Server(BER_TLV_IE, tag=0x81):
        # 3GPP TS 23.140
        pass
    class Interface_to_CN(BER_TLV_IE, tag=0x82):
        # 3GPP TS 23.140
        pass
    class Gateway(BER_TLV_IE, tag=0x83):
        # Address, Type of address, Port, Service, AuthType, AuthId, AuthPass / 3GPP TS 23.140
        pass
    class MMS_ConnectivityParamters(TLV_IE_Collection,
            nested=[MMS_Implementation, MMS_Relay_Server, Interface_to_CN, Gateway]):
        pass
    def __init__(self, fid='6fd0', sfid=None, name='EF.MMSICP', size={1,None},
                 desc='MMS Issuer Connectivity Parameters'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)
        self._tlv = EF_MMSICP.MMS_ConnectivityParamters

# TS 51.011 Section 10.3.54
class EF_MMSUP(LinFixedEF):
    class MMS_UserPref_ProfileName(BER_TLV_IE, tag=0x81):
        pass
    class MMS_UserPref_Info(BER_TLV_IE, tag=0x82):
        pass
    class MMS_User_Preferences(TLV_IE_Collection,
            nested=[MMS_Implementation,MMS_UserPref_ProfileName,MMS_UserPref_Info]):
        pass
    def __init__(self, fid='6fd1', sfid=None, name='EF.MMSUP', rec_len={1,None},
                 desc='MMS User Preferences'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, rec_len=rec_len)
        self.tlv = EF_MMSUP.MMS_User_Preferences

# TS 51.011 Section 10.3.55
class EF_MMSUCP(TransparentEF):
    def __init__(self, fid='6fd2', sfid=None, name='EF.MMSUCP', size={1,None},
                 desc='MMS User Connectivity Parameters'):
        super().__init__(fid, sfid=sfid, name=name, desc=desc, size=size)


class DF_GSM(CardDF):
    def __init__(self, fid='7f20', name='DF.GSM', desc='GSM Network related files'):
        super().__init__(fid=fid, name=name, desc=desc)
        files = [
          EF_LP(),
          EF_IMSI(),
          EF_Kc(),
          EF_PLMNsel(),
          TransparentEF('6f31', None, 'EF.HPPLMN', 'Higher Priority PLMN search period'),
          EF_ACMmax(),
          EF_ServiceTable('6f38', None, 'EF.SST', 'SIM service table', table=EF_SST_map, size={2,16}),
          CyclicEF('6f39', None, 'EF.ACM', 'Accumulated call meter', rec_len={3,3}),
          TransparentEF('6f3e', None, 'EF.GID1', 'Group Identifier Level 1'),
          TransparentEF('6f3f', None, 'EF.GID2', 'Group Identifier Level 2'),
          EF_SPN(),
          TransparentEF('6f41', None, 'EF.PUCT', 'Price per unit and currency table', size={5,5}),
          EF_CBMI(),
          TransparentEF('6f7f', None, 'EF.BCCH', 'Broadcast control channels', size={16,16}),
          EF_ACC(),
          EF_PLMNsel('6f7b', None, 'EF.FPLMN', 'Forbidden PLMNs', size={12,12}),
          EF_LOCI(),
          EF_AD(),
          TransparentEF('6fa3', None, 'EF.Phase', 'Phase identification', size={1,1}),
          EF_VGCS(),
          EF_VGCSS(),
          EF_VGCS('6fb3', None, 'EF.VBS', 'Voice Broadcast Service'),
          EF_VGCSS('6fb4', None, 'EF.VBSS', 'Voice Broadcast Service Status'),
          EF_eMLPP(),
          EF_AAeM(),
          EF_CBMID(),
          EF_ECC(),
          EF_CBMIR(),
          EF_DCK(),
          EF_CNL(),
          EF_NIA(),
          EF_Kc('6f52', None, 'EF.KcGPRS', 'GPRS Ciphering key KcGPRS'),
          EF_LOCIGPRS(),
          TransparentEF('6f54', None, 'EF.SUME', 'SetUpMenu Elements'),
          EF_xPLMNwAcT('6f60', None, 'EF.PLMNwAcT',
                                   'User controlled PLMN Selector with Access Technology'),
          EF_xPLMNwAcT('6f61', None, 'EF.OPLMNwAcT',
                                   'Operator controlled PLMN Selector with Access Technology'),
          EF_xPLMNwAcT('6f62', None, 'EF.HPLMNwAcT', 'HPLMN Selector with Access Technology'),
          EF_CPBCCH(),
          EF_InvScan(),
          EF_PNN(),
          EF_OPL(),
          EF_ADN('6fc7', None, 'EF.MBDN', 'Mailbox Dialling Numbers'),
          EF_MBI(),
          EF_MWIS(),
          EF_ADN('6fcb', None, 'EF.CFIS', 'Call Forwarding Indication Status'),
          EF_EXT('6fc8', None, 'EF.EXT6', 'Externsion6 (MBDN)'),
          EF_EXT('6fcc', None, 'EF.EXT7', 'Externsion7 (CFIS)'),
          EF_SPDI(),
          EF_MMSN(),
          EF_EXT('6fcf', None, 'EF.EXT8', 'Extension8 (MMSN)'),
          EF_MMSICP(),
          EF_MMSUP(),
          EF_MMSUCP(),
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
        ret['file_characteristics'] = b2h(resp_bin[13:14])
        ret['num_direct_child_df'] = resp_bin[14]
        ret['num_direct_child_ef'] = resp_bin[15]
        ret['num_chv_unblock_adm_codes'] = int(resp_bin[16])
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
