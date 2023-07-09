# -*- coding: utf-8 -*-

"""
Various constants from 3GPP TS 31.102 V17.9.0 usd by *legacy* code
"""

#
# Copyright (C) 2020 Supreeth Herle <herlesupreeth@gmail.com>
# Copyright (C) 2021-2023 Harald Welte <laforge@osmocom.org>
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

LOCI_STATUS_map = {
    0:	'updated',
    1:	'not updated',
    2:	'plmn not allowed',
    3:	'locatation area not allowed'
}
