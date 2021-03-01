# -*- coding: utf-8 -*-

"""
Various constants from ETSI TS 131 103 V14.2.0
"""

#
# Copyright (C) 2020 Supreeth Herle <herlesupreeth@gmail.com>
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

# Mapping between ISIM Service Number and its description
EF_IST_map = {
	1: 'P-CSCF address',
	2: 'Generic Bootstrapping Architecture (GBA)',
	3: 'HTTP Digest',
	4: 'GBA-based Local Key Establishment Mechanism',
	5: 'Support of P-CSCF discovery for IMS Local Break Out',
	6: 'Short Message Storage (SMS)',
	7: 'Short Message Status Reports (SMSR)',
	8: 'Support for SM-over-IP including data download via SMS-PP as defined in TS 31.111 [31]',
	9: 'Communication Control for IMS by ISIM',
	10: 'Support of UICC access to IMS',
	11: 'URI support by UICC',
	12: 'Media Type support',
	13: 'IMS call disconnection cause',
	14: 'URI support for MO SHORT MESSAGE CONTROL',
	15: 'MCPTT',
	16: 'URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111 [31]',
	17: 'From Preferred',
	18: 'IMS configuration data',
	19: 'XCAP Configuration Data',
	20: 'WebRTC URI',
}

EF_ISIM_ADF_map = {
	'IST': '6F07',
	'IMPI': '6F02',
	'DOMAIN': '6F03',
	'IMPU': '6F04',
	'AD': '6FAD',
	'ARR': '6F06',
	'PCSCF': '6F09',
	'GBAP': '6FD5',
	'GBANL': '6FD7',
	'NAFKCA': '6FDD',
	'UICCIARI': '6FE7',
	'SMS': '6F3C',
	'SMSS': '6F43',
	'SMSR': '6F47',
	'SMSP': '6F42',
	'FromPreferred': '6FF7',
	'IMSConfigData': '6FF8',
	'XCAPConfigData': '6FFC',
	'WebRTCURI': '6FFA'
}
