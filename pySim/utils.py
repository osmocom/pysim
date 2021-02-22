#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pySim: various utilities
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
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


def h2b(s):
	return ''.join([chr((int(x,16)<<4)+int(y,16)) for x,y in zip(s[0::2], s[1::2])])

def b2h(s):
	return ''.join(['%02x'%ord(x) for x in s])

def h2i(s):
	return [(int(x,16)<<4)+int(y,16) for x,y in zip(s[0::2], s[1::2])]

def i2h(s):
	return ''.join(['%02x'%(x) for x in s])

def h2s(s):
	return ''.join([chr((int(x,16)<<4)+int(y,16)) for x,y in zip(s[0::2], s[1::2])
						      if int(x + y, 16) != 0xff])

def s2h(s):
	return b2h(s)

# List of bytes to string
def i2s(s):
	return ''.join([chr(x) for x in s])

def swap_nibbles(s):
	return ''.join([x+y for x,y in zip(s[1::2], s[0::2])])

def rpad(s, l, c='f'):
	return s + c * (l - len(s))

def lpad(s, l, c='f'):
	return c * (l - len(s)) + s

def half_round_up(n):
	return (n + 1)//2

# IMSI encoded format:
# For IMSI 0123456789ABCDE:
#
# |     byte 1      | 2 upper | 2 lower  | 3 upper | 3 lower | ... | 9 upper | 9 lower |
# | length in bytes |    0    | odd/even |    2    |    1    | ... |    E    |    D    |
#
# If the IMSI is less than 15 characters, it should be padded with 'f' from the end.
#
# The length is the total number of bytes used to encoded the IMSI. This includes the odd/even
# parity bit. E.g. an IMSI of length 14 is 8 bytes long, not 7, as it uses bytes 2 to 9 to
# encode itself.
#
# Because of this, an odd length IMSI fits exactly into len(imsi) + 1 // 2 bytes, whereas an
# even length IMSI only uses half of the last byte.

def enc_imsi(imsi):
	"""Converts a string imsi into the value of the EF"""
	l = half_round_up(len(imsi) + 1)	# Required bytes - include space for odd/even indicator
	oe = len(imsi) & 1			# Odd (1) / Even (0)
	ei = '%02x' % l + swap_nibbles('%01x%s' % ((oe<<3)|1, rpad(imsi, 15)))
	return ei

def dec_imsi(ef):
	"""Converts an EF value to the imsi string representation"""
	if len(ef) < 4:
		return None
	l = int(ef[0:2], 16) * 2		# Length of the IMSI string
	l = l - 1						# Encoded length byte includes oe nibble
	swapped = swap_nibbles(ef[2:]).rstrip('f')
	if len(swapped) < 1:
		return None
	oe = (int(swapped[0])>>3) & 1	# Odd (1) / Even (0)
	if not oe:
		# if even, only half of last byte was used
		l = l-1
	if l != len(swapped) - 1:
		return None
	imsi = swapped[1:]
	return imsi

def dec_iccid(ef):
	return swap_nibbles(ef).strip('f')

def enc_iccid(iccid):
	return swap_nibbles(rpad(iccid, 20))

def enc_plmn(mcc, mnc):
	"""Converts integer MCC/MNC into 3 bytes for EF"""
	if len(mnc) == 2:
		mnc = "F%s" % mnc
	return swap_nibbles("%s%s" % (mcc, mnc))

def dec_spn(ef):
	byte1 = int(ef[0:2])
	hplmn_disp = (byte1&0x01 == 0x01)
	oplmn_disp = (byte1&0x02 == 0x02)
	name = h2s(ef[2:])
	return (name, hplmn_disp, oplmn_disp)

def enc_spn(name, hplmn_disp=False, oplmn_disp=False):
	byte1 = 0x00
	if hplmn_disp: byte1 = byte1|0x01
	if oplmn_disp: byte1 = byte1|0x02
	return i2h([byte1])+s2h(name)

def hexstr_to_Nbytearr(s, nbytes):
	return [s[i:i+(nbytes*2)] for i in range(0, len(s), (nbytes*2)) ]

# Accepts hex string representing three bytes
def dec_mcc_from_plmn(plmn):
	ia = h2i(plmn)
	digit1 = ia[0] & 0x0F		# 1st byte, LSB
	digit2 = (ia[0] & 0xF0) >> 4	# 1st byte, MSB
	digit3 = ia[1] & 0x0F		# 2nd byte, LSB
	if digit3 == 0xF and digit2 == 0xF and digit1 == 0xF:
		return 0xFFF # 4095
	return derive_mcc(digit1, digit2, digit3)

def dec_mnc_from_plmn(plmn):
	ia = h2i(plmn)
	digit1 = (ia[1] & 0xF0)	>>4		# 2nd byte, MSB
	digit2 = ia[2] & 0x0F			# 3rd byte, LSB
	digit3 = (ia[2] & 0xF0) >> 4	# 3nd byte, MSB
	if digit3 == 0xF and digit2 == 0xF and digit1 == 0xF:
		return 0xFFF # 4095
	return derive_mnc(digit1, digit2, digit3)

def dec_act(twohexbytes):
	act_list = [
		{'bit': 15, 'name': "UTRAN"},
		{'bit': 14, 'name': "E-UTRAN"},
		{'bit':  7, 'name': "GSM"},
		{'bit':  6, 'name': "GSM COMPACT"},
		{'bit':  5, 'name': "cdma2000 HRPD"},
		{'bit':  4, 'name': "cdma2000 1xRTT"},
	]
	ia = h2i(twohexbytes)
	u16t = (ia[0] << 8)|ia[1]
	sel = []
	for a in act_list:
		if u16t & (1 << a['bit']):
			sel.append(a['name'])
	return sel

def dec_xplmn_w_act(fivehexbytes):
	res = {'mcc': 0, 'mnc': 0, 'act': []}
	plmn_chars = 6
	act_chars = 4
	plmn_str = fivehexbytes[:plmn_chars]				# first three bytes (six ascii hex chars)
	act_str = fivehexbytes[plmn_chars:plmn_chars + act_chars]	# two bytes after first three bytes
	res['mcc'] = dec_mcc_from_plmn(plmn_str)
	res['mnc'] = dec_mnc_from_plmn(plmn_str)
	res['act'] = dec_act(act_str)
	return res

def format_xplmn_w_act(hexstr):
	s = ""
	for rec_data in hexstr_to_Nbytearr(hexstr, 5):
		rec_info = dec_xplmn_w_act(rec_data)
		if rec_info['mcc'] == 0xFFF and rec_info['mnc'] == 0xFFF:
			rec_str = "unused"
		else:
			rec_str = "MCC: %03d MNC: %03d AcT: %s" % (rec_info['mcc'], rec_info['mnc'], ", ".join(rec_info['act']))
		s += "\t%s # %s\n" % (rec_data, rec_str)
	return s

def dec_loci(hexstr):
	res = {'tmsi': '',  'mcc': 0, 'mnc': 0, 'lac': '', 'status': 0}
	res['tmsi'] = hexstr[:8]
	res['mcc'] = dec_mcc_from_plmn(hexstr[8:14])
	res['mnc'] = dec_mnc_from_plmn(hexstr[8:14])
	res['lac'] = hexstr[14:18]
	res['status'] = h2i(hexstr[20:22])
	return res

def dec_psloci(hexstr):
	res = {'p-tmsi': '', 'p-tmsi-sig': '', 'mcc': 0, 'mnc': 0, 'lac': '', 'rac': '', 'status': 0}
	res['p-tmsi'] = hexstr[:8]
	res['p-tmsi-sig'] = hexstr[8:14]
	res['mcc'] = dec_mcc_from_plmn(hexstr[14:20])
	res['mnc'] = dec_mnc_from_plmn(hexstr[14:20])
	res['lac'] = hexstr[20:24]
	res['rac'] = hexstr[24:26]
	res['status'] = h2i(hexstr[26:28])
	return res

def dec_epsloci(hexstr):
	res = {'guti': '', 'mcc': 0, 'mnc': 0, 'tac': '', 'status': 0}
	res['guti'] = hexstr[:24]
	res['tai'] = hexstr[24:34]
	res['mcc'] = dec_mcc_from_plmn(hexstr[24:30])
	res['mnc'] = dec_mnc_from_plmn(hexstr[24:30])
	res['tac'] = hexstr[30:34]
	res['status'] = h2i(hexstr[34:36])
	return res

def dec_xplmn(threehexbytes):
	res = {'mcc': 0, 'mnc': 0, 'act': []}
	plmn_chars = 6
	plmn_str = threehexbytes[:plmn_chars]				# first three bytes (six ascii hex chars)
	res['mcc'] = dec_mcc_from_plmn(plmn_str)
	res['mnc'] = dec_mnc_from_plmn(plmn_str)
	return res

def format_xplmn(hexstr):
	s = ""
	for rec_data in hexstr_to_Nbytearr(hexstr, 3):
		rec_info = dec_xplmn(rec_data)
		if rec_info['mcc'] == 0xFFF and rec_info['mnc'] == 0xFFF:
			rec_str = "unused"
		else:
			rec_str = "MCC: %03d MNC: %03d" % (rec_info['mcc'], rec_info['mnc'])
		s += "\t%s # %s\n" % (rec_data, rec_str)
	return s

def derive_milenage_opc(ki_hex, op_hex):
	"""
	Run the milenage algorithm to calculate OPC from Ki and OP
	"""
	from Crypto.Cipher import AES
	from Crypto.Util.strxor import strxor
	from pySim.utils import b2h

	# We pass in hex string and now need to work on bytes
	aes = AES.new(h2b(ki_hex))
	opc_bytes = aes.encrypt(h2b(op_hex))
	return b2h(strxor(opc_bytes, h2b(op_hex)))

def calculate_luhn(cc):
	"""
	Calculate Luhn checksum used in e.g. ICCID and IMEI
	"""
	num = list(map(int, str(cc)))
	check_digit = 10 - sum(num[-2::-2] + [sum(divmod(d * 2, 10)) for d in num[::-2]]) % 10
	return 0 if check_digit == 10 else check_digit

def mcc_from_imsi(imsi):
	"""
	Derive the MCC (Mobile Country Code) from the first three digits of an IMSI
	"""
	if imsi == None:
		return None

	if len(imsi) > 3:
		return imsi[:3]
	else:
		return None

def mnc_from_imsi(imsi, long=False):
	"""
	Derive the MNC (Mobile Country Code) from the 4th to 6th digit of an IMSI
	"""
	if imsi == None:
		return None

	if len(imsi) > 3:
		if long:
			return imsi[3:6]
		else:
			return imsi[3:5]
	else:
		return None

def derive_mcc(digit1, digit2, digit3):
	"""
	Derive decimal representation of the MCC (Mobile Country Code)
	from three given digits.
	"""

	mcc = 0

	if digit1 != 0x0f:
		mcc += digit1 * 100
	if digit2 != 0x0f:
		mcc += digit2 * 10
	if digit3 != 0x0f:
		mcc += digit3

	return mcc

def derive_mnc(digit1, digit2, digit3=0x0f):
	"""
	Derive decimal representation of the MNC (Mobile Network Code)
	from two or (optionally) three given digits.
	"""

	mnc = 0

	# 3-rd digit is optional for the MNC. If present
	# the algorythm is the same as for the MCC.
	if digit3 != 0x0f:
		return derive_mcc(digit1, digit2, digit3)

	if digit1 != 0x0f:
		mnc += digit1 * 10
	if digit2 != 0x0f:
		mnc += digit2

	return mnc

def dec_msisdn(ef_msisdn):
	"""
	Decode MSISDN from EF.MSISDN or EF.ADN (same structure).
	See 3GPP TS 31.102, section 4.2.26 and 4.4.2.3.
	"""

	# Convert from str to (kind of) 'bytes'
	ef_msisdn = h2b(ef_msisdn)

	# Make sure mandatory fields are present
	if len(ef_msisdn) < 14:
		raise ValueError("EF.MSISDN is too short")

	# Skip optional Alpha Identifier
	xlen = len(ef_msisdn) - 14
	msisdn_lhv = ef_msisdn[xlen:]

	# Parse the length (in bytes) of the BCD encoded number
	bcd_len = ord(msisdn_lhv[0])
	# BCD length = length of dial num (max. 10 bytes) + 1 byte ToN and NPI
	if bcd_len == 0xff:
		return None
	elif bcd_len > 11 or bcd_len < 1:
		raise ValueError("Length of MSISDN (%d bytes) is out of range" % bcd_len)

	# Parse ToN / NPI
	ton = (ord(msisdn_lhv[1]) >> 4) & 0x07
	npi = ord(msisdn_lhv[1]) & 0x0f
	bcd_len -= 1

	# No MSISDN?
	if not bcd_len:
		return (npi, ton, None)

	msisdn = swap_nibbles(b2h(msisdn_lhv[2:][:bcd_len])).rstrip('f')
	# International number 10.5.118/3GPP TS 24.008
	if ton == 0x01:
		msisdn = '+' + msisdn

	return (npi, ton, msisdn)

def enc_msisdn(msisdn, npi=0x01, ton=0x03):
	"""
	Encode MSISDN as LHV so it can be stored to EF.MSISDN.
	See 3GPP TS 31.102, section 4.2.26 and 4.4.2.3.

	Default NPI / ToN values:
	  - NPI: ISDN / telephony numbering plan (E.164 / E.163),
	  - ToN: network specific or international number (if starts with '+').
	"""

	# Leading '+' indicates International Number
	if msisdn[0] == '+':
		msisdn = msisdn[1:]
		ton = 0x01

	# Append 'f' padding if number of digits is odd
	if len(msisdn) % 2 > 0:
		msisdn += 'f'

	# BCD length also includes NPI/ToN header
	bcd_len = len(msisdn) // 2 + 1
	npi_ton = (npi & 0x0f) | ((ton & 0x07) << 4) | 0x80
	bcd = rpad(swap_nibbles(msisdn), 10 * 2) # pad to 10 octets

	return ('%02x' % bcd_len) + ('%02x' % npi_ton) + bcd

def dec_st(st, table="sim"):
	"""
	Parses the EF S/U/IST and prints the list of available services in EF S/U/IST
	"""

	if table == "isim":
		from pySim.ts_31_103 import EF_IST_map
		lookup_map = EF_IST_map
	elif table == "usim":
		from pySim.ts_31_102 import EF_UST_map
		lookup_map = EF_UST_map
	else:
		from pySim.ts_51_011 import EF_SST_map
		lookup_map = EF_SST_map

	st_bytes = [st[i:i+2] for i in range(0, len(st), 2) ]

	avail_st = ""
	# Get each byte and check for available services
	for i in range(0, len(st_bytes)):
		# Byte i contains info about Services num (8i+1) to num (8i+8)
		byte = int(st_bytes[i], 16)
		# Services in each byte are in order MSB to LSB
		# MSB - Service (8i+8)
		# LSB - Service (8i+1)
		for j in range(1, 9):
			if byte&0x01 == 0x01 and ((8*i) + j in lookup_map):
				# Byte X contains info about Services num (8X-7) to num (8X)
				# bit = 1: service available
				# bit = 0: service not available
				avail_st += '\tService %d - %s\n' % ((8*i) + j, lookup_map[(8*i) + j])
			byte = byte >> 1
	return avail_st

def first_TLV_parser(bytelist):
	'''
	first_TLV_parser([0xAA, 0x02, 0xAB, 0xCD, 0xFF, 0x00]) -> (170, 2, [171, 205])

	parses first TLV format record in a list of bytelist
	returns a 3-Tuple: Tag, Length, Value
	Value is a list of bytes
	parsing of length is ETSI'style 101.220
	'''
	Tag = bytelist[0]
	if bytelist[1] == 0xFF:
		Len = bytelist[2]*256 + bytelist[3]
		Val = bytelist[4:4+Len]
	else:
		Len = bytelist[1]
		Val = bytelist[2:2+Len]
	return (Tag, Len, Val)

def TLV_parser(bytelist):
	'''
	TLV_parser([0xAA, ..., 0xFF]) -> [(T, L, [V]), (T, L, [V]), ...]

	loops on the input list of bytes with the "first_TLV_parser()" function
	returns a list of 3-Tuples
	'''
	ret = []
	while len(bytelist) > 0:
		T, L, V = first_TLV_parser(bytelist)
		if T == 0xFF:
			# padding bytes
			break
		ret.append( (T, L, V) )
		# need to manage length of L
		if L > 0xFE:
			bytelist = bytelist[ L+4 : ]
		else:
			bytelist = bytelist[ L+2 : ]
	return ret

def enc_st(st, service, state=1):
	"""
	Encodes the EF S/U/IST/EST and returns the updated Service Table

	Parameters:
		st - Current value of SIM/USIM/ISIM Service Table
		service - Service Number to encode as activated/de-activated
		state - 1 mean activate, 0 means de-activate

	Returns:
		s - Modified value of SIM/USIM/ISIM Service Table

	Default values:
		- state: 1 - Sets the particular Service bit to 1
	"""
	st_bytes = [st[i:i+2] for i in range(0, len(st), 2) ]

	s = ""
	# Check whether the requested service is present in each byte
	for i in range(0, len(st_bytes)):
		# Byte i contains info about Services num (8i+1) to num (8i+8)
		if service in range((8*i) + 1, (8*i) + 9):
			byte = int(st_bytes[i], 16)
			# Services in each byte are in order MSB to LSB
			# MSB - Service (8i+8)
			# LSB - Service (8i+1)
			mod_byte = 0x00
			# Copy bit by bit contents of byte to mod_byte with modified bit
			# for requested service
			for j in range(1, 9):
				mod_byte = mod_byte >> 1
				if service == (8*i) + j:
					mod_byte = state == 1 and mod_byte|0x80 or mod_byte&0x7f
				else:
					mod_byte = byte&0x01 == 0x01 and mod_byte|0x80 or mod_byte&0x7f
				byte = byte >> 1

			s += ('%02x' % (mod_byte))
		else:
			s += st_bytes[i]

	return s

def dec_addr_tlv(hexstr):
	"""
	Decode hex string to get EF.P-CSCF Address or EF.ePDGId or EF.ePDGIdEm.
	See 3GPP TS 31.102 version 13.4.0 Release 13, section 4.2.8, 4.2.102 and 4.2.104.
	"""

	# Convert from hex str to int bytes list
	addr_tlv_bytes = h2i(hexstr)

	s = ""

	# Get list of tuples containing parsed TLVs
	tlvs = TLV_parser(addr_tlv_bytes)

	for tlv in tlvs:
		# tlv = (T, L, [V])
		# T = Tag
		# L = Length
		# [V] = List of value

		# Invalid Tag value scenario
		if tlv[0] != 0x80:
			continue

		# Empty field - Zero length
		if tlv[1] == 0:
			continue

		# First byte in the value has the address type
		addr_type = tlv[2][0]
		# TODO: Support parsing of IPv6
		# Address Type: 0x00 (FQDN), 0x01 (IPv4), 0x02 (IPv6), other (Reserved)
		if addr_type == 0x00: #FQDN
			# Skip address tye byte i.e. first byte in value list
			content = tlv[2][1:]
			s += "\t%s # %s\n" % (i2h(content), i2s(content))
		elif addr_type == 0x01: #IPv4
			# Skip address tye byte i.e. first byte in value list
			# Skip the unused byte in Octect 4 after address type byte as per 3GPP TS 31.102
			ipv4 = tlv[2][2:]
			content = '.'.join(str(x) for x in ipv4)
			s += "\t%s # %s\n" % (i2h(ipv4), content)

	return s

def enc_addr_tlv(addr, addr_type='00'):
	"""
	Encode address TLV object used in EF.P-CSCF Address, EF.ePDGId and EF.ePDGIdEm.
	See 3GPP TS 31.102 version 13.4.0 Release 13, section 4.2.8, 4.2.102 and 4.2.104.

	Default values:
	  - addr_type: 00 - FQDN format of Address
	"""

	s = ""

	# TODO: Encoding of IPv6 address
	if addr_type == '00': #FQDN
		hex_str = s2h(addr)
		s += '80' + ('%02x' % ((len(hex_str)//2)+1)) + '00' + hex_str
	elif addr_type == '01': #IPv4
		ipv4_list = addr.split('.')
		ipv4_str = ""
		for i in ipv4_list:
			ipv4_str += ('%02x' % (int(i)))

		# Unused bytes shall be set to 'ff'. i.e 4th Octet after Address Type is not used
		# IPv4 Address is in octet 5 to octet 8 of the TLV data object
		s += '80' + ('%02x' % ((len(ipv4_str)//2)+2)) + '01' + 'ff' + ipv4_str

	return s

def sanitize_pin_adm(opts):
	"""
	The ADM pin can be supplied either in its hexadecimal form or as
	ascii string. This function checks the supplied opts parameter and
	returns the pin_adm as hex encoded string, regardles in which form
	it was originally supplied by the user
	"""

	pin_adm = None

	if opts.pin_adm is not None:
		if len(opts.pin_adm) <= 8:
			pin_adm = ''.join(['%02x'%(ord(x)) for x in opts.pin_adm])
			pin_adm = rpad(pin_adm, 16)

		else:
			raise ValueError("PIN-ADM needs to be <=8 digits (ascii)")

	if opts.pin_adm_hex is not None:
		if len(opts.pin_adm_hex) == 16:
			pin_adm = opts.pin_adm_hex
			# Ensure that it's hex-encoded
			try:
				try_encode = h2b(pin_adm)
			except ValueError:
				raise ValueError("PIN-ADM needs to be hex encoded using this option")
		else:
			raise ValueError("PIN-ADM needs to be exactly 16 digits (hex encoded)")

	return pin_adm

def init_reader(opts):
	"""
	Init card reader driver
	"""
	try:
		if opts.pcsc_dev is not None:
			print("Using PC/SC reader interface")
			from pySim.transport.pcsc import PcscSimLink
			sl = PcscSimLink(opts.pcsc_dev)
		elif opts.osmocon_sock is not None:
			print("Using Calypso-based (OsmocomBB) reader interface")
			from pySim.transport.calypso import CalypsoSimLink
			sl = CalypsoSimLink(sock_path=opts.osmocon_sock)
		elif opts.modem_dev is not None:
			print("Using modem for Generic SIM Access (3GPP TS 27.007)")
			from pySim.transport.modem_atcmd import ModemATCommandLink
			sl = ModemATCommandLink(device=opts.modem_dev, baudrate=opts.modem_baud)
		else: # Serial reader is default
			print("Using serial reader interface")
			from pySim.transport.serial import SerialSimLink
			sl = SerialSimLink(device=opts.device, baudrate=opts.baudrate)
		return sl
	except Exception as e:
		print("Card reader initialization failed with exception:\n" + str(e))
		return None


def enc_ePDGSelection(hexstr, mcc, mnc, epdg_priority='0001', epdg_fqdn_format='00'):
	"""
	Encode ePDGSelection so it can be stored at EF.ePDGSelection or EF.ePDGSelectionEm.
	See 3GPP TS 31.102 version 15.2.0 Release 15, section 4.2.104 and 4.2.106.

	Default values:
		- epdg_priority: '0001' - 1st Priority
		- epdg_fqdn_format: '00' - Operator Identifier FQDN
	"""

	plmn1 = enc_plmn(mcc, mnc) + epdg_priority + epdg_fqdn_format
	# TODO: Handle encoding of Length field for length more than 127 Bytes
	content = '80' + ('%02x' % (len(plmn1)//2)) + plmn1
	content = rpad(content, len(hexstr))
	return content

def dec_ePDGSelection(sixhexbytes):
	"""
	Decode ePDGSelection to get EF.ePDGSelection or EF.ePDGSelectionEm.
	See 3GPP TS 31.102 version 15.2.0 Release 15, section 4.2.104 and 4.2.106.
	"""

	res = {'mcc': 0, 'mnc': 0, 'epdg_priority': 0, 'epdg_fqdn_format': ''}
	plmn_chars = 6
	epdg_priority_chars = 4
	epdg_fqdn_format_chars = 2
	# first three bytes (six ascii hex chars)
	plmn_str = sixhexbytes[:plmn_chars]
	# two bytes after first three bytes
	epdg_priority_str = sixhexbytes[plmn_chars:plmn_chars + epdg_priority_chars]
	# one byte after first five bytes
	epdg_fqdn_format_str = sixhexbytes[plmn_chars + epdg_priority_chars:plmn_chars + epdg_priority_chars + epdg_fqdn_format_chars]
	res['mcc'] = dec_mcc_from_plmn(plmn_str)
	res['mnc'] = dec_mnc_from_plmn(plmn_str)
	res['epdg_priority'] = epdg_priority_str
	res['epdg_fqdn_format'] = epdg_fqdn_format_str == '00' and 'Operator Identifier FQDN' or 'Location based FQDN'
	return res

def format_ePDGSelection(hexstr):
	ePDGSelection_info_tag_chars = 2
	ePDGSelection_info_tag_str = hexstr[:2]
	s = ""
	# Minimum length
	len_chars = 2
	# TODO: Need to determine length properly - definite length support only
	# Inconsistency in spec: 3GPP TS 31.102 version 15.2.0 Release 15, 4.2.104
	# As per spec, length is 5n, n - number of PLMNs
	# But, each PLMN entry is made of PLMN (3 Bytes) + ePDG Priority (2 Bytes) + ePDG FQDN format (1 Byte)
	# Totalling to 6 Bytes, maybe length should be 6n
	len_str = hexstr[ePDGSelection_info_tag_chars:ePDGSelection_info_tag_chars+len_chars]

	# Not programmed scenario
	if int(len_str, 16) == 255 or int(ePDGSelection_info_tag_str, 16) == 255:
		len_chars = 0
		ePDGSelection_info_tag_chars = 0
	if len_str[0] == '8':
		# The bits 7 to 1 denotes the number of length octets if length > 127
		if int(len_str[1]) > 0:
			# Update number of length octets
			len_chars = len_chars * int(len_str[1])
			len_str = hexstr[ePDGSelection_info_tag_chars:len_chars]

	content_str = hexstr[ePDGSelection_info_tag_chars+len_chars:]
	# Right pad to prevent index out of range - multiple of 6 bytes
	content_str = rpad(content_str, len(content_str) + (12 - (len(content_str) % 12)))
	for rec_data in hexstr_to_Nbytearr(content_str, 6):
		rec_info = dec_ePDGSelection(rec_data)
		if rec_info['mcc'] == 0xFFF and rec_info['mnc'] == 0xFFF:
			rec_str = "unused"
		else:
			rec_str = "MCC: %03d MNC: %03d ePDG Priority: %s ePDG FQDN format: %s" % \
					(rec_info['mcc'], rec_info['mnc'], rec_info['epdg_priority'], rec_info['epdg_fqdn_format'])
		s += "\t%s # %s\n" % (rec_data, rec_str)
	return s

def get_addr_type(addr):
	"""
	Validates the given address and returns it's type (FQDN or IPv4 or IPv6)
	Return: 0x00 (FQDN), 0x01 (IPv4), 0x02 (IPv6), None (Bad address argument given)

	TODO: Handle IPv6
	"""

	# Empty address string
	if not len(addr):
		return None

	import sys
	# Handle python3 and python2 - unicode
	if sys.version_info[0] < 3:
		addr_str = unicode(addr)
	else:
		addr_str = addr

	addr_list = addr.split('.')

	# Check for IPv4/IPv6
	try:
		import ipaddress
		# Throws ValueError if addr is not correct
		ipa = ipaddress.ip_address(addr_str)

		if ipa.version == 4:
			return 0x01
		elif ipa.version == 6:
			return 0x02
	except Exception as e:
		invalid_ipv4 = True
		for i in addr_list:
			# Invalid IPv4 may qualify for a valid FQDN, so make check here
			# e.g. 172.24.15.300
			import re
			if not re.match('^[0-9_]+$', i):
				invalid_ipv4 = False
				break

		if invalid_ipv4:
			return None

	fqdn_flag = True
	for i in addr_list:
		# Only Alpha-numeric characters and hyphen - RFC 1035
		import re
		if not re.match("^[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)?$", i):
			fqdn_flag = False
			break

	# FQDN
	if fqdn_flag:
		return 0x00

	return None
