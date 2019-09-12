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
	return ''.join([chr((int(x,16)<<4)+int(y,16)) for x,y in zip(s[0::2], s[1::2]) if not (x == 'f' and y == 'f') ])

def s2h(s):
	return b2h(s)

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
	return swap_nibbles(lpad('%d' % int(mcc), 3) + lpad('%d' % int(mnc), 3))

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

def hexstr_to_fivebytearr(s):
	return [s[i:i+10] for i in range(0, len(s), 10) ]

# Accepts hex string representing three bytes
def dec_mcc_from_plmn(plmn):
	ia = h2i(plmn)
	digit1 = ia[0] & 0x0F		# 1st byte, LSB
	digit2 = (ia[0] & 0xF0) >> 4	# 1st byte, MSB
	digit3 = ia[1] & 0x0F		# 2nd byte, LSB
	if digit3 == 0xF and digit2 == 0xF and digit1 == 0xF:
		return 0xFFF # 4095
	mcc = digit1 * 100
	mcc += digit2 * 10
	mcc += digit3
	return mcc

def dec_mnc_from_plmn(plmn):
	ia = h2i(plmn)
	digit1 = ia[2] & 0x0F		# 3rd byte, LSB
	digit2 = (ia[2] & 0xF0) >> 4	# 3rd byte, MSB
	digit3 = (ia[1] & 0xF0) >> 4	# 2nd byte, MSB
	if digit3 == 0xF and digit2 == 0xF and digit1 == 0xF:
		return 0xFFF # 4095
	mnc = 0
	# signifies two digit MNC
	if digit3 == 0xF:
		mnc += digit1 * 10
		mnc += digit2
	else:
		mnc += digit1 * 100
		mnc += digit2 * 10
		mnc += digit3
	return mnc

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
	for rec_data in hexstr_to_fivebytearr(hexstr):
		rec_info = dec_xplmn_w_act(rec_data)
		if rec_info['mcc'] == 0xFFF and rec_info['mnc'] == 0xFFF:
			rec_str = "unused"
		else:
			rec_str = "MCC: %3s MNC: %3s AcT: %s" % (rec_info['mcc'], rec_info['mnc'], ", ".join(rec_info['act']))
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
	num = map(int, str(cc))
	check_digit = 10 - sum(num[-2::-2] + [sum(divmod(d * 2, 10)) for d in num[::-2]]) % 10
	return 0 if check_digit == 10 else check_digit
