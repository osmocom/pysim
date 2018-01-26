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

def enc_imsi(imsi):
	"""Converts a string imsi into the value of the EF"""
	l = (len(imsi) + 1) // 2	# Required bytes
	oe = len(imsi) & 1			# Odd (1) / Even (0)
	ei = '%02x' % l + swap_nibbles(lpad('%01x%s' % ((oe<<3)|1, imsi), 16))
	return ei

def dec_imsi(ef):
	"""Converts an EF value to the imsi string representation"""
	if len(ef) < 4:
		return None
	l = int(ef[0:2], 16) * 2		# Length of the IMSI string
	swapped = swap_nibbles(ef[2:])
	oe = (int(swapped[0])>>3) & 1	# Odd (1) / Even (0)
	if oe:
		l = l-1
	if l+1 > len(swapped):
		return None
	imsi = swapped[1:l+2]
	return imsi

def dec_iccid(ef):
	return swap_nibbles(ef).strip('f')

def enc_iccid(iccid):
	return swap_nibbles(rpad(iccid, 20))

def enc_plmn(mcc, mnc):
	"""Converts integer MCC/MNC into 3 bytes for EF"""
	return swap_nibbles(lpad('%03d' % mcc, 3) + lpad('%02d' % mnc, 3))

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
