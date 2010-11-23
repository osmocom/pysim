#!/usr/bin/env python

#
# Utility to deal with sim cards and program the 'magic' ones easily
#
#
# Part of the sim link code of inspired by pySimReader-Serial-src-v2
#
#
# Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010  Harald Welte <laforge@gnumonks.org>
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

import time
import serial
import sys

from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.util import toBytes


# ----------------------------------------------------------------------------
# Utils
# -------------------------------------------------------------------------{{{

def h2b(s):
	return ''.join([chr((int(x,16)<<4)+int(y,16)) for x,y in zip(s[0::2], s[1::2])])

def b2h(s):
	return ''.join(['%02x'%ord(x) for x in s])

def i2h(s):
	return ''.join(['%02x'%(x) for x in s])

def swap_nibbles(s):
	return ''.join([x+y for x,y in zip(s[1::2], s[0::2])])

def rpad(s, l, c='f'):
	return s + c * (l - len(s))

def lpad(s, l, c='f'):
	return c * (l - len(s)) + s

def scan_all(base, start=0, end=65536):
	rv = []
	s.select_file(base)
	for v in range(start, end):
		try:
			data, sw = s._tp.send_apdu('a0a4000002%04x' % v)
			if sw == '9000':
				rv.append( (v, data, sw) )
				s.select_file(base)
		except KeyboardInterrupt:
			return rv, v
		except:
			s.reset_card()
	return rv, end-1

# }}}


# ----------------------------------------------------------------------------
# Transport Link for serial (RS232) based readers included with simcard
# -------------------------------------------------------------------------{{{

import exceptions

class NoCardError(exceptions.Exception):
	pass
class ProtocolError(exceptions.Exception):
	pass


class SerialSimLink(object):
	def __init__(self, device='/dev/ttyUSB0', baudrate=9600, rst='-rts', debug=False):
		self._sl = serial.Serial(
				port = device,
				parity = serial.PARITY_EVEN,
				bytesize = serial.EIGHTBITS,
				stopbits = serial.STOPBITS_TWO,
				timeout = 1,
				xonxoff = 0,
				rtscts = 0,
				baudrate = baudrate,
			)
		self._rst_pin = rst
		self._debug = debug

		rv = self.reset_card()
		if rv == 0:
			raise NoCardError()
		elif rv < 0:
			raise ProtocoldError()

	def __del__(self):
		self._sl.close()

	def reset_card(self):
		rst_meth_map = {
			'rts': self._sl.setRTS,
			'dtr': self._sl.setDTR,
		}
		rst_val_map = { '+':0, '-':1 }

		try:
			rst_meth = rst_meth_map[self._rst_pin[1:]]
			rst_val  = rst_val_map[self._rst_pin[0]]
		except:
			raise ValueError('Invalid reset pin %s' % self._rst_pin);

		rst_meth(rst_val)
		time.sleep(0.1)  # 100 ms
		self._sl.flushInput()
		rst_meth(rst_val ^ 1)

		b = self._rx_byte()
		if not b:
			return 0
		if ord(b) != 0x3b:
			return -1;
		self._dbg_print("TS: 0x%x Direct convention" % ord(b))

		while ord(b) == 0x3b:
			b = self._rx_byte()

		if not b:
			return -1
		t0 = ord(b)
		self._dbg_print("T0: 0x%x" % t0)

		for i in range(4):
			if t0 & (0x10 << i):
				self._dbg_print("T%si = %x" % (chr(ord('A')+i), ord(self._rx_byte())))

		for i in range(0, t0 & 0xf):
			self._dbg_print("Historical = %x" % ord(self._rx_byte()))

		while True:
			x = self._rx_byte()
			if not x:
				break
			self._dbg_print("Extra: %x" % ord(x))

		return 1

	def _dbg_print(self, s):
		if self._debug:
			print s

	def _tx_byte(self, b):
		self._sl.write(b)
		r = self._sl.read()
		if r != b:	# TX and RX are tied, so we must clear the echo
			raise RuntimeError("Bad echo value. Expected %02x, got %s)" % (ord(b), '%02x'%ord(r) if r else '(nil)'))

	def _tx_string(self, s):
		"""This is only safe if it's guaranteed the card won't send any data
		during the time of tx of the string !!!"""
		self._sl.write(s)
		r = self._sl.read(len(s))
		if r != s:	# TX and RX are tied, so we must clear the echo
			raise RuntimeError("Bad echo value (Expected: %s, got %s)" % (b2h(s), b2h(r)))

	def _rx_byte(self):
		return self._sl.read()

	def send_apdu_raw(self, pdu):
		"""send_apdu_raw(pdu): Sends an APDU with minimal processing

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""

		pdu = h2b(pdu)
		data_len = ord(pdu[4])	# P3

		# Send first CLASS,INS,P1,P2,P3
		self._tx_string(pdu[0:5])

		# Wait ack which can be
		#  - INS: Command acked -> go ahead
		#  - 0x60: NULL, just wait some more
		#  - SW1: The card can apparently proceed ...
		while True:
			b = self._rx_byte()
			if b == pdu[1]:
				break
			elif b != '\x60':
				# Ok, it 'could' be SW1
				sw1 = b
				sw2 = self._rx_byte()
				nil = self._rx_byte()
				if (sw2 and not nil):
					return '', b2h(sw1+sw2)

				raise RuntimeError('Protocol error')

		# Send data (if any)
		if len(pdu) > 5:
			self._tx_string(pdu[5:])

		# Receive data (including SW !)
		#  length = [P3 - tx_data (=len(pdu)-len(hdr)) + 2 (SW1/2) ]
		to_recv = data_len - len(pdu) + 5 + 2

		data = ''
		while (len(data) < to_recv):
			b = self._rx_byte()
			if (to_recv == 2) and (b == '\x60'): # Ignore NIL if we have no RX data (hack ?)
				continue
			if not b:
				break;
			data += b

		# Split datafield from SW
		if len(data) < 2:
			return None, None
		sw = data[-2:]
		data = data[0:-2]

		# Return value
		return b2h(data), b2h(sw)

	def send_apdu(self, pdu):
		"""send_apdu(pdu): Sends an APDU and auto fetch response data

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		data, sw = self.send_apdu_raw(pdu)

		if (sw is not None) and (sw[0:2] == '9f'):
			pdu_gr = pdu[0:2] + 'c00000' + sw[2:4]
			data, sw = self.send_apdu_raw(pdu_gr)

		return data, sw

	def send_apdu_checksw(self, pdu, sw="9000"):
		"""send_apdu_checksw(pdu,sw): Sends an APDU and check returned SW

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   sw     : string of 4 hexadecimal characters (ex. "9000")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		rv = self.send_apdu(pdu)
		if sw.lower() != rv[1]:
			raise RuntimeError("SW match failed ! Expected %s and got %s." % (sw.lower(), rv[1]))
		return rv

# }}}

# ----------------------------------------------------------------------------
# Transport Link for a standard PC/SC reader
# -------------------------------------------------------------------------{{{

class PcscSimLink(object):
	def __init__(self, reader_number=0, observer=0):
		r = readers();
		try:
			self._con = r[reader_number].createConnection()
			if (observer):
			    observer = ConsoleCardConnectionObserver()
			    self._con.addObserver(observer)
			self._con.connect()
			#print r[reader_number], b2h(self._con.getATR())
		except NoCardException:
			raise NoCardError()

	def __del__(self):
		self._con.disconnect()
		return

	def reset_card(self):
		self._con.disconnect()
		try:
			self._con.connect()
		except NoCardException:
			raise NoCardError()
		return 1

	def send_apdu_raw(self, pdu):
		"""send_apdu_raw(pdu): Sends an APDU with minimal processing

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		apdu = toBytes(pdu)

		data, sw1, sw2 = self._con.transmit(apdu)

		sw = [sw1, sw2]

		# Return value
		return i2h(data), i2h(sw)

	def send_apdu(self, pdu):
		"""send_apdu(pdu): Sends an APDU and auto fetch response data

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		data, sw = self.send_apdu_raw(pdu)

		if (sw is not None) and (sw[0:2] == '9f'):
			pdu_gr = pdu[0:2] + 'c00000' + sw[2:4]
			data, sw = self.send_apdu_raw(pdu_gr)

		return data, sw

	def send_apdu_checksw(self, pdu, sw="9000"):
		"""send_apdu_checksw(pdu,sw): Sends an APDU and check returned SW

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   sw     : string of 4 hexadecimal characters (ex. "9000")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		rv = self.send_apdu(pdu)
		if sw.lower() != rv[1]:
			raise RuntimeError("SW match failed ! Expected %s and got %s." % (sw.lower(), rv[1]))
		return rv

# }}}

# ----------------------------------------------------------------------------
# SIM Card commands according to ISO 7816-4 and TS 11.11
# -------------------------------------------------------------------------{{{

class SimCardCommands(object):
	def __init__(self, transport):
		self._tp = transport;

	def select_file(self, dir_list):
		rv = []
		for i in dir_list:
			data, sw = self._tp.send_apdu_checksw("a0a4000002" + i)
			rv.append(data)
		return rv

	def read_binary(self, ef, length=None, offset=0):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		if length is None:
			length = int(r[-1][4:8], 16) - offset
		pdu = 'a0b0%04x%02x' % (offset, (min(256, length) & 0xff))
		return self._tp.send_apdu(pdu)

	def update_binary(self, ef, data, offset=0):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		self.select_file(ef)
		pdu = 'a0d6%04x%02x' % (offset, len(data)/2) + data
		return self._tp.send_apdu(pdu)

	def read_record(self, ef, rec_no):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		rec_length = int(r[-1][28:30], 16)
		pdu = 'a0b2%02x04%02x' % (rec_no, rec_length)
		return self._tp.send_apdu(pdu)

	def update_record(self, ef, rec_no, data, force_len=False):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		if not force_len:
			rec_length = int(r[-1][28:30], 16)
			if (len(data)/2 != rec_length):
				raise ValueError('Invalid data length (expected %d, got %d)' % (rec_length, len(data)/2))
		else:
			rec_length = len(data)/2
		pdu = ('a0dc%02x04%02x' % (rec_no, rec_length)) + data
		return self._tp.send_apdu(pdu)

	def record_size(self, ef):
		r = self.select_file(ef)
		return int(r[-1][28:30], 16)

	def record_count(self, ef):
		r = self.select_file(ef)
		return int(r[-1][4:8], 16) // int(r[-1][28:30], 16)

	def run_gsm(self, rand):
		if len(rand) != 32:
			raise ValueError('Invalid rand')
		self.select_file(['3f00', '7f20'])
		return self._tp.send_apdu('a088000010' + rand)

	def reset_card(self):
		return self._tp.reset_card()
# }}}


# ----------------------------------------------------------------------------
# Cards model
# -------------------------------------------------------------------------{{{

class Card(object):

	def __init__(self, scc):
		self._scc = scc

	def _e_iccid(self, iccid):
		return swap_nibbles(iccid)

	def _e_imsi(self, imsi):
		"""Converts a string imsi into the value of the EF"""
		l = (len(imsi) + 1) // 2	# Required bytes
		oe = len(imsi) & 1			# Odd (1) / Even (0)
		ei = '%02x' % l + swap_nibbles(lpad('%01x%s' % ((oe<<3)|1, imsi), 16))
		return ei

	def _e_plmn(self, mcc, mnc):
		"""Converts integer MCC/MNC into 6 bytes for EF"""
		return swap_nibbles(lpad('%d' % mcc, 3) + lpad('%d' % mnc, 3))

	def reset(self):
		self._scc.reset_card()


class _MagicSimBase(Card):
	"""
	Theses cards uses several record based EFs to store the provider infos,
	each possible provider uses a specific record number in each EF. The
	indexes used are ( where N is the number of providers supported ) :
	 - [2 .. N+1] for the operator name
     - [1 .. N] for the programable EFs

	* 3f00/7f4d/8f0c : Operator Name

	bytes 0-15 : provider name, padded with 0xff
	byte  16   : length of the provider name
	byte  17   : 01 for valid records, 00 otherwise

	* 3f00/7f4d/8f0d : Programmable Binary EFs

	* 3f00/7f4d/8f0e : Programmable Record EFs

	"""

	@classmethod
	def autodetect(kls, scc):
		try:
			for p, l, t in kls._files.values():
				if not t:
					continue
				if scc.record_size(['3f00', '7f4d', p]) != l:
					return None
		except:
			return None

		return kls(scc)

	def _get_count(self):
		"""
		Selects the file and returns the total number of entries
		and entry size
		"""
		f = self._files['name']

		r = self._scc.select_file(['3f00', '7f4d', f[0]])
		rec_len = int(r[-1][28:30], 16)
		tlen = int(r[-1][4:8],16)
		rec_cnt = (tlen / rec_len) - 1;

		if (rec_cnt < 1) or (rec_len != f[1]):
			raise RuntimeError('Bad card type')

		return rec_cnt

	def program(self, p):
		# Go to dir
		self._scc.select_file(['3f00', '7f4d'])

		# Home PLMN in PLMN_Sel format
		hplmn = self._e_plmn(p['mcc'], p['mnc'])

		# Operator name ( 3f00/7f4d/8f0c )
		self._scc.update_record(self._files['name'][0], 2,
			rpad(b2h(p['name']), 32)  + ('%02x' % len(p['name'])) + '01'
		)

		# ICCID/IMSI/Ki/HPLMN ( 3f00/7f4d/8f0d )
		v = ''

			# inline Ki
		if self._ki_file is None:
			v += p['ki']

			# ICCID
		v += '3f00' + '2fe2' + '0a' + self._e_iccid(p['iccid'])

			# IMSI
		v += '7f20' + '6f07' + '09' + self._e_imsi(p['imsi'])

			# Ki
		if self._ki_file:
			v += self._ki_file + '10' + p['ki']

			# PLMN_Sel
		v+= '6f30' + '18' +  rpad(hplmn, 36)

		self._scc.update_record(self._files['b_ef'][0], 1,
			rpad(v, self._files['b_ef'][1]*2)
		)

		# SMSP ( 3f00/7f4d/8f0e )
			# FIXME

		# Write PLMN_Sel forcefully as well
		r = self._scc.select_file(['3f00', '7f20', '6f30'])
		tl = int(r[-1][4:8], 16)

		hplmn = self._e_plmn(p['mcc'], p['mnc'])
		self._scc.update_binary('6f30', hplmn + 'ff' * (tl-3))

	def erase(self):
		# Dummy
		df = {}
		for k, v in self._files.iteritems():
			ofs = 1
			fv = v[1] * 'ff'
			if k == 'name':
				ofs = 2
				fv = fv[0:-4] + '0000'
			df[v[0]] = (fv, ofs)

		# Write
		for n in range(0,self._get_count()):
			for k, (msg, ofs) in df.iteritems():
				self._scc.update_record(['3f00', '7f4d', k], n + ofs, msg)


class SuperSim(_MagicSimBase):

	name = 'supersim'

	_files = {
		'name' : ('8f0c', 18, True),
		'b_ef' : ('8f0d', 74, True),
		'r_ef' : ('8f0e', 50, True),
	}

	_ki_file = None


class MagicSim(_MagicSimBase):

	name = 'magicsim'

	_files = {
		'name' : ('8f0c', 18, True),
		'b_ef' : ('8f0d', 130, True),
		'r_ef' : ('8f0e', 102, False),
	}

	_ki_file = '6f1b'


class FakeMagicSim(Card):
	"""
	Theses cards have a record based EF 3f00/000c that contains the provider
	informations. See the program method for its format. The records go from
	1 to N.
	"""

	name = 'fakemagicsim'

	@classmethod
	def autodetect(kls, scc):
		try:
			if scc.record_size(['3f00', '000c']) != 0x5a:
				return None
		except:
			return None

		return kls(scc)

	def _get_infos(self):
		"""
		Selects the file and returns the total number of entries
		and entry size
		"""

		r = self._scc.select_file(['3f00', '000c'])
		rec_len = int(r[-1][28:30], 16)
		tlen = int(r[-1][4:8],16)
		rec_cnt = (tlen / rec_len) - 1;

		if (rec_cnt < 1) or (rec_len != 0x5a):
			raise RuntimeError('Bad card type')

		return rec_cnt, rec_len

	def program(self, p):
		# Home PLMN
		r = self._scc.select_file(['3f00', '7f20', '6f30'])
		tl = int(r[-1][4:8], 16)

		hplmn = self._e_plmn(p['mcc'], p['mnc'])
		self._scc.update_binary('6f30', hplmn + 'ff' * (tl-3))

		# Get total number of entries and entry size
		rec_cnt, rec_len = self._get_infos()

		# Set first entry
		entry = (
			'81' +								#  1b  Status: Valid & Active
			rpad(b2h(p['name'][0:14]), 28) +	# 14b  Entry Name
			self._e_iccid(p['iccid']) +			# 10b  ICCID
			self._e_imsi(p['imsi']) +			#  9b  IMSI_len + id_type(9) + IMSI
			p['ki'] +							# 16b  Ki
			24*'f' + 'fd' + 24*'f' +			# 25b  (unknown ...)
			rpad(p['smsp'], 20) +				# 10b  SMSP (padded with ff if needed)
			10*'f'								#  5b  (unknown ...)
		)
		self._scc.update_record('000c', 1, entry)

	def erase(self):
		# Get total number of entries and entry size
		rec_cnt, rec_len = self._get_infos()

		# Erase all entries
		entry = 'ff' * rec_len
		for i in range(0, rec_cnt):
			self._scc.update_record('000c', 1+i, entry)


	# In order for autodetection ...
_cards_classes = [ FakeMagicSim, SuperSim, MagicSim ]

# }}}


# ----------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------{{{

import hashlib
from optparse import OptionParser
import random
import re


def parse_options():

	parser = OptionParser(usage="usage: %prog [options]")

	parser.add_option("-d", "--device", dest="device", metavar="DEV",
			help="Serial Device for SIM access [default: %default]",
			default="/dev/ttyUSB0",
		)
	parser.add_option("-p", "--pcsc-device", dest="pcsc_dev", metavar="PCSC",
			help="Which PC/SC reader number for SIM access",
			default=None,
		)
	parser.add_option("-b", "--baud", dest="baudrate", type="int", metavar="BAUD",
			help="Baudrate used for SIM access [default: %default]",
			default=9600,
		)
	parser.add_option("-t", "--type", dest="type",
			help="Card type (user -t list to view) [default: %default]",
			default="auto",
		)
	parser.add_option("-e", "--erase", dest="erase", action='store_true',
			help="Erase beforehand [default: %default]",
			default=False,
		)

	parser.add_option("-n", "--name", dest="name",
			help="Operator name [default: %default]",
			default="Magic",
		)
	parser.add_option("-c", "--country", dest="country", type="int", metavar="CC",
			help="Country code [default: %default]",
			default=1,
		)
	parser.add_option("-x", "--mcc", dest="mcc", type="int",
			help="Mobile Country Code [default: %default]",
			default=901,
		)
	parser.add_option("-y", "--mnc", dest="mnc", type="int",
			help="Mobile Network Code",
			default=55,
		)
	parser.add_option("-m", "--smsp", dest="smsp",
			help="SMSP [default: '00 + country code + 5555']",
		)

	parser.add_option("-s", "--iccid", dest="iccid", metavar="ID",
			help="Integrated Circuit Card ID",
		)
	parser.add_option("-i", "--imsi", dest="imsi",
			help="International Mobile Subscriber Identity",
		)
	parser.add_option("-k", "--ki", dest="ki",
			help="Ki (default is to randomize)",
		)

	parser.add_option("-z", "--secret", dest="secret", metavar="STR",
			help="Secret used for ICCID/IMSI autogen",
		)
	parser.add_option("-j", "--num", dest="num", type=int,
			help="Card # used for ICCID/IMSI autogen",
		)

	(options, args) = parser.parse_args()

	if options.type == 'list':
		for kls in _cards_classes:
			print kls.name
		sys.exit(0)

	if ((options.imsi is None) or (options.iccid is None)) and (options.num is None):
		parser.error("If either IMSI or ICCID isn't specified, num is required")

	if args:
		parser.error("Extraneous arguments")

	return options


def _digits(secret, usage, len, num):
	s = hashlib.sha1(secret + usage + '%d' % num)
	d = ''.join(['%02d'%ord(x) for x in s.digest()])
	return d[0:len]

def _mcc_mnc_digits(mcc, mnc):
	return ('%03d%03d' if mnc > 100 else '%03d%02d') % (mcc, mnc)

def _cc_digits(cc):
	return ('%03d' if cc > 100 else '%02d') % cc

def _isnum(s, l=-1):
	return s.isdigit() and ((l== -1) or (len(s) == l))


def gen_parameters(opts):
	"""Generates Name, ICCID, MCC, MNC, IMSI, SMSP, Ki from the
	options given by the user"""

	# MCC/MNC
	mcc = opts.mcc
	mnc = opts.mnc

	if not ((0 < mcc < 999) and (0 < mnc < 999)):
		raise ValueError('mcc & mnc must be between 0 and 999')

	# Digitize country code (2 or 3 digits)
	cc_digits = _cc_digits(opts.country)

	# Digitize MCC/MNC (5 or 6 digits)
	plmn_digits = _mcc_mnc_digits(mcc, mnc)

	# ICCID (20 digits)
	if opts.iccid is not None:
		iccid = opts.iccid
		if not _isnum(iccid, 20):
			raise ValueError('ICCID must be 20 digits !');

	else:
		if opts.num is None:
			raise ValueError('Neither ICCID nor card number specified !')

		iccid = (
			'89' +			# Common prefix (telecom)
			cc_digits +		# Country Code on 2/3 digits
			plmn_digits 	# MCC/MNC on 5/6 digits
		)

		ml = 20 - len(iccid)

		if opts.secret is None:
			# The raw number
			iccid += ('%%0%dd' % ml) % opts.num
		else:
			# Randomized digits
			iccid += _digits(opts.secret, 'ccid', ml, opts.num)

	# IMSI (15 digits usually)
	if opts.imsi is not None:
		imsi = opts.imsi
		if not _isnum(imsi):
			raise ValueError('IMSI must be digits only !')

	else:
		if opts.num is None:
			raise ValueError('Neither IMSI nor card number specified !')

		ml = 15 - len(plmn_digits)

		if opts.secret is None:
			# The raw number
			msin = ('%%0%dd' % ml) % opts.num
		else:
			# Randomized digits
			msin = _digits(opts.secret, 'imsi', ml, opts.num)

		imsi = (
			plmn_digits +	# MCC/MNC on 5/6 digits
			msin			# MSIN
		)

	# SMSP
	if opts.smsp is not None:
		smsp = opts.smsp
		if not _isnum(smsp):
			raise ValueError('SMSP must be digits only !')

	else:
		smsp = '00%d' % opts.country + '5555'	# Hack ...

	# Ki (random)
	if opts.ki is not None:
		ki = opts.ki
		if not re.match('^[0-9a-fA-F]{32}$', ki):
			raise ValueError('Ki needs to be 128 bits, in hex format')

	else:
		ki = ''.join(['%02x' % random.randrange(0,256) for i in range(16)])

	# Return that
	return {
		'name'	: opts.name,
		'iccid'	: iccid,
		'mcc'	: mcc,
		'mnc'	: mnc,
		'imsi'	: imsi,
		'smsp'	: smsp,
		'ki'	: ki,
	}


def print_parameters(params):

	print """Generated card parameters :
 > Name    : %(name)s
 > SMSP    : %(smsp)s
 > ICCID   : %(iccid)s
 > MCC/MNC : %(mcc)d/%(mnc)d
 > IMSI    : %(imsi)s
 > Ki      : %(ki)s
"""	% params


if __name__ == '__main__':

	# Get/Gen the parameters
	opts = parse_options()
	cp = gen_parameters(opts)
	print_parameters(cp)

	# Connect to the card
	if opts.pcsc_dev is None:
		sl = SerialSimLink(device=opts.device, baudrate=opts.baudrate)
	else:
		sl = PcscSimLink(0, observer=0)
	scc = SimCardCommands(transport=sl)

	# Detect type if needed
	card = None
	ctypes = dict([(kls.name, kls) for kls in _cards_classes])

	if opts.type == "auto":
		for kls in _cards_classes:
			card = kls.autodetect(scc)
			if card:
				print "Autodetected card type %s" % card.name
				card.reset()
				break

		if card is None:
			print "Autodetection failed"
			sys.exit(-1)

	elif opts.type in ctypes:
		card = ctypes[opts.type](scc)

	else:
		print "Unknown card type %s" % opts.type
		sys.exit(-1)

	# Erase it if asked
	if opts.erase:
		print "Formatting ..."
		card.erase()
		card.reset()

	# Program it
	print "Programming ..."
	card.program(cp)

	print "Done !"

