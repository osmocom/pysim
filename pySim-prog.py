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

import hashlib
from optparse import OptionParser
import os
import random
import re
import sys

try:
	import json
except ImportError:
	# Python < 2.5
	import simplejson as json

from pySim.commands import SimCardCommands
from pySim.cards import _cards_classes
from pySim.utils import h2b, swap_nibbles, rpad


def parse_options():

	parser = OptionParser(usage="usage: %prog [options]")

	parser.add_option("-d", "--device", dest="device", metavar="DEV",
			help="Serial Device for SIM access [default: %default]",
			default="/dev/ttyUSB0",
		)
	parser.add_option("-b", "--baud", dest="baudrate", type="int", metavar="BAUD",
			help="Baudrate used for SIM access [default: %default]",
			default=9600,
		)
	parser.add_option("-p", "--pcsc-device", dest="pcsc_dev", type='int', metavar="PCSC",
			help="Which PC/SC reader number for SIM access",
			default=None,
		)
	parser.add_option("-t", "--type", dest="type",
			help="Card type (user -t list to view) [default: %default]",
			default="auto",
		)
	parser.add_option("-a", "--pin-adm", dest="pin_adm",
			help="ADM PIN used for provisioning (overwrites default)",
		)
	parser.add_option("-e", "--erase", dest="erase", action='store_true',
			help="Erase beforehand [default: %default]",
			default=False,
		)

	parser.add_option("-S", "--source", dest="source",
			help="Data Source[default: %default]",
			default="cmdline",
		)

	# if mode is "cmdline"
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
			help="Mobile Network Code [default: %default]",
			default=55,
		)
	parser.add_option("-m", "--smsc", dest="smsc",
			help="SMSP [default: '00 + country code + 5555']",
		)
	parser.add_option("-M", "--smsp", dest="smsp",
			help="Raw SMSP content in hex [default: auto from SMSC]",
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
	parser.add_option("-o", "--opc", dest="opc",
			help="OPC (default is to randomize)",
		)
	parser.add_option("--op", dest="op",
			help="Set OP to derive OPC from OP and KI",
		)
	parser.add_option("--acc", dest="acc",
			help="Set ACC bits (Access Control Code). not all card types are supported",
		)


	parser.add_option("-z", "--secret", dest="secret", metavar="STR",
			help="Secret used for ICCID/IMSI autogen",
		)
	parser.add_option("-j", "--num", dest="num", type=int,
			help="Card # used for ICCID/IMSI autogen",
		)
	parser.add_option("--batch", dest="batch_mode",
			help="Enable batch mode [default: %default]",
			default=False, action='store_true',
		)
	parser.add_option("--batch-state", dest="batch_state", metavar="FILE",
			help="Optional batch state file",
		)

	# if mode is "csv"
	parser.add_option("--read-csv", dest="read_csv", metavar="FILE",
			help="Read parameters from CSV file rather than command line")


	parser.add_option("--write-csv", dest="write_csv", metavar="FILE",
			help="Append generated parameters in CSV file",
		)
	parser.add_option("--write-hlr", dest="write_hlr", metavar="FILE",
			help="Append generated parameters to OpenBSC HLR sqlite3",
		)
	parser.add_option("--dry-run", dest="dry_run",
			help="Perform a 'dry run', don't actually program the card",
			default=False, action="store_true")

	(options, args) = parser.parse_args()

	if options.type == 'list':
		for kls in _cards_classes:
			print kls.name
		sys.exit(0)

	if options.source == 'csv':
		if (options.imsi is None) and (options.batch_mode is False):
			parser.error("CSV mode needs either an IMSI or batch mode")
		if options.read_csv is None:
			parser.error("CSV mode requires a CSV input file")
	elif options.source == 'cmdline':
		if ((options.imsi is None) or (options.iccid is None)) and (options.num is None):
			parser.error("If either IMSI or ICCID isn't specified, num is required")
	else:
		parser.error("Only `cmdline' and `csv' sources supported")

	if (options.read_csv is not None) and (options.source != 'csv'):
		parser.error("You cannot specify a CSV input file in source != csv")

	if (options.batch_mode) and (options.num is None):
		options.num = 0

	if (options.batch_mode):
		if (options.imsi is not None) or (options.iccid is not None):
			parser.error("Can't give ICCID/IMSI for batch mode, need to use automatic parameters ! see --num and --secret for more informations")

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

def _ishex(s, l=-1):
	hc = '0123456789abcdef'
	return all([x in hc for x in s.lower()]) and ((l== -1) or (len(s) == l))


def _dbi_binary_quote(s):
	# Count usage of each char
	cnt = {}
	for c in s:
		cnt[c] = cnt.get(c, 0) + 1

	# Find best offset
	e = 0
	m = len(s)
	for i in range(1, 256):
		if i == 39:
			continue
		sum_ = cnt.get(i, 0) + cnt.get((i+1)&0xff, 0) + cnt.get((i+39)&0xff, 0)
		if sum_ < m:
			m = sum_
			e = i
			if m == 0:	# No overhead ? use this !
				break;

	# Generate output
	out = []
	out.append( chr(e) )	# Offset
	for c in s:
		x = (256 + ord(c) - e) % 256
		if x in (0, 1, 39):
			out.append('\x01')
			out.append(chr(x+1))
		else:
			out.append(chr(x))

	return ''.join(out)

def calculate_luhn(cc):
	num = map(int, str(cc))
	check_digit = 10 - sum(num[-2::-2] + [sum(divmod(d * 2, 10)) for d in num[::-2]]) % 10
	return 0 if check_digit == 10 else check_digit

def derive_milenage_opc(ki_hex, op_hex):
	"""
	Run the milenage algorithm.
	"""
	from Crypto.Cipher import AES
	from Crypto.Util.strxor import strxor
	from pySim.utils import b2h

	# We pass in hex string and now need to work on bytes
	aes = AES.new(h2b(ki_hex))
	opc_bytes = aes.encrypt(h2b(op_hex))
	return b2h(strxor(opc_bytes, h2b(op_hex)))

def gen_parameters(opts):
	"""Generates Name, ICCID, MCC, MNC, IMSI, SMSP, Ki, PIN-ADM from the
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

	# ICCID (19 digits, E.118), though some phase1 vendors use 20 :(
	if opts.iccid is not None:
		iccid = opts.iccid
		if not _isnum(iccid, 19):
			raise ValueError('ICCID must be 19 digits !');

	else:
		if opts.num is None:
			raise ValueError('Neither ICCID nor card number specified !')

		iccid = (
			'89' +			# Common prefix (telecom)
			cc_digits +		# Country Code on 2/3 digits
			plmn_digits 	# MCC/MNC on 5/6 digits
		)

		ml = 18 - len(iccid)

		if opts.secret is None:
			# The raw number
			iccid += ('%%0%dd' % ml) % opts.num
		else:
			# Randomized digits
			iccid += _digits(opts.secret, 'ccid', ml, opts.num)

		# Add checksum digit
		iccid += ('%1d' % calculate_luhn(iccid))

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
		if not _ishex(smsp):
			raise ValueError('SMSP must be hex digits only !')
		if len(smsp) < 28*2:
			raise ValueError('SMSP must be at least 28 bytes')

	else:
		if opts.smsc is not None:
			smsc = opts.smsc
			if not _isnum(smsc):
				raise ValueError('SMSC must be digits only !')
		else:
			smsc = '00%d' % opts.country + '5555'	# Hack ...

		smsc = '%02d' % ((len(smsc) + 3)//2,) + "81" + swap_nibbles(rpad(smsc, 20))

		smsp = (
			'e1' +			# Parameters indicator
			'ff' * 12 +		# TP-Destination address
			smsc +			# TP-Service Centre Address
			'00' +			# TP-Protocol identifier
			'00' +			# TP-Data coding scheme
			'00'			# TP-Validity period
		)

	# ACC
	if opts.acc is not None:
		acc = opts.acc
		if not _ishex(acc):
			raise ValueError('ACC must be hex digits only !')
		if len(acc) != 2*2:
			raise ValueError('ACC must be exactly 2 bytes')

	else:
		acc = None

	# Ki (random)
	if opts.ki is not None:
		ki = opts.ki
		if not re.match('^[0-9a-fA-F]{32}$', ki):
			raise ValueError('Ki needs to be 128 bits, in hex format')
	else:
		ki = ''.join(['%02x' % random.randrange(0,256) for i in range(16)])

	# Ki (random)
	if opts.opc is not None:
		opc = opts.opc
		if not re.match('^[0-9a-fA-F]{32}$', opc):
			raise ValueError('OPC needs to be 128 bits, in hex format')

	elif opts.op is not None:
		opc = derive_milenage_opc(ki, opts.op)
	else:
		opc = ''.join(['%02x' % random.randrange(0,256) for i in range(16)])

	if opts.pin_adm is not None:
		if len(opts.pin_adm) > 8:
			raise ValueError("PIN-ADM needs to be <=8 digits")
		pin_adm = ''.join(['%02x'%(ord(x)) for x in opts.pin_adm])
		pin_adm = rpad(pin_adm, 16)
	else:
		pin_adm = None


	# Return that
	return {
		'name'	: opts.name,
		'iccid'	: iccid,
		'mcc'	: mcc,
		'mnc'	: mnc,
		'imsi'	: imsi,
		'smsp'	: smsp,
		'ki'	: ki,
		'opc'	: opc,
		'acc'	: acc,
		'pin_adm' : pin_adm,
	}


def print_parameters(params):

	print """Generated card parameters :
 > Name    : %(name)s
 > SMSP    : %(smsp)s
 > ICCID   : %(iccid)s
 > MCC/MNC : %(mcc)d/%(mnc)d
 > IMSI    : %(imsi)s
 > Ki      : %(ki)s
 > OPC     : %(opc)s
 > ACC     : %(acc)s
"""	% params


def write_params_csv(opts, params):
	# csv
	if opts.write_csv:
		import csv
		row = ['name', 'iccid', 'mcc', 'mnc', 'imsi', 'smsp', 'ki', 'opc']
		f = open(opts.write_csv, 'a')
		cw = csv.writer(f)
		cw.writerow([params[x] for x in row])
		f.close()

def _read_params_csv(opts, imsi):
	import csv
	row = ['name', 'iccid', 'mcc', 'mnc', 'imsi', 'smsp', 'ki', 'opc']
	f = open(opts.read_csv, 'r')
	cr = csv.DictReader(f, row)
	i = 0
	for row in cr:
		if opts.num is not None:
			if opts.num == i:
				f.close()
				return row;
			i += 1
		if row['imsi'] == imsi:
			f.close()
			return row;

	f.close()
	return None

def read_params_csv(opts, imsi):
	row = _read_params_csv(opts, imsi)
	if row is not None:
		row['mcc'] = int(row['mcc'])
		row['mnc'] = int(row['mnc'])
	return row


def write_params_hlr(opts, params):
	# SQLite3 OpenBSC HLR
	if opts.write_hlr:
		import sqlite3
		conn = sqlite3.connect(opts.write_hlr)

		c = conn.execute(
			'INSERT INTO Subscriber ' +
			'(imsi, name, extension, authorized, created, updated) ' +
			'VALUES ' +
			'(?,?,?,1,datetime(\'now\'),datetime(\'now\'));',
			[
				params['imsi'],
				params['name'],
				'9' + params['iccid'][-5:-1]
			],
		)
		sub_id = c.lastrowid
		c.close()

		c = conn.execute(
			'INSERT INTO AuthKeys ' +
			'(subscriber_id, algorithm_id, a3a8_ki)' +
			'VALUES ' +
			'(?,?,?)',
			[ sub_id, 2, sqlite3.Binary(_dbi_binary_quote(h2b(params['ki']))) ],
		)

		conn.commit()
		conn.close()

def write_parameters(opts, params):
	write_params_csv(opts, params)
	write_params_hlr(opts, params)


BATCH_STATE = [ 'name', 'country', 'mcc', 'mnc', 'smsp', 'secret', 'num' ]
BATCH_INCOMPATIBLE = ['iccid', 'imsi', 'ki']

def init_batch(opts):
	# Need to do something ?
	if not opts.batch_mode:
		return

	for k in BATCH_INCOMPATIBLE:
		if getattr(opts, k):
			print "Incompatible option with batch_state: %s" % (k,)
			sys.exit(-1)

	# Don't load state if there is none ...
	if not opts.batch_state:
		return

	if not os.path.isfile(opts.batch_state):
		print "No state file yet"
		return

	# Get stored data
	fh = open(opts.batch_state)
	d = json.loads(fh.read())
	fh.close()

	for k,v in d.iteritems():
		setattr(opts, k, v)


def save_batch(opts):
	# Need to do something ?
	if not opts.batch_mode or not opts.batch_state:
		return

	d = json.dumps(dict([(k,getattr(opts,k)) for k in BATCH_STATE]))
	fh = open(opts.batch_state, 'w')
	fh.write(d)
	fh.close()


def card_detect(opts, scc):

	# Detect type if needed
	card = None
	ctypes = dict([(kls.name, kls) for kls in _cards_classes])

	if opts.type in ("auto", "auto_once"):
		for kls in _cards_classes:
			card = kls.autodetect(scc)
			if card:
				print "Autodetected card type %s" % card.name
				card.reset()
				break

		if card is None:
			print "Autodetection failed"
			return

		if opts.type == "auto_once":
			opts.type = card.name

	elif opts.type in ctypes:
		card = ctypes[opts.type](scc)

	else:
		raise ValueError("Unknown card type %s" % opts.type)

	return card


if __name__ == '__main__':

	# Parse options
	opts = parse_options()

	# Connect to the card
	if opts.pcsc_dev is None:
		from pySim.transport.serial import SerialSimLink
		sl = SerialSimLink(device=opts.device, baudrate=opts.baudrate)
	else:
		from pySim.transport.pcsc import PcscSimLink
		sl = PcscSimLink(opts.pcsc_dev)

	# Create command layer
	scc = SimCardCommands(transport=sl)

	# Batch mode init
	init_batch(opts)

	# Iterate
	done = False
	first = True
	card = None

	while not done:

		if opts.dry_run is False:
			# Connect transport
			print "Insert card now (or CTRL-C to cancel)"
			sl.wait_for_card(newcardonly=not first)

		# Not the first anymore !
		first = False

		if opts.dry_run is False:
			# Get card
			card = card_detect(opts, scc)
			if card is None:
				if opts.batch_mode:
					first = False
					continue
				else:
					sys.exit(-1)

			# Erase if requested
			if opts.erase:
				print "Formatting ..."
				card.erase()
				card.reset()

		# Generate parameters
		if opts.source == 'cmdline':
			cp = gen_parameters(opts)
		elif opts.source == 'csv':
			cp = read_params_csv(opts, opts.imsi)
		if cp is None:
			print "Error reading parameters\n"
			sys.exit(2)
		print_parameters(cp)

		if opts.dry_run is False:
			# Program the card
			print "Programming ..."
			if opts.dry_run is not True:
				card.program(cp)
		else:
			print "Dry Run: NOT PROGRAMMING!"

		# Write parameters permanently
		write_parameters(opts, cp)

		# Batch mode state update and save
		if opts.num is not None:
			opts.num += 1
		save_batch(opts)

		# Done for this card and maybe for everything ?
		print "Done !\n"

		if not opts.batch_mode:
			done = True

