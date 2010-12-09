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
import random
import re
import sys

from pySim.commands import SimCardCommands
from pySim.cards import _cards_classes
from pySim.utils import h2b


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
			help="Mobile Network Code [default: %default]",
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

	parser.add_option("--write-csv", dest="write_csv", metavar="FILE",
			help="Append generated parameters in CSV file",
		)
	parser.add_option("--write-hlr", dest="write_hlr", metavar="FILE",
			help="Append generated parameters to OpenBSC HLR sqlite3",
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


def write_parameters(opts, params):
	# CSV
	if opts.write_csv:
		import csv
		row = ['name', 'iccid', 'mcc', 'mnc', 'imsi', 'smsp', 'ki']
		f = open(opts.write_csv, 'a')
		cw = csv.writer(f)
		cw.writerow([params[x] for x in row])
		f.close()

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
				'9' + params['iccid'][-5:]
			],
		)
		sub_id = c.lastrowid
		c.close()

		c = conn.execute(
			'INSERT INTO AuthKeys ' +
			'(subscriber_id, algorithm_id, a3a8_ki)' +
			'VALUES ' +
			'(?,?,?)',
			[ sub_id, 2, sqlite3.Binary(h2b(params['ki'])) ],
		)

		conn.commit()
		conn.close()



if __name__ == '__main__':

	# Get/Gen the parameters
	opts = parse_options()
	cp = gen_parameters(opts)
	print_parameters(cp)
	write_parameters(opts, cp)

	# Connect to the card
	if opts.pcsc_dev is None:
		from pySim.transport.serial import SerialSimLink
		sl = SerialSimLink(device=opts.device, baudrate=opts.baudrate)
	else:
		from pySim.transport.pcsc import PcscSimLink
		sl = PcscSimLink(opts.pcsc_dev)
	scc = SimCardCommands(transport=sl)

	print "Insert Card now"
	sl.wait_for_card()

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

