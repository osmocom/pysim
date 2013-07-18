#!/usr/bin/env python

#
# Utility to display some informations about a SIM card
#
#
# Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010  Harald Welte <laforge@gnumonks.org>
# Copyright (C) 2013  Alexander Chemeris <alexander.chemeris@gmail.com>
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
from pySim.utils import h2b, swap_nibbles, rpad, dec_imsi, dec_iccid


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

	(options, args) = parser.parse_args()

	if args:
		parser.error("Extraneous arguments")

	return options


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

	# Wait for SIM card
	sl.wait_for_card()

	# Program the card
	print("Reading ...")

	# EF.ICCID
	(res, sw) = scc.read_binary(['3f00', '2fe2'])
	if sw == '9000':
		print("ICCID: %s" % (dec_iccid(res),))
	else:
		print("ICCID: Can't read, response code = %s" % (sw,))

	# EF.IMSI
	(res, sw) = scc.read_binary(['3f00', '7f20', '6f07'])
	if sw == '9000':
		print("IMSI: %s" % (dec_imsi(res),))
	else:
		print("IMSI: Can't read, response code = %s" % (sw,))

	# EF.SMSP
	(res, sw) = scc.read_record(['3f00', '7f10', '6f42'], 1)
	if sw == '9000':
		print("SMSP: %s" % (res,))
	else:
		print("SMSP: Can't read, response code = %s" % (sw,))

	# EF.HPLMN
#	(res, sw) = scc.read_binary(['3f00', '7f20', '6f30'])
#	if sw == '9000':
#		print("HPLMN: %s" % (res))
#		print("HPLMN: %s" % (dec_hplmn(res),))
#	else:
#		print("HPLMN: Can't read, response code = %s" % (sw,))
	# FIXME

	# EF.ACC
	(res, sw) = scc.read_binary(['3f00', '7f20', '6f78'])
	if sw == '9000':
		print("ACC: %s" % (res,))
	else:
		print("ACC: Can't read, response code = %s" % (sw,))

	# EF.MSISDN
	try:
	#	print(scc.record_size(['3f00', '7f10', '6f40']))
		(res, sw) = scc.read_record(['3f00', '7f10', '6f40'], 1)
		if sw == '9000':
			if res[1] != 'f':
				print("MSISDN: %s" % (res,))
			else:
				print("MSISDN: Not available")
		else:
			print("MSISDN: Can't read, response code = %s" % (sw,))
	except:
		print "MSISDN: Can't read. Probably not existing file"

	# Done for this card and maybe for everything ?
	print "Done !\n"
