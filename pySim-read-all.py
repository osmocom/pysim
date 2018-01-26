#!/usr/bin/env python2

#
# Utility to display all files from a SIM card
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
from pySim.utils import h2b, swap_nibbles, rpad, dec_imsi, dec_iccid, dec_select_ef_response
from pySim.ts_51_011 import EF, DF

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

	# Read all
	for (name, path) in EF.items():
		try:
			resp = scc.select_file(path)
			(length, file_id, file_type, increase_cmd, access_cond,
			 file_status, data_len, ef_struct, record_len) = dec_select_ef_response(resp[-1])
#			print name, resp
			print name, (length, file_id, file_type, increase_cmd, access_cond, file_status, data_len, ef_struct, record_len)

			if not access_cond[0] == '0' and not access_cond[0] == '1':
				print("%s: Requires %s access to read." % (name, access_cond[0],))
				continue

			if ef_struct == '00':
				# transparent
				(res, sw) = scc.read_binary_selected(length)
				if sw == '9000':
					print("%s: %s" % (name, res,))
				else:
					print("%s: Can't read, response code = %s" % (name, sw,))
			elif (ef_struct == '01' or ef_struct == '03') and record_len>0:
				for i in range(1,length/record_len+1):
					# linear fixed
					(res, sw) = scc.read_record_selected(record_len, i)
					if sw == '9000':
						print("%s[%d]: %s" % (name, i, res,))
					else:
						print("%s[%d]: Can't read, response code = %s" % (name, i, sw,))
			elif ef_struct == '03':
				# cyclic
				raise RuntimeError("Don't know how to read a cyclic EF")
			else:
				raise RuntimeError("Unknown EF type")
		except RuntimeError as e:
			print("%s: Can't read (%s)" % (name,e.message,))

	# Done for this card and maybe for everything ?
	print "Done !\n"
