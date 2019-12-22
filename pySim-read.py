#!/usr/bin/env python2

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
from pySim.ts_51_011 import EF, DF

try:
	import json
except ImportError:
	# Python < 2.5
	import simplejson as json

from pySim.commands import SimCardCommands
from pySim.utils import h2b, swap_nibbles, rpad, dec_imsi, dec_iccid, dec_msisdn, format_xplmn_w_act, dec_spn


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
	parser.add_option("--osmocon", dest="osmocon_sock", metavar="PATH",
			help="Socket path for Calypso (e.g. Motorola C1XX) based reader (via OsmocomBB)",
			default=None,
		)

	(options, args) = parser.parse_args()

	if args:
		parser.error("Extraneous arguments")

	return options


if __name__ == '__main__':

	# Parse options
	opts = parse_options()

	# Init card reader driver
	if opts.pcsc_dev is not None:
		print("Using PC/SC reader (dev=%d) interface"
			% opts.pcsc_dev)
		from pySim.transport.pcsc import PcscSimLink
		sl = PcscSimLink(opts.pcsc_dev)
	elif opts.osmocon_sock is not None:
		print("Using Calypso-based (OsmocomBB, sock=%s) reader interface"
			% opts.osmocon_sock)
		from pySim.transport.calypso import CalypsoSimLink
		sl = CalypsoSimLink(sock_path=opts.osmocon_sock)
	else: # Serial reader is default
		print("Using serial reader (port=%s, baudrate=%d) interface"
			% (opts.device, opts.baudrate))
		from pySim.transport.serial import SerialSimLink
		sl = SerialSimLink(device=opts.device, baudrate=opts.baudrate)

	# Create command layer
	scc = SimCardCommands(transport=sl)

	# Wait for SIM card
	sl.wait_for_card()

	# Program the card
	print("Reading ...")

	# EF.ICCID
	(res, sw) = scc.read_binary(EF['ICCID'])
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

	# EF.SPN
	try:
		(res, sw) = scc.read_binary(EF['SPN'])
		if sw == '9000':
			spn_res = dec_spn(res)
			print("SPN: %s" % (spn_res[0] or "Not available"))
			print("Display HPLMN: %s" % (spn_res[1],))
			print("Display OPLMN: %s" % (spn_res[2],))
		else:
			print("SPN: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("SPN: Can't read file -- %s" % (str(e),))

	# EF.PLMNsel
	try:
		(res, sw) = scc.read_binary(EF['PLMNsel'])
		if sw == '9000':
			print("PLMNsel: %s" % (res))
		else:
			print("PLMNsel: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("PLMNsel: Can't read file -- " + str(e))

	# EF.PLMNwAcT
	try:
		(res, sw) = scc.read_binary(EF['PLMNwAcT'])
		if sw == '9000':
			print("PLMNwAcT:\n%s" % (format_xplmn_w_act(res)))
		else:
			print("PLMNwAcT: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("PLMNwAcT: Can't read file -- " + str(e))

	# EF.OPLMNwAcT
	try:
		(res, sw) = scc.read_binary(EF['OPLMNwAcT'])
		if sw == '9000':
			print("OPLMNwAcT:\n%s" % (format_xplmn_w_act(res)))
		else:
			print("OPLMNwAcT: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("OPLMNwAcT: Can't read file -- " + str(e))

	# EF.HPLMNAcT
	try:
		(res, sw) = scc.read_binary(EF['HPLMNAcT'])
		if sw == '9000':
			print("HPLMNAcT:\n%s" % (format_xplmn_w_act(res)))
		else:
			print("HPLMNAcT: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("HPLMNAcT: Can't read file -- " + str(e))

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
			res_dec = dec_msisdn(res)
			if res_dec is not None:
				# (npi, ton, msisdn) = res_dec
				print("MSISDN (NPI=%d ToN=%d): %s" % res_dec)
			else:
				print("MSISDN: Not available")
		else:
			print("MSISDN: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("MSISDN: Can't read file -- " + str(e))

	# EF.AD
	(res, sw) = scc.read_binary(['3f00', '7f20', '6fad'])
	if sw == '9000':
		print("AD: %s" % (res,))
	else:
		print("AD: Can't read, response code = %s" % (sw,))

	# Done for this card and maybe for everything ?
	print("Done !\n")
