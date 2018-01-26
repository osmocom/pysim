#!/usr/bin/env python2

#
# Utility to run an A3/A8 algorithm on a SIM card
#
# Copyright (C) 2018  Alexander Chemeris <alexander.chemeris@gmail.com>
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

import sys
from optparse import OptionParser
from pySim.commands import SimCardCommands

def parse_options():

	parser = OptionParser(usage="usage: %prog [options]",
	                      description="Utility to run an A3/A8 algorithm on a SIM card. "
	                                  "Prints generated SRES and Kc for a given RAND number "
	                                  "and exits.")

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
	parser.add_option("-r", "--rand", dest="rand", metavar="RAND",
			help="16 bytes of RAND value",
			default=None,
		)

	(options, args) = parser.parse_args()

	if args:
		parser.error("Extraneous arguments")

	return options


if __name__ == '__main__':

	# Parse options
	opts = parse_options()

	if opts.rand is None:
		print("Please specify RAND value")
		sys.exit(1)
	if len(opts.rand) != 32:
		print("RAND must be 16 bytes long")
		sys.exit(1)

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
	print("Running GSM algorithm with RAND %s" % (opts.rand,))

	# Run GSM A3/A8
	(res, sw) = scc.run_gsm(opts.rand)
	if sw == '9000':
		sres, kc = res
		print("SRES = %s" % (sres,))
		print("Kc   = %s" % (kc,))
	else:
		print("Error %s, result data '%s'" % (sw, res))

	# Done for this card and maybe for everything ?
	print "Done !\n"
