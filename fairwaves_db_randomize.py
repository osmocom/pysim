#!/usr/bin/env python

#
# Utility to randomize Ki and other values in a Fairwaves SIM card DB file
#
# Copyright (C) 2017-2018  Alexander Chemeris <alexander.chemeris@gmail.com>
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

from optparse import OptionParser
import os
import sys
import csv
import random

from pySim.utils import derive_milenage_opc

#from pySim.utils import h2b
def h2b(s):
	return ''.join([chr((int(x,16)<<4)+int(y,16)) for x,y in zip(s[0::2], s[1::2])])

def load_sim_db(filename):
	sim_db = {}
	with open(filename, 'r') as f:
		reader = csv.reader(f, delimiter=' ')
		# Skip the header
		reader.next()
		for l in reader:
			sim_db[l[0]] = l
	return sim_db

def write_sim_db(filename, sim_db):
	with open(filename, 'a') as f:
		cw = csv.writer(f, delimiter=' ')
		for iccid in sorted(sim_db.iterkeys()):
			cw.writerow([x for x in sim_db[iccid]])

def process_sim(sim_keys, opts):
	# Update IMSI
	imsi = sim_keys[1]
	imsi = "%03d%02d%s" % (opts.mcc, opts.mnc, imsi[5:])
	sim_keys[1] = imsi

	# Update Ki
	ki = ''.join(['%02x' % random.randrange(0,256) for i in range(16)]).upper()
	sim_keys[8] = ki

	# Update OPC
	op_opc = derive_milenage_opc(ki, opts.op).upper()
	sim_keys[9] = '01' + op_opc

	return sim_keys


def process_db(sim_db, opts):
	sim_db_new = {}
	for iccid, sim_keys in sim_db.items():
		sim_db_new[iccid] = process_sim(sim_keys, opts)
	return sim_db_new


def parse_options():

	parser = OptionParser(usage="usage: %prog [options]",
	                      description="Utility to randomize Ki and other values in a Fairwaves SIM card DB file.")

	parser.add_option("-s", "--sim-db", dest="sim_db_filename", type='string', metavar="FILE",
			help="filename of a SIM DB to load keys from (space separated)",
			default="sim_db.dat",
		)
	parser.add_option("-o", "--out-db", dest="out_db_filename", type='string', metavar="FILE",
			help="filename of a SIM DB to write keys to (space separated)",
			default=None,
		)
	parser.add_option("-x", "--mcc", dest="mcc", type="int",
			help="Mobile Country Code [default: %default]",
			default=001,
		)
	parser.add_option("-y", "--mnc", dest="mnc", type="int",
			help="Mobile Network Code [default: %default]",
			default=01,
		)
	parser.add_option("--op", dest="op",
			help="Set OP to derive OPC from OP and KI [default: %default]",
			default='00000000000000000000000000000000',
		)

	(options, args) = parser.parse_args()

	if args:
		parser.error("Extraneous arguments")

	return options


if __name__ == '__main__':

	# Parse options
	opts = parse_options()

	if opts.out_db_filename is None:
		print("Please specify output DB filename")
		sys.exit(1)

	print("Loading SIM DB ...")
	sim_db = load_sim_db(opts.sim_db_filename)

	sim_db = process_db(sim_db, opts)

	print("Writing SIM DB ...")
	write_sim_db(opts.out_db_filename, sim_db)
