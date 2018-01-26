#!/usr/bin/env python

#
# Utility to update SPN field of a SIM card
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
import subprocess

from pySim.commands import SimCardCommands
from pySim.utils import h2b, swap_nibbles, rpad, dec_imsi, dec_iccid, derive_milenage_opc
from pySim.cards import card_autodetect


def load_sim_db(filename):
	sim_db = {}
	with open(filename, 'r') as f:
		reader = csv.reader(f, delimiter=' ')
		# Skip the header
		reader.next()
		for l in reader:
			sim_db[l[0]] = l
	return sim_db

def write_params_csv(filename, sim_keys):
	with open(filename, 'a') as f:
		cw = csv.writer(f, delimiter=' ')
		cw.writerow([x for x in sim_keys])


def program_sim_card(card, sim_db, opts):
	# Program the card
	print("Reading SIM card ...")

	# EF.ICCID
	(iccid, sw) = card.read_iccid()
	if sw != '9000':
		print("ICCID: Can't read, response code = %s" % (sw,))
		sys.exit(1)
	print("ICCID: %s" % (iccid))

	# Find SIM card keys in the DB
	sim_keys = sim_db.get(iccid+'F')
	if sim_keys == None:
		print("Can't find SIM card in the SIM DB.")
		sys.exit(1)

	# EF.IMSI
	(imsi, sw) = card.read_imsi()
	if sw != '9000':
		print("IMSI: Can't read, response code = %s" % (sw,))
		sys.exit(1)
	print("IMSI: %s" % (imsi))

	# EF.SPN
	((name, hplmn_disp, oplmn_disp), sw) = card.read_spn()
	if sw == '9000':
		print("Service Provider Name:    %s" % name)
		print("  display for HPLMN       %s" % hplmn_disp)
		print("  display for other PLMN  %s" % oplmn_disp)
	else:
		print("Old SPN: Can't read, response code = %s" % (sw,))

	print("Entring ADM code...")

	# Enter ADM code to get access to proprietary files
	sw = card.verify_adm(h2b(sim_keys[6]))
	if sw != '9000':
		print("Fail to verify ADM code with result = %s" % (sw,))
		sys.exit(1)

	# Read EF.Ki
	(ki, sw) = card.read_ki()
	if sw == '9000':
		ki = ki.upper()
		print("Ki:                       %s" % ki)
	else:
		print("Ki: Can't read, response code = %s" % (sw,))

	# Read EF.OP/OPC
	((op_opc_type, op_opc), sw) = card.read_op_opc()
	if sw == '9000':
		op_opc = op_opc.upper()
		print("%s:                      %s" % (op_opc_type, op_opc))
	else:
		print("Ki: Can't read, response code = %s" % (sw,))

	print("Programming...")

	# Update SPN
	sw = card.update_spn(opts.name, False, False)
	if sw != '9000':
		print("SPN: Fail to update with result = %s" % (sw,))
		sys.exit(1)

	# Update Ki
	ki = ''.join(['%02x' % random.randrange(0,256) for i in range(16)]).upper()
	sim_keys[8] = ki
	sw = card.update_ki(sim_keys[8])
	if sw != '9000':
		print("Ki: Fail to update with result = %s" % (sw,))
		sys.exit(1)

	# Update OPC
	op_opc = derive_milenage_opc(ki, opts.op).upper()
	sim_keys[9] = '01' + op_opc
	sw = card.update_opc(sim_keys[9][2:])
	if sw != '9000':
		print("OPC: Fail to update with result = %s" % (sw,))
		sys.exit(1)

	# Update Home PLMN
	sw = card.update_hplmn_act(opts.mcc, opts.mnc)
	if sw != '9000':
		print("MCC/MNC: Fail to update with result = %s" % (sw,))
		sys.exit(1)

	# Update IMSI
	imsi = "%03d%02d%s" % (opts.mcc, opts.mnc, imsi[5:])
	sw = card.update_imsi(imsi)
	if sw != '9000':
		print("IMSI: Fail to update with result = %s" % (sw,))
		sys.exit(1)

	# Verify EF.IMSI
	(imsi_new, sw) = card.read_imsi()
	if sw != '9000':
		print("IMSI: Can't read, response code = %s" % (sw,))
		sys.exit(1)
	print("IMSI: %s" % (imsi_new))

	# Verify EF.SPN
	((name, hplmn_disp, oplmn_disp), sw) = card.read_spn()
	if sw == '9000':
		print("Service Provider Name:    %s" % name)
		print("  display for HPLMN       %s" % hplmn_disp)
		print("  display for other PLMN  %s" % oplmn_disp)
	else:
		print("New SPN: Can't read, response code = %s" % (sw,))

	# Verify EF.Ki
	(ki_new, sw) = card.read_ki()
	if sw == '9000':
		ki_new = ki_new.upper()
		print("Ki:                       %s (%s)" % (ki_new, "match" if (ki==ki_new) else ("DON'T match %s" % ki)))
	else:
		print("New Ki: Can't read, response code = %s" % (sw,))

	# Verify EF.OP/OPC
	((op_opc_type_new, op_opc_new), sw) = card.read_op_opc()
	if sw == '9000':
		op_opc_new = op_opc_new.upper()
		print("%s:                      %s (%s)" % (op_opc_type_new, op_opc_new, "match" if (op_opc==op_opc_new) else ("DON'T match %s" % op_opc)))
	else:
		print("Ki: Can't read, response code = %s" % (sw,))

	# Done with this card
	print "Done !\n"

	return sim_keys


def parse_options():

	parser = OptionParser(usage="usage: %prog [options]",
	                      description="An example utility to program Fairwaves SIM cards."
	                                  " Modify it to your own specific needs.")

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
	parser.add_option("-s", "--sim-db", dest="sim_db_filename", type='string', metavar="FILE",
			help="filename of a SIM DB to load keys from (space searated)",
			default="sim_db.dat",
		)
	parser.add_option("-o", "--out-db", dest="out_db_filename", type='string', metavar="FILE",
			help="filename of a SIM DB to write keys to (space searated)",
			default="out.csv",
		)
	parser.add_option("--batch", dest="batch",
			help="Process SIM cards in batch mode - don't exit after programming and wait for the next SIM card to be inserted.",
			default=False, action="store_true",
		)
	parser.add_option("--sound", dest="sound_file", type='string', metavar="SOUND_FILE",
			help="Only in the batch mode. Play the given sound file on successful SIM programming",
		)
	parser.add_option("-n", "--name", dest="name",
			help="Operator name [default: %default]",
			default="Fairwaves",
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

	# Connect to the card
	if opts.pcsc_dev is None:
		from pySim.transport.serial import SerialSimLink
		sl = SerialSimLink(device=opts.device, baudrate=opts.baudrate)
	else:
		from pySim.transport.pcsc import PcscSimLink
		sl = PcscSimLink(opts.pcsc_dev)

	# Create command layer
	scc = SimCardCommands(transport=sl)

	print("Loading SIM DB ...")
	sim_db = load_sim_db(opts.sim_db_filename)

	if opts.batch:
		print("Batch mode enabled! Press Ctrl-C to exit")

	# Loop once in non-batch mode and loop forever in batch mode
	first_run = True
	while first_run or opts.batch:
		print("Insert a SIM card to program...")
		sl.wait_for_card(newcardonly=not first_run)
		first_run = False

		card = card_autodetect(scc)
		if card is None:
			print("Card autodetect failed")
			continue
		print "Autodetected card type %s" % card.name

		sim_keys = program_sim_card(card, sim_db, opts)
		write_params_csv(opts.out_db_filename, sim_keys)
		if opts.sound_file is not None and opts.sound_file != "":
			subprocess.call(["paplay", opts.sound_file])
