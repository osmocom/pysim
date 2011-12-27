#!/usr/bin/env python

#
# Utility to generate the HLR
#
#
# Copyright (C) 2010  Sylvain Munaut <tnt@246tNt.com>
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

from ccc import StateManager, CardParametersGenerator, isnum
from pySim.utils import h2b, swap_nibbles, rpad


#
# OpenBSC HLR Writing
#

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


def hlr_write_cards(filename, network, cards):

	import sqlite3

	conn = sqlite3.connect(filename)

	for card in cards:
		c = conn.execute(
			'INSERT INTO Subscriber ' +
			'(imsi, name, extension, authorized, created, updated) ' +
			'VALUES ' +
			'(?,?,?,1,datetime(\'now\'),datetime(\'now\'));',
			[
				card.imsi,
				'%s #%d' % (network.name, card.num),
				'9%05d' % card.num,
			],
		)
		sub_id = c.lastrowid
		c.close()

		c = conn.execute(
			'INSERT INTO AuthKeys ' +
			'(subscriber_id, algorithm_id, a3a8_ki)' +
			'VALUES ' +
			'(?,?,?)',
			[ sub_id, 2, sqlite3.Binary(_dbi_binary_quote(h2b(card.ki))) ],
		)
		c.close()

	conn.commit()
	conn.close()


#
# CSV Writing
#

def csv_write_cards(filename, network, cards):
	import csv
	fh = open(filename, 'a')
	cw = csv.writer(fh)
	cw.writerows(cards)
	fh.close()


#
# Main stuff
#

def parse_options():

	parser = OptionParser(usage="usage: %prog [options]")

	# Network parameters
	parser.add_option("-n", "--name", dest="name",
			help="Operator name [default: %default]",
			default="CCC Event",
		)
	parser.add_option("-c", "--country", dest="country", type="int", metavar="CC",
			help="Country code [default: %default]",
			default=49,
		)
	parser.add_option("-x", "--mcc", dest="mcc", type="int",
			help="Mobile Country Code [default: %default]",
			default=262,
		)
	parser.add_option("-y", "--mnc", dest="mnc", type="int",
			help="Mobile Network Code [default: %default]",
			default=42,
		)
	parser.add_option("-m", "--smsc", dest="smsc",
			help="SMSP [default: '00 + country code + 5555']",
		)
	parser.add_option("-M", "--smsp", dest="smsp",
			help="Raw SMSP content in hex [default: auto from SMSC]",
		)

	# Autogen
	parser.add_option("-z", "--secret", dest="secret", metavar="STR",
			help="Secret used for ICCID/IMSI autogen",
		)
	parser.add_option("-k", "--count", dest="count", type="int", metavar="CNT",
			help="Number of entried to generate [default: %default]",
			default=1000,
		)

	# Output
	parser.add_option("--state", dest="state_file", metavar="FILE",
			help="Use this state file",
		)
	parser.add_option("--write-csv", dest="write_csv", metavar="FILE",
			help="Append generated parameters in CSV file",
		)
	parser.add_option("--write-hlr", dest="write_hlr", metavar="FILE",
			help="Append generated parameters to OpenBSC HLR sqlite3",
		)

	(options, args) = parser.parse_args()

	if args:
		parser.error("Extraneous arguments")

	# Check everything
	if 1 < len(options.name) > 16:
		parser.error("Name must be between 1 and 16 characters")

	if 0 < options.country > 999:
		parser.error("Invalid country code")

	if 0 < options.mcc > 999:
		parser.error("Invalid Mobile Country Code (MCC)")
	if 0 < options.mnc > 999:
		parser.error("Invalid Mobile Network Code (MNC)")

	# SMSP
	if options.smsp is not None:
		smsp = options.smsp
		if not _ishex(smsp):
			raise ValueError('SMSP must be hex digits only !')
		if len(smsp) < 28*2:
			raise ValueError('SMSP must be at least 28 bytes')

	else:
		if options.smsc is not None:
			smsc = options.smsc
			if not _isnum(smsc):
				raise ValueError('SMSC must be digits only !')
		else:
			smsc = '00%d' % options.country + '5555'	# Hack ...

		smsc = '%02d' % ((len(smsc) + 3)//2,) + "81" + swap_nibbles(rpad(smsc, 20))

		options.smsp = (
			'e1' +			# Parameters indicator
			'ff' * 12 +		# TP-Destination address
			smsc +			# TP-Service Centre Address
			'00' +			# TP-Protocol identifier
			'00' +			# TP-Data coding scheme
			'00'			# TP-Validity period
		)

	return options


def main():

	# Parse options
	opts = parse_options()

	# Load state
	sm = StateManager(opts.state_file, opts)
	sm.load()

	# Instanciate generator
	np = sm.network
	cpg = CardParametersGenerator(np.cc, np.mcc, np.mnc, sm.get_secret())

	# Generate cards
	imsis = set()
	cards = []
	while len(cards) < opts.count:
		# Next number
		i = sm.next_gen_num()

		# Generate card number
		cp = cpg.generate(i)

		# Check for dupes
		if cp.imsi in imsis:
			continue
		imsis.add(cp.imsi)

		# Collect
		cards.append(cp)

	# Save cards
	if opts.write_hlr:
		hlr_write_cards(opts.write_hlr, np, cards)

	if opts.write_csv:
		csv_write_cards(opts.write_csv, np, cards)

	# Save state
	sm.save()


if __name__ == '__main__':
	main()
