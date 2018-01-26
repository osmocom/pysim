#!/usr/bin/env python

#
# Utility to write data from a Fairwaves SIM card DB to Osmocom HLR DB
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

#from pySim.utils import h2b
def h2b(s):
	return ''.join([chr((int(x,16)<<4)+int(y,16)) for x,y in zip(s[0::2], s[1::2])])

def load_sim_db(filename):
	sim_db = {}
	with open(filename, 'r') as f:
		reader = csv.reader(f, delimiter=' ')
		# Skip the header
#		reader.next()
		for l in reader:
			sim_db[l[0]] = l
	return sim_db

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

def write_key_hlr(opts, sim_data):
	# SQLite3 OpenBSC HLR
	import sqlite3
	conn = sqlite3.connect(opts.hlr_db_filename)

	imsi = sim_data[1]
	ki = sim_data[8]

	c = conn.execute('SELECT id FROM Subscriber WHERE imsi = ?', (imsi,))
	sub_id = c.fetchone()
	if sub_id is None:
		print("IMSI %s is not found in the HLR" % (imsi,))
		return None
	sub_id = sub_id[0]
	print("IMSI %s has ID %d, writing Ki %s" % (imsi, sub_id, ki))

#	c = conn.execute(
#		'INSERT INTO Subscriber ' +
#		'(imsi, name, extension, authorized, created, updated) ' +
#		'VALUES ' +
#		'(?,?,?,1,datetime(\'now\'),datetime(\'now\'));',
#		[
#			params['imsi'],
#			params['name'],
#			'9' + params['iccid'][-5:-1]
#		],
#	)
#	sub_id = c.lastrowid
#	c.close()

	c = conn.execute(
		'INSERT OR REPLACE INTO AuthKeys ' +
		'(subscriber_id, algorithm_id, a3a8_ki)' +
		'VALUES ' +
		'(?,?,?)',
		[ sub_id, 2, sqlite3.Binary(_dbi_binary_quote(h2b(ki))) ],
	)

	c = conn.execute(
		'DELETE FROM AuthLastTuples WHERE subscriber_id = ?',
		[ sub_id ],
	)

	conn.commit()
	conn.close()
	return True


def parse_options():

	parser = OptionParser(usage="usage: %prog [options]",
	                      description="Utility to write data from a Fairwaves SIM card DB to Osmocom HLR DB.")

	parser.add_option("-s", "--sim-db", dest="sim_db_filename", type='string', metavar="FILE",
			help="filename of a SIM DB to load keys from (space searated)",
			default="sim_db.dat",
		)
	parser.add_option("-d", "--hlr", dest="hlr_db_filename", type='string', metavar="FILE",
			help="filename of a HLR SQLite3 DB to write the keys to",
			default="hlr.sqlite3",
		)

	(options, args) = parser.parse_args()

	if args:
		parser.error("Extraneous arguments")

	return options


if __name__ == '__main__':

	# Parse options
	opts = parse_options()

	print("Loading SIM DB ...")
	sim_db = load_sim_db(opts.sim_db_filename)

	for iccid, sim in sim_db.items():
		write_key_hlr(opts, sim)


