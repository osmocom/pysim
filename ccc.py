#!/usr/bin/env python

#
# CCC Event HLR management common stuff
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

import hashlib
import os
import random

from collections import namedtuple

try:
	import json
except Importerror:
	# Python < 2.5
	import simplejson as json

#
# Various helpers
#

def isnum(s, l=-1):
	return s.isdigit() and ((l== -1) or (len(s) == l))


#
# Storage tuples
#

CardParameters = namedtuple("CardParameters", "num iccid imsi ki")
NetworkParameters = namedtuple("NetworkParameters", "name cc mcc mnc smsp")


#
# State management
#

class StateManager(object):

	def __init__(self, filename=None, options=None):
		# Filename for state storage
		self._filename = filename

		# Params from options
		self._net_name = options.name		if options else None
		self._net_cc   = options.country	if options else None
		self._net_mcc  = options.mcc		if options else None
		self._net_mnc  = options.mnc		if options else None
		self._net_smsp = options.smsp		if options else None

		self._secret   = options.secret		if options else None

		# Default
		self._num_gen = 0
		self._num_write = 0

	def load(self):
		# Skip if no state file
		if self._filename is None:
			return

		# Skip if doesn't exist yet
		if not os.path.isfile(self._filename):
			return

		# Read
		fh = open(self._filename, 'r')
		data = fh.read()
		fh.close()

		# Decode json and merge
		dd = json.loads(data)

		self._net_name  = dd['name']
		self._net_cc    = dd['cc']
		self._net_mcc   = dd['mcc']
		self._net_mnc   = dd['mnc']
		self._net_smsp  = dd['smsp']
		self._secret    = dd['secret']
		self._num_gen   = dd['num_gen']
		self._num_write = dd['num_write']

	def save(self):
		# Skip if no state file
		if self._filename is None:
			return

		# Serialize
		data = json.dumps({
			'name':      self._net_name,
			'cc':        self._net_cc,
			'mcc':       self._net_mcc,
			'mnc':       self._net_mnc,
			'smsp':      self._net_smsp,
			'secret':    self._secret,
			'num_gen':   self._num_gen,
			'num_write': self._num_write,
		})

		# Save in json
		fh = open(self._filename, 'w')
		fh.write(data)
		fh.close()

	@property
	def network(self):
		return NetworkParameters(
			self._net_name,
			self._net_cc,
			self._net_mcc,
			self._net_mnc,
			self._net_smsp,
		)

	def get_secret(self):
		return self._secret

	def next_gen_num(self):
		n = self._num_gen
		self._num_gen += 1
		return n

	def next_write_num(self):
		n = self._num_write
		self._num_write += 1
		return n

#
# Card parameters generation
#

class CardParametersGenerator(object):

	def __init__(self, cc, mcc, mnc, secret):
		# Digitize country code (2 or 3 digits)
		self._cc_digits = ('%03d' if cc > 100 else '%02d') % cc

		# Digitize MCC/MNC (5 or 6 digits)
		self._plmn_digits = ('%03d%03d' if mnc > 100 else '%03d%02d') % (mcc, mnc)

		# Store secret
		self._secret = secret

	def _digits(self, usage, len_, num):
		s = hashlib.sha1(self._secret + usage + '%d' % num)
		d = ''.join(['%02d'%ord(x) for x in s.digest()])
		return d[0:len_]

	def _gen_iccid(self, num):
		iccid = (
			'89' +				# Common prefix (telecom)
			self._cc_digits +	# Country Code on 2/3 digits
			self._plmn_digits 	# MCC/MNC on 5/6 digits
		)
		ml = 20 - len(iccid)
		iccid += self._digits('ccid', ml, num)
		return iccid

	def _gen_imsi(self, num):
		ml = 15 - len(self._plmn_digits)
		msin = self._digits('imsi', ml, num)
		return (
			self._plmn_digits +	# MCC/MNC on 5/6 digits
			msin				# MSIN
		)

	def _gen_ki(self):
		return ''.join(['%02x' % random.randrange(0,256) for i in range(16)])

	def generate(self, num):
		return CardParameters(
			num,
			self._gen_iccid(num),
			self._gen_imsi(num),
			self._gen_ki(),
		)
