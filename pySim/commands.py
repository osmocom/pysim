#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pySim: SIM Card commands according to ISO 7816-4 and TS 11.11
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010       Harald Welte <laforge@gnumonks.org>
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

from pySim.utils import rpad, b2h


class SimCardCommands(object):
	def __init__(self, transport):
		self._tp = transport;

	def select_file(self, dir_list):
		rv = []
		for i in dir_list:
			data, sw = self._tp.send_apdu_checksw("a0a4000002" + i)
			rv.append(data)
		return rv

	def read_binary(self, ef, length=None, offset=0):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		if length is None:
			length = int(r[-1][4:8], 16) - offset
		pdu = 'a0b0%04x%02x' % (offset, (min(256, length) & 0xff))
		return self._tp.send_apdu(pdu)

	def update_binary(self, ef, data, offset=0):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		self.select_file(ef)
		pdu = 'a0d6%04x%02x' % (offset, len(data)/2) + data
		return self._tp.send_apdu_checksw(pdu)

	def read_record(self, ef, rec_no):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		rec_length = int(r[-1][28:30], 16)
		pdu = 'a0b2%02x04%02x' % (rec_no, rec_length)
		return self._tp.send_apdu(pdu)

	def update_record(self, ef, rec_no, data, force_len=False):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		if not force_len:
			rec_length = int(r[-1][28:30], 16)
			if (len(data)/2 != rec_length):
				raise ValueError('Invalid data length (expected %d, got %d)' % (rec_length, len(data)/2))
		else:
			rec_length = len(data)/2
		pdu = ('a0dc%02x04%02x' % (rec_no, rec_length)) + data
		return self._tp.send_apdu_checksw(pdu)

	def record_size(self, ef):
		r = self.select_file(ef)
		return int(r[-1][28:30], 16)

	def record_count(self, ef):
		r = self.select_file(ef)
		return int(r[-1][4:8], 16) // int(r[-1][28:30], 16)

	def run_gsm(self, rand):
		if len(rand) != 32:
			raise ValueError('Invalid rand')
		self.select_file(['3f00', '7f20'])
		return self._tp.send_apdu('a088000010' + rand)

	def reset_card(self):
		return self._tp.reset_card()

	def verify_chv(self, chv_no, code):
		fc = rpad(b2h(code), 16)
		return self._tp.send_apdu_checksw('a02000' + ('%02x' % chv_no) + '08' + fc)
