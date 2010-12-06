#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pySim: PCSC reader transport link
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010  Harald Welte <laforge@gnumonks.org>
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

from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver

from pySim.exceptions import NoCardError
from pySim.utils import h2i, i2h


class PcscSimLink(object):

	def __init__(self, reader_number=0, observer=0):
		r = readers();
		try:
			self._con = r[reader_number].createConnection()
			if (observer):
			    observer = ConsoleCardConnectionObserver()
			    self._con.addObserver(observer)
			self._con.connect()
			#print r[reader_number], b2h(self._con.getATR())
		except NoCardException:
			raise NoCardError()

	def __del__(self):
		self._con.disconnect()
		return

	def reset_card(self):
		self._con.disconnect()
		try:
			self._con.connect()
		except NoCardException:
			raise NoCardError()
		return 1

	def send_apdu_raw(self, pdu):
		"""send_apdu_raw(pdu): Sends an APDU with minimal processing

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		apdu = h2i(pdu)

		data, sw1, sw2 = self._con.transmit(apdu)

		sw = [sw1, sw2]

		# Return value
		return i2h(data), i2h(sw)

	def send_apdu(self, pdu):
		"""send_apdu(pdu): Sends an APDU and auto fetch response data

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		data, sw = self.send_apdu_raw(pdu)

		if (sw is not None) and (sw[0:2] == '9f'):
			pdu_gr = pdu[0:2] + 'c00000' + sw[2:4]
			data, sw = self.send_apdu_raw(pdu_gr)

		return data, sw

	def send_apdu_checksw(self, pdu, sw="9000"):
		"""send_apdu_checksw(pdu,sw): Sends an APDU and check returned SW

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   sw     : string of 4 hexadecimal characters (ex. "9000")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		rv = self.send_apdu(pdu)
		if sw.lower() != rv[1]:
			raise RuntimeError("SW match failed ! Expected %s and got %s." % (sw.lower(), rv[1]))
		return rv
