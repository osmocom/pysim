#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pySim: PCSC reader transport link base
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
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

class LinkBase(object):

	def wait_for_card(self, timeout=None, newcardonly=False):
		"""wait_for_card(): Wait for a card and connect to it

		   timeout     : Maximum wait time (None=no timeout)
		   newcardonly : Should we wait for a new card, or an already
		                 inserted one ?
		"""
		pass

	def connect(self):
		"""connect(): Connect to a card immediately
		"""
		pass

	def disconnect(self):
		"""disconnect(): Disconnect from card
		"""
		pass

	def reset_card(self):
		"""reset_card(): Resets the card (power down/up)
		"""
		pass

	def send_apdu_raw(self, pdu):
		"""send_apdu_raw(pdu): Sends an APDU with minimal processing

		   pdu    : string of hexadecimal characters (ex. "A0A40000023F00")
		   return : tuple(data, sw), where
		            data : string (in hex) of returned data (ex. "074F4EFFFF")
		            sw   : string (in hex) of status word (ex. "9000")
		"""
		pass

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
