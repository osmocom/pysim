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

from smartcard.CardConnection import CardConnection
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import NoCardException, CardRequestTimeoutException, CardConnectionException
from smartcard.System import readers

from pySim.exceptions import NoCardError, ProtocolError
from pySim.transport import LinkBase
from pySim.utils import h2i, i2h


class PcscSimLink(LinkBase):

	def __init__(self, reader_number=0):
     """
     Initialize the reader.

     Args:
         self: (todo): write your description
         reader_number: (int): write your description
     """
		r = readers()
		self._reader = r[reader_number]
		self._con = self._reader.createConnection()

	def __del__(self):
     """
     Disconnects a connection

     Args:
         self: (todo): write your description
     """
		self._con.disconnect()
		return

	def wait_for_card(self, timeout=None, newcardonly=False):
     """
     Wait for card card to complete.

     Args:
         self: (todo): write your description
         timeout: (float): write your description
         newcardonly: (todo): write your description
     """
		cr = CardRequest(readers=[self._reader], timeout=timeout, newcardonly=newcardonly)
		try:
			cr.waitforcard()
		except CardRequestTimeoutException:
			raise NoCardError()
		self.connect()

	def connect(self):
     """
     Connect to the connection.

     Args:
         self: (todo): write your description
     """
		try:
			# Explicitly select T=0 communication protocol
			self._con.connect(CardConnection.T0_protocol)
		except CardConnectionException:
			raise ProtocolError()
		except NoCardException:
			raise NoCardError()

	def get_atr(self):
     """
     Returns the atr of the atr.

     Args:
         self: (todo): write your description
     """
		return self._con.getATR()

	def disconnect(self):
     """
     Disconnects from the server.

     Args:
         self: (todo): write your description
     """
		self._con.disconnect()

	def reset_card(self):
     """
     Reset the card.

     Args:
         self: (todo): write your description
     """
		self.disconnect()
		self.connect()
		return 1

	def send_apdu_raw(self, pdu):
		"""see LinkBase.send_apdu_raw"""

		apdu = h2i(pdu)

		data, sw1, sw2 = self._con.transmit(apdu)

		sw = [sw1, sw2]

		# Return value
		return i2h(data), i2h(sw)
