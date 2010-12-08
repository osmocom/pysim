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

from pySim.exceptions import NoCardError
from pySim.transport import LinkBase
from pySim.utils import h2i, i2h


class PcscSimLink(LinkBase):

	def __init__(self, reader_number=0):
		r = readers();
		try:
			self._con = r[reader_number].createConnection()
			self._con.connect()
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
		"""see LinkBase.send_apdu_raw"""

		apdu = h2i(pdu)

		data, sw1, sw2 = self._con.transmit(apdu)

		sw = [sw1, sw2]

		# Return value
		return i2h(data), i2h(sw)
