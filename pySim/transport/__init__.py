# -*- coding: utf-8 -*-

""" pySim: PCSC reader transport link base
"""

from typing import Optional

from pySim.exceptions import *
from pySim.utils import sw_match

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
	"""Base class for link/transport to card."""

	def __init__(self, sw_interpreter=None):
		self.sw_interpreter = sw_interpreter

	def set_sw_interpreter(self, interp):
		"""Set an (optional) status word interpreter."""
		self.sw_interpreter = interp

	def wait_for_card(self, timeout:int=None, newcardonly:bool=False):
		"""Wait for a card and connect to it

		Args:
		   timeout : Maximum wait time in seconds (None=no timeout)
		   newcardonly : Should we wait for a new card, or an already inserted one ?
		"""
		pass

	def connect(self):
		"""Connect to a card immediately
		"""
		pass

	def disconnect(self):
		"""Disconnect from card
		"""
		pass

	def reset_card(self):
		"""Resets the card (power down/up)
		"""
		pass

	def send_apdu_raw(self, pdu:str):
		"""Sends an APDU with minimal processing

		Args:
		   pdu : string of hexadecimal characters (ex. "A0A40000023F00")
		Returns:
		   tuple(data, sw), where
				data : string (in hex) of returned data (ex. "074F4EFFFF")
				sw   : string (in hex) of status word (ex. "9000")
		"""
		return self._send_apdu_raw(pdu)

	def send_apdu(self, pdu):
		"""Sends an APDU and auto fetch response data

		Args:
		   pdu : string of hexadecimal characters (ex. "A0A40000023F00")
		Returns:
		   tuple(data, sw), where
				data : string (in hex) of returned data (ex. "074F4EFFFF")
				sw   : string (in hex) of status word (ex. "9000")
		"""
		data, sw = self.send_apdu_raw(pdu)

		# When whe have sent the first APDU, the SW may indicate that there are response bytes
		# available. There are two SWs commonly used for this 9fxx (sim) and 61xx (usim), where
		# xx is the number of response bytes available.
		# See also:
		# SW1=9F: 3GPP TS 51.011 9.4.1, Responses to commands which are correctly executed
		# SW1=61: ISO/IEC 7816-4, Table 5 — General meaning of the interindustry values of SW1-SW2
		if (sw is not None) and ((sw[0:2] == '9f') or (sw[0:2] == '61')):
			pdu_gr = pdu[0:2] + 'c00000' + sw[2:4]
			data, sw = self.send_apdu_raw(pdu_gr)

		return data, sw

	def send_apdu_checksw(self, pdu, sw="9000"):
		"""Sends an APDU and check returned SW

		Args:
		   pdu : string of hexadecimal characters (ex. "A0A40000023F00")
		   sw : string of 4 hexadecimal characters (ex. "9000"). The user may mask out certain
				digits using a '?' to add some ambiguity if needed.
		Returns:
			tuple(data, sw), where
				data : string (in hex) of returned data (ex. "074F4EFFFF")
				sw   : string (in hex) of status word (ex. "9000")
		"""
		rv = self.send_apdu(pdu)

		if not sw_match(rv[1], sw):
			raise SwMatchError(rv[1], sw.lower(), self.sw_interpreter)
		return rv

def init_reader(opts, **kwargs) -> Optional[LinkBase]:
	"""
	Init card reader driver
	"""
	sl = None # type : :Optional[LinkBase]
	try:
		if opts.pcsc_dev is not None:
			print("Using PC/SC reader interface")
			from pySim.transport.pcsc import PcscSimLink
			sl = PcscSimLink(opts.pcsc_dev, **kwargs)
		elif opts.osmocon_sock is not None:
			print("Using Calypso-based (OsmocomBB) reader interface")
			from pySim.transport.calypso import CalypsoSimLink
			sl = CalypsoSimLink(sock_path=opts.osmocon_sock, **kwargs)
		elif opts.modem_dev is not None:
			print("Using modem for Generic SIM Access (3GPP TS 27.007)")
			from pySim.transport.modem_atcmd import ModemATCommandLink
			sl = ModemATCommandLink(device=opts.modem_dev, baudrate=opts.modem_baud, **kwargs)
		else: # Serial reader is default
			print("Using serial reader interface")
			from pySim.transport.serial import SerialSimLink
			sl = SerialSimLink(device=opts.device, baudrate=opts.baudrate, **kwargs)
		return sl
	except Exception as e:
		print("Card reader initialization failed with exception:\n" + str(e))
		return None
