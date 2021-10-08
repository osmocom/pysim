# -*- coding: utf-8 -*-

""" pySim: PCSC reader transport link base
"""

import abc
import argparse
from typing import Optional, Tuple

from pySim.exceptions import *
from pySim.construct import filter_dict
from pySim.utils import sw_match, b2h, h2b, i2h

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2021 Harald Welte <laforge@osmocom.org>
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

class ApduTracer:
	def trace_command(self, cmd):
		pass

	def trace_response(self, cmd, sw, resp):
		pass


class LinkBase(abc.ABC):
	"""Base class for link/transport to card."""

	def __init__(self, sw_interpreter=None, apdu_tracer=None):
		self.sw_interpreter = sw_interpreter
		self.apdu_tracer = apdu_tracer

	@abc.abstractmethod
	def _send_apdu_raw(self, pdu:str) -> Tuple[str, str]:
		"""Implementation specific method for sending the PDU."""

	def set_sw_interpreter(self, interp):
		"""Set an (optional) status word interpreter."""
		self.sw_interpreter = interp

	@abc.abstractmethod
	def wait_for_card(self, timeout:int=None, newcardonly:bool=False):
		"""Wait for a card and connect to it

		Args:
		   timeout : Maximum wait time in seconds (None=no timeout)
		   newcardonly : Should we wait for a new card, or an already inserted one ?
		"""

	@abc.abstractmethod
	def connect(self):
		"""Connect to a card immediately
		"""

	@abc.abstractmethod
	def disconnect(self):
		"""Disconnect from card
		"""

	@abc.abstractmethod
	def reset_card(self):
		"""Resets the card (power down/up)
		"""

	def send_apdu_raw(self, pdu:str):
		"""Sends an APDU with minimal processing

		Args:
		   pdu : string of hexadecimal characters (ex. "A0A40000023F00")
		Returns:
		   tuple(data, sw), where
				data : string (in hex) of returned data (ex. "074F4EFFFF")
				sw   : string (in hex) of status word (ex. "9000")
		"""
		if self.apdu_tracer:
			self.apdu_tracer.trace_command(pdu)
		(data, sw) = self._send_apdu_raw(pdu)
		if self.apdu_tracer:
			self.apdu_tracer.trace_response(pdu, sw, data)
		return (data, sw)

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
		if (sw is not None):
			if ((sw[0:2] == '9f') or (sw[0:2] == '61')):
				# SW1=9F: 3GPP TS 51.011 9.4.1, Responses to commands which are correctly executed
				# SW1=61: ISO/IEC 7816-4, Table 5 — General meaning of the interindustry values of SW1-SW2
				pdu_gr = pdu[0:2] + 'c00000' + sw[2:4]
				data, sw = self.send_apdu_raw(pdu_gr)
			if sw[0:2] == '6c':
				# SW1=6C: ETSI TS 102 221 Table 7.1: Procedure byte coding
				pdu_gr = pdu[0:8] + sw[2:4]
				data,sw = self.send_apdu_raw(pdu_gr)

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

		if sw == '9000' and sw_match(rv[1], '91xx'):
			# proactive sim as per TS 102 221 Setion 7.4.2
			rv = self.send_apdu_checksw('80120000' + rv[1][2:], sw)
			print("FETCH: %s", rv[0])
		if not sw_match(rv[1], sw):
			raise SwMatchError(rv[1], sw.lower(), self.sw_interpreter)
		return rv

	def send_apdu_constr(self, cla, ins, p1, p2, cmd_constr, cmd_data, resp_constr):
		"""Build and sends an APDU using a 'construct' definition; parses response.

		Args:
			cla : string (in hex) ISO 7816 class byte
			ins : string (in hex) ISO 7816 instruction byte
			p1 : string (in hex) ISO 7116 Parameter 1 byte
			p2 : string (in hex) ISO 7116 Parameter 2 byte
			cmd_cosntr : defining how to generate binary APDU command data
			cmd_data : command data passed to cmd_constr
			resp_cosntr : defining how to decode  binary APDU response data
		Returns:
			Tuple of (decoded_data, sw)
		"""
		cmd = cmd_constr.build(cmd_data) if cmd_data else ''
		p3 = i2h([len(cmd)])
		pdu = ''.join([cla, ins, p1, p2, p3, b2h(cmd)])
		(data, sw) = self.send_apdu(pdu)
		if data:
			# filter the resulting dict to avoid '_io' members inside
			rsp = filter_dict(resp_constr.parse(h2b(data)))
		else:
			rsp = None
		return (rsp, sw)

	def send_apdu_constr_checksw(self, cla, ins, p1, p2, cmd_constr, cmd_data, resp_constr,
								 sw_exp="9000"):
		"""Build and sends an APDU using a 'construct' definition; parses response.

		Args:
			cla : string (in hex) ISO 7816 class byte
			ins : string (in hex) ISO 7816 instruction byte
			p1 : string (in hex) ISO 7116 Parameter 1 byte
			p2 : string (in hex) ISO 7116 Parameter 2 byte
			cmd_cosntr : defining how to generate binary APDU command data
			cmd_data : command data passed to cmd_constr
			resp_cosntr : defining how to decode  binary APDU response data
			exp_sw : string (in hex) of status word (ex. "9000")
		Returns:
			Tuple of (decoded_data, sw)
		"""
		(rsp, sw) = self.send_apdu_constr(cla, ins, p1, p2, cmd_constr, cmd_data, resp_constr)
		if not sw_match(sw, sw_exp):
			raise SwMatchError(sw, sw_exp.lower(), self.sw_interpreter)
		return (rsp, sw)

def argparse_add_reader_args(arg_parser):
	"""Add all reader related arguments to the given argparse.Argumentparser instance."""
	serial_group = arg_parser.add_argument_group('Serial Reader')
	serial_group.add_argument('-d', '--device', metavar='DEV', default='/dev/ttyUSB0',
							  help='Serial Device for SIM access')
	serial_group.add_argument('-b', '--baud', dest='baudrate', type=int, metavar='BAUD', default=9600,
							  help='Baud rate used for SIM access')

	pcsc_group = arg_parser.add_argument_group('PC/SC Reader')
	pcsc_group.add_argument('-p', '--pcsc-device', type=int, dest='pcsc_dev', metavar='PCSC', default=None,
							help='PC/SC reader number to use for SIM access')

	modem_group = arg_parser.add_argument_group('AT Command Modem Reader')
	modem_group.add_argument('--modem-device', dest='modem_dev', metavar='DEV', default=None,
							 help='Serial port of modem for Generic SIM Access (3GPP TS 27.007)')
	modem_group.add_argument('--modem-baud', type=int, metavar='BAUD', default=115200,
							 help='Baud rate used for modem port')

	osmobb_group = arg_parser.add_argument_group('OsmocomBB Reader')
	osmobb_group.add_argument('--osmocon', dest='osmocon_sock', metavar='PATH', default=None,
							  help='Socket path for Calypso (e.g. Motorola C1XX) based reader (via OsmocomBB)')

	return arg_parser

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
		if str(e):
			print("Card reader initialization failed with exception:\n" + str(e))
		else:
			print("Card reader initialization failed with an exception of type:\n" + str(type(e)))
		return None
