#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pySim: Transport Link for 3GPP TS 27.007 compliant modems
"""

# Copyright (C) 2020 Vadim Yanitskiy <axilirator@gmail.com>
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

from __future__ import absolute_import

import logging as log
import serial
import time
import re

from pySim.transport import LinkBase
from pySim.exceptions import *

# HACK: if somebody needs to debug this thing
# log.root.setLevel(log.DEBUG)

class ModemATCommandLink(LinkBase):
	def __init__(self, device='/dev/ttyUSB0', baudrate=115200):
		self._sl = serial.Serial(device, baudrate, timeout=5)
		self._device = device
		self._atr = None

		# Trigger initial reset
		self.reset_card()

	def __del__(self):
		self._sl.close()

	def send_at_cmd(self, cmd):
		# Convert from string to bytes, if needed
		bcmd = cmd if type(cmd) is bytes else cmd.encode()
		bcmd += b'\r'

		# Send command to the modem
		log.debug('Sending AT command: %s' % cmd)
		try:
			wlen = self._sl.write(bcmd)
			assert(wlen == len(bcmd))
		except:
			raise ReaderError('Failed to send AT command: %s' % cmd)

		# Give the modem some time...
		time.sleep(0.3)

		# Read the response
		try:
			# Skip characters sent back
			self._sl.read(wlen)
			# Read the rest
			rsp = self._sl.read_all()

			# Strip '\r\n'
			rsp = rsp.strip()
			# Split into a list
			rsp = rsp.split(b'\r\n\r\n')
		except:
			raise ReaderError('Failed parse response to AT command: %s' % cmd)

		log.debug('Got response from modem: %s' % rsp)
		return rsp

	def reset_card(self):
		# Make sure that we can talk to the modem
		if self.send_at_cmd('AT') != [b'OK']:
			raise ReaderError('Failed to connect to modem')

		# Reset the modem, just to be sure
		if self.send_at_cmd('ATZ') != [b'OK']:
			raise ReaderError('Failed to reset the modem')

		# Make sure that generic SIM access is supported
		if self.send_at_cmd('AT+CSIM=?') != [b'OK']:
			raise ReaderError('The modem does not seem to support SIM access')

		log.info('Modem at \'%s\' is ready!' % self._device)

	def connect(self):
		pass # Nothing to do really ...

	def disconnect(self):
		pass # Nothing to do really ...

	def wait_for_card(self, timeout=None, newcardonly=False):
		pass # Nothing to do really ...

	def send_apdu_raw(self, pdu):
		# Prepare the command as described in 8.17
		cmd = 'AT+CSIM=%d,\"%s\"' % (len(pdu), pdu)

		# Send AT+CSIM command to the modem
		# TODO: also handle +CME ERROR: <err>
		rsp = self.send_at_cmd(cmd)
		if len(rsp) != 2 or rsp[-1] != b'OK':
			raise ReaderError('APDU transfer failed: %s' % str(rsp))
		rsp = rsp[0] # Get rid of b'OK'

		# Make sure that the response has format: b'+CSIM: %d,\"%s\"'
		try:
			result = re.match(b'\+CSIM: (\d+),\"([0-9A-F]+)\"', rsp)
			(rsp_pdu_len, rsp_pdu) = result.groups()
		except:
			raise ReaderError('Failed to parse response from modem: %s' % rsp)

		# TODO: make sure we have at least SW
		data = rsp_pdu[:-4].decode()
		sw   = rsp_pdu[-4:].decode()
		return data, sw
