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
		self._cla_byte = "a0"
		self.sel_ctrl = "0000"

	# Get file size from FCP
	def __get_len_from_tlv(self, fcp):
		# see also: ETSI TS 102 221, chapter 11.1.1.3.1 Response for MF,
		# DF or ADF
                from pytlv.TLV import TLV
		tlvparser = TLV(['82', '83', '84', 'A5', '8a', '8b', '8c', '80', 'ab', 'c6', '81', '88'])

		# pytlv is case sensitive!
		fcp = fcp.lower()

		if fcp[0:2] != '62':
			raise ValueError('Tag of the FCP template does not match, expected 62 but got %s'%fcp[0:2])

		# Unfortunately the spec is not very clear if the FCP length is
		# coded as one or two byte vale, so we have to try it out by
		# checking if the length of the remaining TLV string matches
		# what we get in the length field.
		# See also ETSI TS 102 221, chapter 11.1.1.3.0 Base coding.
		exp_tlv_len = int(fcp[2:4], 16)
		if len(fcp[4:])/2 == exp_tlv_len:
			skip = 4
		else:
			exp_tlv_len = int(fcp[2:6], 16)
			if len(fcp[4:])/2 == exp_tlv_len:
				skip = 6

		# Skip FCP tag and length
		tlv = fcp[skip:]
		tlv_parsed = tlvparser.parse(tlv)

		return int(tlv_parsed['80'], 16)

        # Tell the length of a record by the card response
        # USIMs respond with an FCP template, which is different
        # from what SIMs responds. See also:
        # USIM: ETSI TS 102 221, chapter 11.1.1.3 Response Data
        # SIM: GSM 11.11, chapter 9.2.1 SELECT
	def __record_len(self, r):
                if self.sel_ctrl == "0004":
                        return self.__get_len_from_tlv(r[-1])
                else:
                        return int(r[-1][28:30], 16)

        # Tell the length of a binary file. See also comment
        # above.
	def __len(self, r):
                if self.sel_ctrl == "0004":
                        return self.__get_len_from_tlv(r[-1])
                else:
                        return int(r[-1][4:8], 16)

	def get_atr(self):
		return self._tp.get_atr()

	@property
	def cla_byte(self):
		return self._cla_byte
	@cla_byte.setter
	def cla_byte(self, value):
		self._cla_byte = value

	@property
	def sel_ctrl(self):
		return self._sel_ctrl
	@sel_ctrl.setter
	def sel_ctrl(self, value):
		self._sel_ctrl = value

	def select_file(self, dir_list):
		rv = []
		for i in dir_list:
			data, sw = self._tp.send_apdu_checksw(self.cla_byte + "a4" + self.sel_ctrl + "02" + i)
			rv.append(data)
		return rv

	def read_binary(self, ef, length=None, offset=0):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		if length is None:
			length = self.__len(r) - offset
		pdu = self.cla_byte + 'b0%04x%02x' % (offset, (min(256, length) & 0xff))
		return self._tp.send_apdu(pdu)

	def update_binary(self, ef, data, offset=0):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		self.select_file(ef)
		pdu = self.cla_byte + 'd6%04x%02x' % (offset, len(data)/2) + data
		return self._tp.send_apdu_checksw(pdu)

	def read_record(self, ef, rec_no):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		rec_length = self.__record_len(r)
		pdu = self.cla_byte + 'b2%02x04%02x' % (rec_no, rec_length)
		return self._tp.send_apdu(pdu)

	def update_record(self, ef, rec_no, data, force_len=False):
		if not hasattr(type(ef), '__iter__'):
			ef = [ef]
		r = self.select_file(ef)
		if not force_len:
			rec_length = self.__record_len(r)
			if (len(data)/2 != rec_length):
				raise ValueError('Invalid data length (expected %d, got %d)' % (rec_length, len(data)/2))
		else:
			rec_length = len(data)/2
		pdu = (self.cla_byte + 'dc%02x04%02x' % (rec_no, rec_length)) + data
		return self._tp.send_apdu_checksw(pdu)

	def record_size(self, ef):
		r = self.select_file(ef)
		return self.__record_len(r)

	def record_count(self, ef):
		r = self.select_file(ef)
		return self.__len(r) // self.__record_len(r)

	def run_gsm(self, rand):
		if len(rand) != 32:
			raise ValueError('Invalid rand')
		self.select_file(['3f00', '7f20'])
		return self._tp.send_apdu(self.cla_byte + '88000010' + rand)

	def reset_card(self):
		return self._tp.reset_card()

	def verify_chv(self, chv_no, code):
		fc = rpad(b2h(code), 16)
		return self._tp.send_apdu_checksw(self.cla_byte + '2000' + ('%02X' % chv_no) + '08' + fc)
