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
     """
     Initialize the transport.

     Args:
         self: (todo): write your description
         transport: (str): write your description
     """
		self._tp = transport
		self._cla_byte = "a0"
		self.sel_ctrl = "0000"

	# Extract a single FCP item from TLV
	def __parse_fcp(self, fcp):
     """
     Parse a tlv

     Args:
         self: (todo): write your description
         fcp: (str): write your description
     """
		# see also: ETSI TS 102 221, chapter 11.1.1.3.1 Response for MF,
		# DF or ADF
		from pytlv.TLV import TLV
		tlvparser = TLV(['82', '83', '84', 'a5', '8a', '8b', '8c', '80', 'ab', 'c6', '81', '88'])

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
		if len(fcp[4:]) // 2 == exp_tlv_len:
			skip = 4
		else:
			exp_tlv_len = int(fcp[2:6], 16)
			if len(fcp[4:]) // 2 == exp_tlv_len:
				skip = 6

		# Skip FCP tag and length
		tlv = fcp[skip:]
		return tlvparser.parse(tlv)

	# Tell the length of a record by the card response
	# USIMs respond with an FCP template, which is different
	# from what SIMs responds. See also:
	# USIM: ETSI TS 102 221, chapter 11.1.1.3 Response Data
	# SIM: GSM 11.11, chapter 9.2.1 SELECT
	def __record_len(self, r):
     """
     Return the length of the file.

     Args:
         self: (todo): write your description
         r: (array): write your description
     """
		if self.sel_ctrl == "0004":
			tlv_parsed = self.__parse_fcp(r[-1])
			file_descriptor = tlv_parsed['82']
			# See also ETSI TS 102 221, chapter 11.1.1.4.3 File Descriptor
			return int(file_descriptor[4:8], 16)
		else:
			return int(r[-1][28:30], 16)

	# Tell the length of a binary file. See also comment
	# above.
	def __len(self, r):
     """
     Returns the number of bytes

     Args:
         self: (todo): write your description
         r: (todo): write your description
     """
		if self.sel_ctrl == "0004":
			tlv_parsed = self.__parse_fcp(r[-1])
			return int(tlv_parsed['80'], 16)
		else:
			return int(r[-1][4:8], 16)

	def get_atr(self):
     """
     Returns the atr : atr : rd )

     Args:
         self: (todo): write your description
     """
		return self._tp.get_atr()

	@property
	def cla_byte(self):
     """
     : return : class : byte.

     Args:
         self: (todo): write your description
     """
		return self._cla_byte
	@cla_byte.setter
	def cla_byte(self, value):
     """
     The byte of byte.

     Args:
         self: (todo): write your description
         value: (todo): write your description
     """
		self._cla_byte = value

	@property
	def sel_ctrl(self):
     """
     : class : class : ~doctorctrlctrlctrlctrl instance.

     Args:
         self: (todo): write your description
     """
		return self._sel_ctrl
	@sel_ctrl.setter
	def sel_ctrl(self, value):
     """
     Setter for : param value.

     Args:
         self: (todo): write your description
         value: (todo): write your description
     """
		self._sel_ctrl = value

	def try_select_file(self, dir_list):
     """
     Try to select select command

     Args:
         self: (todo): write your description
         dir_list: (str): write your description
     """
		rv = []
		if type(dir_list) is not list:
			dir_list = [dir_list]
		for i in dir_list:
			data, sw = self._tp.send_apdu(self.cla_byte + "a4" + self.sel_ctrl + "02" + i)
			rv.append((data, sw))
			if sw != '9000':
				return rv
		return rv

	def select_file(self, dir_list):
     """
     Select file list of dir_list.

     Args:
         self: (todo): write your description
         dir_list: (str): write your description
     """
		rv = []
		if type(dir_list) is not list:
			dir_list = [dir_list]
		for i in dir_list:
			data, sw = self._tp.send_apdu_checksw(self.cla_byte + "a4" + self.sel_ctrl + "02" + i)
			rv.append(data)
		return rv

	def select_adf(self, aid):
     """
     Select an adf.

     Args:
         self: (todo): write your description
         aid: (int): write your description
     """
		aidlen = ("0" + format(len(aid) // 2, 'x'))[-2:]
		return self._tp.send_apdu_checksw(self.cla_byte + "a4" + "0404" + aidlen + aid)

	def read_binary(self, ef, length=None, offset=0):
     """
     Read binary data.

     Args:
         self: (todo): write your description
         ef: (todo): write your description
         length: (int): write your description
         offset: (int): write your description
     """
		r = self.select_file(ef)
		if len(r[-1]) == 0:
			return (None, None)
		if length is None:
			length = self.__len(r) - offset
		total_data = ''
		while offset < length:
			chunk_len = min(255, length-offset)
			pdu = self.cla_byte + 'b0%04x%02x' % (offset, chunk_len)
			data,sw = self._tp.send_apdu(pdu)
			if sw == '9000':
				total_data += data
				offset += chunk_len
			else:
				raise ValueError('Failed to read (offset %d)' % (offset))
		return total_data, sw

	def update_binary(self, ef, data, offset=0, verify=False):
     """
     Update binary data.

     Args:
         self: (todo): write your description
         ef: (todo): write your description
         data: (todo): write your description
         offset: (int): write your description
         verify: (str): write your description
     """
		self.select_file(ef)
		pdu = self.cla_byte + 'd6%04x%02x' % (offset, len(data) // 2) + data
		res = self._tp.send_apdu_checksw(pdu)
		if verify:
			self.verify_binary(ef, data, offset)
		return res

	def verify_binary(self, ef, data, offset=0):
     """
     Verify binary data.

     Args:
         self: (todo): write your description
         ef: (str): write your description
         data: (str): write your description
         offset: (int): write your description
     """
		res = self.read_binary(ef, len(data) // 2, offset)
		if res[0].lower() != data.lower():
			raise ValueError('Binary verification failed (expected %s, got %s)' % (data.lower(), res[0].lower()))

	def read_record(self, ef, rec_no):
     """
     Read a record.

     Args:
         self: (todo): write your description
         ef: (str): write your description
         rec_no: (str): write your description
     """
		r = self.select_file(ef)
		rec_length = self.__record_len(r)
		pdu = self.cla_byte + 'b2%02x04%02x' % (rec_no, rec_length)
		return self._tp.send_apdu(pdu)

	def update_record(self, ef, rec_no, data, force_len=False, verify=False):
     """
     Update a record to the given record.

     Args:
         self: (todo): write your description
         ef: (array): write your description
         rec_no: (array): write your description
         data: (array): write your description
         force_len: (bool): write your description
         verify: (todo): write your description
     """
		r = self.select_file(ef)
		if not force_len:
			rec_length = self.__record_len(r)
			if (len(data) // 2 != rec_length):
				raise ValueError('Invalid data length (expected %d, got %d)' % (rec_length, len(data) // 2))
		else:
			rec_length = len(data) // 2
		pdu = (self.cla_byte + 'dc%02x04%02x' % (rec_no, rec_length)) + data
		res = self._tp.send_apdu_checksw(pdu)
		if verify:
			self.verify_record(ef, rec_no, data)
		return res

	def verify_record(self, ef, rec_no, data):
     """
     Verify a record

     Args:
         self: (todo): write your description
         ef: (str): write your description
         rec_no: (str): write your description
         data: (str): write your description
     """
		res = self.read_record(ef, rec_no)
		if res[0].lower() != data.lower():
			raise ValueError('Record verification failed (expected %s, got %s)' % (data.lower(), res[0].lower()))

	def record_size(self, ef):
     """
     Returns the size of the record.

     Args:
         self: (todo): write your description
         ef: (array): write your description
     """
		r = self.select_file(ef)
		return self.__record_len(r)

	def record_count(self, ef):
     """
     Return the number of records in this record.

     Args:
         self: (todo): write your description
         ef: (todo): write your description
     """
		r = self.select_file(ef)
		return self.__len(r) // self.__record_len(r)

	def binary_size(self, ef):
     """
     Return the size of the binary file.

     Args:
         self: (todo): write your description
         ef: (int): write your description
     """
		r = self.select_file(ef)
		return self.__len(r)

	def run_gsm(self, rand):
     """
     Run gsm command.

     Args:
         self: (todo): write your description
         rand: (todo): write your description
     """
		if len(rand) != 32:
			raise ValueError('Invalid rand')
		self.select_file(['3f00', '7f20'])
		return self._tp.send_apdu(self.cla_byte + '88000010' + rand)

	def reset_card(self):
     """
     Reset the card card.

     Args:
         self: (todo): write your description
     """
		return self._tp.reset_card()

	def verify_chv(self, chv_no, code):
     """
     Verify the chv_nov_now_chv_no

     Args:
         self: (todo): write your description
         chv_no: (todo): write your description
         code: (str): write your description
     """
		fc = rpad(b2h(code), 16)
		return self._tp.send_apdu_checksw(self.cla_byte + '2000' + ('%02X' % chv_no) + '08' + fc)
