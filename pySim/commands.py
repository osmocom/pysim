# -*- coding: utf-8 -*-

""" pySim: SIM Card commands according to ISO 7816-4 and TS 11.11
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010-2021  Harald Welte <laforge@gnumonks.org>
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

from construct import *
from pySim.construct import LV
from pySim.utils import rpad, b2h, h2b, sw_match, bertlv_encode_len, Hexstr, h2i
from pySim.exceptions import SwMatchError

class SimCardCommands(object):
	def __init__(self, transport):
		self._tp = transport
		self.cla_byte = "a0"
		self.sel_ctrl = "0000"

	# Extract a single FCP item from TLV
	def __parse_fcp(self, fcp):
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
	def __record_len(self, r) -> int:
		if self.sel_ctrl == "0004":
			tlv_parsed = self.__parse_fcp(r[-1])
			file_descriptor = tlv_parsed['82']
			# See also ETSI TS 102 221, chapter 11.1.1.4.3 File Descriptor
			return int(file_descriptor[4:8], 16)
		else:
			return int(r[-1][28:30], 16)

	# Tell the length of a binary file. See also comment
	# above.
	def __len(self, r) -> int:
		if self.sel_ctrl == "0004":
			tlv_parsed = self.__parse_fcp(r[-1])
			return int(tlv_parsed['80'], 16)
		else:
			return int(r[-1][4:8], 16)

	def get_atr(self) -> str:
		"""Return the ATR of the currently inserted card."""
		return self._tp.get_atr()

	def try_select_path(self, dir_list):
		""" Try to select a specified path given as list of hex-string FIDs"""
		rv = []
		if type(dir_list) is not list:
			dir_list = [dir_list]
		for i in dir_list:
			data, sw = self._tp.send_apdu(self.cla_byte + "a4" + self.sel_ctrl + "02" + i)
			rv.append((data, sw))
			if sw != '9000':
				return rv
		return rv

	def select_path(self, dir_list):
		"""Execute SELECT for an entire list/path of FIDs.

		Args:
			dir_list: list of FIDs representing the path to select

		Returns:
			list of return values (FCP in hex encoding) for each element of the path
		"""
		rv = []
		if type(dir_list) is not list:
			dir_list = [dir_list]
		for i in dir_list:
			data, sw = self.select_file(i)
			rv.append(data)
		return rv

	def select_file(self, fid:str):
		"""Execute SELECT a given file by FID."""
		return self._tp.send_apdu_checksw(self.cla_byte + "a4" + self.sel_ctrl + "02" + fid)

	def select_adf(self, aid:str):
		"""Execute SELECT a given Applicaiton ADF."""
		aidlen = ("0" + format(len(aid) // 2, 'x'))[-2:]
		return self._tp.send_apdu_checksw(self.cla_byte + "a4" + "0404" + aidlen + aid)

	def read_binary(self, ef, length:int=None, offset:int=0):
		"""Execute READD BINARY.

		Args:
			ef : string or list of strings indicating name or path of transparent EF
			length : number of bytes to read
			offset : byte offset in file from which to start reading
		"""
		r = self.select_path(ef)
		if len(r[-1]) == 0:
			return (None, None)
		if length is None:
			length = self.__len(r) - offset
		total_data = ''
		chunk_offset = 0
		while chunk_offset < length:
			chunk_len = min(255, length-chunk_offset)
			pdu = self.cla_byte + 'b0%04x%02x' % (offset + chunk_offset, chunk_len)
			data,sw = self._tp.send_apdu(pdu)
			if sw == '9000':
				total_data += data
				chunk_offset += chunk_len
			else:
				raise ValueError('Failed to read (offset %d)' % (offset))
		return total_data, sw

	def update_binary(self, ef, data:str, offset:int=0, verify:bool=False, conserve:bool=False):
		"""Execute UPDATE BINARY.

		Args:
			ef : string or list of strings indicating name or path of transparent EF
			data : hex string of data to be written
			offset : byte offset in file from which to start writing
			verify : Whether or not to verify data after write
		"""
		data_length = len(data) // 2

		# Save write cycles by reading+comparing before write
		if conserve:
			data_current, sw = self.read_binary(ef, data_length, offset)
			if data_current == data:
				return None, sw

		self.select_path(ef)
		total_data = ''
		total_sw = "9000"
		chunk_offset = 0
		while chunk_offset < data_length:
			chunk_len = min(255, data_length - chunk_offset)
			# chunk_offset is bytes, but data slicing is hex chars, so we need to multiply by 2
			pdu = self.cla_byte + 'd6%04x%02x' % (offset + chunk_offset, chunk_len) + data[chunk_offset*2 : (chunk_offset+chunk_len)*2]
			chunk_data, chunk_sw = self._tp.send_apdu(pdu)
			if chunk_sw == total_sw:
				total_data += chunk_data
				chunk_offset += chunk_len
			else:
				total_sw = chunk_sw
				raise ValueError('Failed to write chunk (chunk_offset %d, chunk_len %d)' % (chunk_offset, chunk_len))
		if verify:
			self.verify_binary(ef, data, offset)
		return total_data, total_sw

	def verify_binary(self, ef, data:str, offset:int=0):
		"""Verify contents of transparent EF.

		Args:
			ef : string or list of strings indicating name or path of transparent EF
			data : hex string of expected data
			offset : byte offset in file from which to start verifying
		"""
		res = self.read_binary(ef, len(data) // 2, offset)
		if res[0].lower() != data.lower():
			raise ValueError('Binary verification failed (expected %s, got %s)' % (data.lower(), res[0].lower()))

	def read_record(self, ef, rec_no:int):
		"""Execute READ RECORD.

		Args:
			ef : string or list of strings indicating name or path of linear fixed EF
			rec_no : record number to read
		"""
		r = self.select_path(ef)
		rec_length = self.__record_len(r)
		pdu = self.cla_byte + 'b2%02x04%02x' % (rec_no, rec_length)
		return self._tp.send_apdu(pdu)

	def update_record(self, ef, rec_no:int, data:str, force_len:bool=False, verify:bool=False,
					  conserve:bool=False):
		res = self.select_path(ef)

		if force_len:
			# enforce the record length by the actual length of the given data input
			rec_length = len(data) // 2
		else:
			# determine the record length from the select response of the file and pad
			# the input data with 0xFF if necessary. In cases where the input data
			# exceed we throw an exception.
			rec_length = self.__record_len(res)
			if (len(data) // 2 > rec_length):
				raise ValueError('Data length exceeds record length (expected max %d, got %d)' % (rec_length, len(data) // 2))
			elif (len(data) // 2 < rec_length):
				data = rpad(data, rec_length * 2)

		# Save write cycles by reading+comparing before write
		if conserve:
			data_current, sw = self.read_record(ef, rec_no)
			data_current = data_current[0:rec_length*2]
			if data_current == data:
				return None, sw

		pdu = (self.cla_byte + 'dc%02x04%02x' % (rec_no, rec_length)) + data
		res = self._tp.send_apdu_checksw(pdu)
		if verify:
			self.verify_record(ef, rec_no, data)
		return res

	def verify_record(self, ef, rec_no:int, data:str):
		res = self.read_record(ef, rec_no)
		if res[0].lower() != data.lower():
			raise ValueError('Record verification failed (expected %s, got %s)' % (data.lower(), res[0].lower()))

	def record_size(self, ef):
		"""Determine the record size of given file.

		Args:
			ef : string or list of strings indicating name or path of linear fixed EF
		"""
		r = self.select_path(ef)
		return self.__record_len(r)

	def record_count(self, ef):
		"""Determine the number of records in given file.

		Args:
			ef : string or list of strings indicating name or path of linear fixed EF
		"""
		r = self.select_path(ef)
		return self.__len(r) // self.__record_len(r)

	def binary_size(self, ef):
		"""Determine the size of given transparent file.

		Args:
			ef : string or list of strings indicating name or path of transparent EF
		"""
		r = self.select_path(ef)
		return self.__len(r)

	# TS 102 221 Section 11.3.1 low-level helper
	def _retrieve_data(self, tag:int, first:bool=True):
		if first:
			pdu = '80cb008001%02x' % (tag)
		else:
			pdu = '80cb000000'
		return self._tp.send_apdu_checksw(pdu)

	# TS 102 221 Section 11.3.1
	def retrieve_data(self, ef, tag:int):
		"""Execute RETRIEVE DATA.

		Args
			ef : string or list of strings indicating name or path of transparent EF
			tag : BER-TLV Tag of value to be retrieved
		"""
		r = self.select_path(ef)
		if len(r[-1]) == 0:
			return (None, None)
		total_data = ''
		# retrieve first block
		data, sw = self._retrieve_data(tag, first=True)
		total_data += data
		while sw == '62f1' or sw == '62f2':
			data, sw = self._retrieve_data(tag, first=False)
			total_data += data
		return total_data, sw

	# TS 102 221 Section 11.3.2 low-level helper
	def _set_data(self, data:str, first:bool=True):
		if first:
			p1 = 0x80
		else:
			p1 = 0x00
		if isinstance(data, bytes) or isinstance(data, bytearray):
			data = b2h(data)
		pdu = '80db00%02x%02x%s' % (p1, len(data)//2, data)
		return self._tp.send_apdu_checksw(pdu)

	def set_data(self, ef, tag:int, value:str, verify:bool=False, conserve:bool=False):
		"""Execute SET DATA.

		Args
			ef : string or list of strings indicating name or path of transparent EF
			tag : BER-TLV Tag of value to be stored
			value : BER-TLV value to be stored
		"""
		r = self.select_path(ef)
		if len(r[-1]) == 0:
			return (None, None)

		# in case of deleting the data, we only have 'tag' but no 'value'
		if not value:
			return self._set_data('%02x' % tag, first=True)

		# FIXME: proper BER-TLV encode
		tl = '%02x%s' % (tag, b2h(bertlv_encode_len(len(value)//2)))
		tlv = tl + value
		tlv_bin = h2b(tlv)

		first = True
		total_len = len(tlv_bin)
		remaining = tlv_bin
		while len(remaining) > 0:
			fragment = remaining[:255]
			rdata, sw = self._set_data(fragment, first=first)
			first = False
			remaining = remaining[255:]
		return rdata, sw

	def run_gsm(self, rand:str):
		"""Execute RUN GSM ALGORITHM."""
		if len(rand) != 32:
			raise ValueError('Invalid rand')
		self.select_path(['3f00', '7f20'])
		return self._tp.send_apdu(self.cla_byte + '88000010' + rand)

	def authenticate(self, rand:str, autn:str, context='3g'):
		"""Execute AUTHENTICATE (USIM/ISIM)."""
		# 3GPP TS 31.102 Section 7.1.2.1
		AuthCmd3G = Struct('rand'/LV, 'autn'/Optional(LV))
		AuthResp3GSyncFail = Struct(Const(b'\xDC'), 'auts'/LV)
		AuthResp3GSuccess = Struct(Const(b'\xDB'), 'res'/LV, 'ck'/LV, 'ik'/LV, 'kc'/Optional(LV))
		AuthResp3G = Select(AuthResp3GSyncFail, AuthResp3GSuccess)
		# build parameters
		cmd_data = {'rand': rand, 'autn': autn}
		if context == '3g':
			p2 = '81'
		elif context == 'gsm':
			p2 = '80'
		(data, sw) = self._tp.send_apdu_constr_checksw(self.cla_byte, '88', '00', p2, AuthCmd3G, cmd_data, AuthResp3G)
		if 'auts' in data:
			ret = {'synchronisation_failure': data}
		else:
			ret = {'successful_3g_authentication': data}
		return (ret, sw)

	def status(self):
		"""Execute a STATUS command as per TS 102 221 Section 11.1.2."""
		return self._tp.send_apdu_checksw('80F20000ff')

	def deactivate_file(self):
		"""Execute DECATIVATE FILE command as per TS 102 221 Section 11.1.14."""
		return self._tp.send_apdu_constr_checksw(self.cla_byte, '04', '00', '00', None, None, None)

	def activate_file(self, fid):
		"""Execute ACTIVATE FILE command as per TS 102 221 Section 11.1.15."""
		return self._tp.send_apdu_checksw(self.cla_byte + '44000002' + fid)

	def manage_channel(self, mode='open', lchan_nr=0):
		"""Execute MANAGE CHANNEL command as per TS 102 221 Section 11.1.17."""
		if mode == 'close':
			p1 = 0x80
		else:
			p1 = 0x00
		pdu = self.cla_byte + '70%02x%02x00' % (p1, lchan_nr)
		return self._tp.send_apdu_checksw(pdu)

	def reset_card(self):
		"""Physically reset the card"""
		return self._tp.reset_card()

	def _chv_process_sw(self, op_name, chv_no, pin_code, sw):
		if sw_match(sw, '63cx'):
			raise RuntimeError('Failed to %s chv_no 0x%02X with code 0x%s, %i tries left.' %
							   (op_name, chv_no, b2h(pin_code).upper(), int(sw[3])))
		elif (sw != '9000'):
			raise SwMatchError(sw, '9000')

	def verify_chv(self, chv_no:int, code:str):
		"""Verify a given CHV (Card Holder Verification == PIN)"""
		fc = rpad(b2h(code), 16)
		data, sw = self._tp.send_apdu(self.cla_byte + '2000' + ('%02X' % chv_no) + '08' + fc)
		self._chv_process_sw('verify', chv_no, code, sw)
		return (data, sw)

	def unblock_chv(self, chv_no:int, puk_code:str, pin_code:str):
		"""Unblock a given CHV (Card Holder Verification == PIN)"""
		fc = rpad(b2h(puk_code), 16) + rpad(b2h(pin_code), 16)
		data, sw = self._tp.send_apdu(self.cla_byte + '2C00' + ('%02X' % chv_no) + '10' + fc)
		self._chv_process_sw('unblock', chv_no, pin_code, sw)
		return (data, sw)

	def change_chv(self, chv_no:int, pin_code:str, new_pin_code:str):
		"""Change a given CHV (Card Holder Verification == PIN)"""
		fc = rpad(b2h(pin_code), 16) + rpad(b2h(new_pin_code), 16)
		data, sw = self._tp.send_apdu(self.cla_byte + '2400' + ('%02X' % chv_no) + '10' + fc)
		self._chv_process_sw('change', chv_no, pin_code, sw)
		return (data, sw)

	def disable_chv(self, chv_no:int, pin_code:str):
		"""Disable a given CHV (Card Holder Verification == PIN)"""
		fc = rpad(b2h(pin_code), 16)
		data, sw = self._tp.send_apdu(self.cla_byte + '2600' + ('%02X' % chv_no) + '08' + fc)
		self._chv_process_sw('disable', chv_no, pin_code, sw)
		return (data, sw)

	def enable_chv(self, chv_no:int, pin_code:str):
		"""Enable a given CHV (Card Holder Verification == PIN)"""
		fc = rpad(b2h(pin_code), 16)
		data, sw = self._tp.send_apdu(self.cla_byte + '2800' + ('%02X' % chv_no) + '08' + fc)
		self._chv_process_sw('enable', chv_no, pin_code, sw)
		return (data, sw)

	def envelope(self, payload:str):
		"""Send one ENVELOPE command to the SIM"""
		return self._tp.send_apdu_checksw('80c20000%02x%s' % (len(payload)//2, payload))

	def terminal_profile(self, payload:str):
		"""Send TERMINAL PROFILE to card"""
		data_length = len(payload) // 2
		data, sw = self._tp.send_apdu(('80100000%02x' % data_length) + payload)
		return (data, sw)

	# ETSI TS 102 221 11.1.22
	def suspend_uicc(self, min_len_secs:int=60, max_len_secs:int=43200):
		"""Send SUSPEND UICC to the card."""
		def encode_duration(secs:int) -> Hexstr:
			if secs >= 10*24*60*60:
				return '04%02x' % (secs // (10*24*60*60))
			elif secs >= 24*60*60:
				return '03%02x' % (secs // (24*60*60))
			elif secs >= 60*60:
				return '02%02x' % (secs // (60*60))
			elif secs >= 60:
				return '01%02x' % (secs // 60)
			else:
				return '00%02x' % secs
		def decode_duration(enc:Hexstr) -> int:
			time_unit = enc[:2]
			length = h2i(enc[2:4])
			if time_unit == '04':
				return length * 10*24*60*60
			elif time_unit == '03':
				return length * 24*60*60
			elif time_unit == '02':
				return length * 60*60
			elif time_unit == '01':
				return length * 60
			elif time_unit == '00':
				return length
			else:
				raise ValueError('Time unit must be 0x00..0x04')
		min_dur_enc = encode_duration(min_len_secs)
		max_dur_enc = encode_duration(max_len_secs)
		data, sw = self._tp.send_apdu_checksw('8076000004' + min_dur_enc + max_dur_enc)
		negotiated_duration_secs = decode_duration(data[:4])
		resume_token = data[4:]
		return (negotiated_duration_secs, resume_token, sw)
