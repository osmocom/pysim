#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pySim: Card programmation logic
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2011  Harald Welte <laforge@gnumonks.org>
# Copyright (C) 2017 Alexander.Chemeris <Alexander.Chemeris@gmail.com>
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

from pySim.ts_51_011 import EF, DF
from pySim.ts_31_102 import EF_USIM_ADF_map
from pySim.utils import *
from smartcard.util import toBytes

class Card(object):

	def __init__(self, scc):
     """
     Initialize the device.

     Args:
         self: (todo): write your description
         scc: (str): write your description
     """
		self._scc = scc
		self._adm_chv_num = 4
		self._aids = []

	def reset(self):
     """
     Reset the card.

     Args:
         self: (todo): write your description
     """
		self._scc.reset_card()

	def erase(self):
     """
     Erase the current session.

     Args:
         self: (todo): write your description
     """
		print("warning: erasing is not supported for specified card type!")
		return

	def file_exists(self, fid):
     """
     Check if a file exists

     Args:
         self: (todo): write your description
         fid: (str): write your description
     """
		res_arr = self._scc.try_select_file(fid)
		for res in res_arr:
			if res[1] != '9000':
				return False
		return True

	def verify_adm(self, key):
		'''
		Authenticate with ADM key
		'''
		(res, sw) = self._scc.verify_chv(self._adm_chv_num, key)
		return sw

	def read_iccid(self):
     """
     Read binary id from the binary.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF['ICCID'])
		if sw == '9000':
			return (dec_iccid(res), sw)
		else:
			return (None, sw)

	def read_imsi(self):
     """
     Reads the image as a binary.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF['IMSI'])
		if sw == '9000':
			return (dec_imsi(res), sw)
		else:
			return (None, sw)

	def update_imsi(self, imsi):
     """
     Update the dimensions of the image.

     Args:
         self: (todo): write your description
         imsi: (int): write your description
     """
		data, sw = self._scc.update_binary(EF['IMSI'], enc_imsi(imsi))
		return sw

	def update_acc(self, acc):
     """
     Update acc and returns a list of the accep.

     Args:
         self: (todo): write your description
         acc: (todo): write your description
     """
		data, sw = self._scc.update_binary(EF['ACC'], lpad(acc, 4))
		return sw

	def read_hplmn_act(self):
     """
     Read hplmn - only.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF['HPLMNAcT'])
		if sw == '9000':
			return (format_xplmn_w_act(res), sw)
		else:
			return (None, sw)

	def update_hplmn_act(self, mcc, mnc, access_tech='FFFF'):
		"""
		Update Home PLMN with access technology bit-field

		See Section "10.3.37 EFHPLMNwAcT (HPLMN Selector with Access Technology)"
		in ETSI TS 151 011 for the details of the access_tech field coding.
		Some common values:
		access_tech = '0080' # Only GSM is selected
		access_tech = 'FFFF' # All technologues selected, even Reserved for Future Use ones
		"""
		# get size and write EF.HPLMNwAcT
		data = self._scc.read_binary(EF['HPLMNwAcT'], length=None, offset=0)
		size = len(data[0]) // 2
		hplmn = enc_plmn(mcc, mnc)
		content = hplmn + access_tech
		data, sw = self._scc.update_binary(EF['HPLMNwAcT'], content + 'ffffff0000' * (size // 5 - 1))
		return sw

	def read_oplmn_act(self):
     """
     Reads the binary data from the - packed.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF['OPLMNwAcT'])
		if sw == '9000':
			return (format_xplmn_w_act(res), sw)
		else:
			return (None, sw)

	def update_oplmn_act(self, mcc, mnc, access_tech='FFFF'):
		"""
		See note in update_hplmn_act()
		"""
		# get size and write EF.OPLMNwAcT
		data = self._scc.read_binary(EF['OPLMNwAcT'], length=None, offset=0)
		size = len(data[0]) // 2
		hplmn = enc_plmn(mcc, mnc)
		content = hplmn + access_tech
		data, sw = self._scc.update_binary(EF['OPLMNwAcT'], content + 'ffffff0000' * (size // 5 - 1))
		return sw

	def read_plmn_act(self):
     """
     Reads : class : ~ / proc.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF['PLMNwAcT'])
		if sw == '9000':
			return (format_xplmn_w_act(res), sw)
		else:
			return (None, sw)

	def update_plmn_act(self, mcc, mnc, access_tech='FFFF'):
		"""
		See note in update_hplmn_act()
		"""
		# get size and write EF.PLMNwAcT
		data = self._scc.read_binary(EF['PLMNwAcT'], length=None, offset=0)
		size = len(data[0]) // 2
		hplmn = enc_plmn(mcc, mnc)
		content = hplmn + access_tech
		data, sw = self._scc.update_binary(EF['PLMNwAcT'], content + 'ffffff0000' * (size // 5 - 1))
		return sw

	def update_plmnsel(self, mcc, mnc):
     """
     Update plmnselselselsel.

     Args:
         self: (todo): write your description
         mcc: (todo): write your description
         mnc: (todo): write your description
     """
		data = self._scc.read_binary(EF['PLMNsel'], length=None, offset=0)
		size = len(data[0]) // 2
		hplmn = enc_plmn(mcc, mnc)
		data, sw = self._scc.update_binary(EF['PLMNsel'], hplmn + 'ff' * (size-3))
		return sw

	def update_smsp(self, smsp):
     """
     Update an sms record.

     Args:
         self: (todo): write your description
         smsp: (int): write your description
     """
		data, sw = self._scc.update_record(EF['SMSP'], 1, rpad(smsp, 84))
		return sw

	def update_ad(self, mnc):
     """
     Update an adcl

     Args:
         self: (todo): write your description
         mnc: (int): write your description
     """
		#See also: 3GPP TS 31.102, chapter 4.2.18
		mnclen = len(str(mnc))
		if mnclen == 1:
			mnclen = 2
		if mnclen > 3:
			raise RuntimeError('unable to calculate proper mnclen')

		data, sw = self._scc.read_binary(EF['AD'], length=None, offset=0)

		# Reset contents to EF.AD in case the file is uninintalized
		if data.lower() == "ffffffff":
			data = "00000000"

		content = data[0:6] + "%02X" % mnclen
		data, sw = self._scc.update_binary(EF['AD'], content)
		return sw

	def read_spn(self):
     """
     Reads the binary string.

     Args:
         self: (todo): write your description
     """
		(spn, sw) = self._scc.read_binary(EF['SPN'])
		if sw == '9000':
			return (dec_spn(spn), sw)
		else:
			return (None, sw)

	def update_spn(self, name, hplmn_disp=False, oplmn_disp=False):
     """
     Update a spnx image.

     Args:
         self: (todo): write your description
         name: (str): write your description
         hplmn_disp: (int): write your description
         oplmn_disp: (int): write your description
     """
		content = enc_spn(name, hplmn_disp, oplmn_disp)
		data, sw = self._scc.update_binary(EF['SPN'], rpad(content, 32))
		return sw

	def read_binary(self, ef, length=None, offset=0):
     """
     Reads binary data : type assertion.

     Args:
         self: (todo): write your description
         ef: (todo): write your description
         length: (int): write your description
         offset: (int): write your description
     """
		ef_path = ef in EF and EF[ef] or ef
		return self._scc.read_binary(ef_path, length, offset)

	def read_record(self, ef, rec_no):
     """
     Read record.

     Args:
         self: (todo): write your description
         ef: (str): write your description
         rec_no: (str): write your description
     """
		ef_path = ef in EF and EF[ef] or ef
		return self._scc.read_record(ef_path, rec_no)

	def read_gid1(self):
     """
     Read the gid from the binary.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF['GID1'])
		if sw == '9000':
			return (res, sw)
		else:
			return (None, sw)

	def read_msisdn(self):
     """
     Read a record from the swf file.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_record(EF['MSISDN'], 1)
		if sw == '9000':
			return (dec_msisdn(res), sw)
		else:
			return (None, sw)

	# Fetch all the AIDs present on UICC
	def read_aids(self):
     """
     Read restructured record.

     Args:
         self: (todo): write your description
     """
		try:
			# Find out how many records the EF.DIR has
			# and store all the AIDs in the UICC
			rec_cnt = self._scc.record_count(EF['DIR'])
			for i in range(0, rec_cnt):
				rec = self._scc.read_record(EF['DIR'], i + 1)
				if (rec[0][0:2], rec[0][4:6]) == ('61', '4f') and len(rec[0]) > 12 \
				and rec[0][8:8 + int(rec[0][6:8], 16) * 2] not in self._aids:
					self._aids.append(rec[0][8:8 + int(rec[0][6:8], 16) * 2])
		except Exception as e:
			print("Can't read AIDs from SIM -- %s" % (str(e),))

	# Select ADF.U/ISIM in the Card using its full AID
	def select_adf_by_aid(self, adf="usim"):
     """
     Select an adf by adf

     Args:
         self: (todo): write your description
         adf: (todo): write your description
     """
		# Check for valid ADF name
		if adf not in ["usim", "isim"]:
			return None

		# First (known) halves of the U/ISIM AID
		aid_map = {}
		aid_map["usim"] = "a0000000871002"
		aid_map["isim"] = "a0000000871004"

		for aid in self._aids:
			if aid_map[adf] in aid:
				(res, sw) = self._scc.select_adf(aid)
				return sw

		return None

	# Erase the contents of a file
	def erase_binary(self, ef):
     """
     Erase binary data.

     Args:
         self: (todo): write your description
         ef: (todo): write your description
     """
		len = self._scc.binary_size(ef)
		self._scc.update_binary(ef, "ff" * len, offset=0, verify=True)

	# Erase the contents of a single record
	def erase_record(self, ef, rec_no):
     """
     Erase record

     Args:
         self: (todo): write your description
         ef: (todo): write your description
         rec_no: (todo): write your description
     """
		len = self._scc.record_size(ef)
		self._scc.update_record(ef, rec_no, "ff" * len, force_len=False, verify=True)

class UsimCard(Card):
	def __init__(self, ssc):
     """
     Initialize the card

     Args:
         self: (todo): write your description
         ssc: (todo): write your description
     """
		super(UsimCard, self).__init__(ssc)

	def read_ehplmn(self):
     """
     Read binary data from binary file.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF_USIM_ADF_map['EHPLMN'])
		if sw == '9000':
			return (format_xplmn(res), sw)
		else:
			return (None, sw)

	def update_ehplmn(self, mcc, mnc):
     """
     Update the binary data.

     Args:
         self: (todo): write your description
         mcc: (todo): write your description
         mnc: (todo): write your description
     """
		data = self._scc.read_binary(EF_USIM_ADF_map['EHPLMN'], length=None, offset=0)
		size = len(data[0]) // 2
		ehplmn = enc_plmn(mcc, mnc)
		data, sw = self._scc.update_binary(EF_USIM_ADF_map['EHPLMN'], ehplmn)
		return sw

	def read_epdgid(self):
     """
     Return epdgid of the given epdgid.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF_USIM_ADF_map['ePDGId'])
		if sw == '9000':
			return (dec_epdgid(res), sw)
		else:
			return (None, sw)

	def update_epdgid(self, epdgid):
     """
     Update epdgid

     Args:
         self: (todo): write your description
         epdgid: (int): write your description
     """
		epdgid_tlv = enc_epdgid(epdgid)
		data, sw = self._scc.update_binary(
						EF_USIM_ADF_map['ePDGId'], epdgid_tlv)
		return sw

	def read_ePDGSelection(self):
     """
     Read elem_election

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF_USIM_ADF_map['ePDGSelection'])
		if sw == '9000':
			return (format_ePDGSelection(res), sw)
		else:
			return (None, sw)

	def read_ust(self):
     """
     Reads : ref : pysynphot - rsa.

     Args:
         self: (todo): write your description
     """
		(res, sw) = self._scc.read_binary(EF_USIM_ADF_map['UST'])
		if sw == '9000':
			# Print those which are available
			return ([res, dec_st(res, table="usim")], sw)
		else:
			return ([None, None], sw)


class _MagicSimBase(Card):
	"""
	Theses cards uses several record based EFs to store the provider infos,
	each possible provider uses a specific record number in each EF. The
	indexes used are ( where N is the number of providers supported ) :
	 - [2 .. N+1] for the operator name
	 - [1 .. N] for the programable EFs

	* 3f00/7f4d/8f0c : Operator Name

	bytes 0-15 : provider name, padded with 0xff
	byte  16   : length of the provider name
	byte  17   : 01 for valid records, 00 otherwise

	* 3f00/7f4d/8f0d : Programmable Binary EFs

	* 3f00/7f4d/8f0e : Programmable Record EFs

	"""

	@classmethod
	def autodetect(kls, scc):
     """
     Find autodetectet

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			for p, l, t in kls._files.values():
				if not t:
					continue
				if scc.record_size(['3f00', '7f4d', p]) != l:
					return None
		except:
			return None

		return kls(scc)

	def _get_count(self):
		"""
		Selects the file and returns the total number of entries
		and entry size
		"""
		f = self._files['name']

		r = self._scc.select_file(['3f00', '7f4d', f[0]])
		rec_len = int(r[-1][28:30], 16)
		tlen = int(r[-1][4:8],16)
		rec_cnt = (tlen / rec_len) - 1

		if (rec_cnt < 1) or (rec_len != f[1]):
			raise RuntimeError('Bad card type')

		return rec_cnt

	def program(self, p):
     """
     Program : p ( p : py : unicode ) description

     Args:
         self: (todo): write your description
         p: (dict): write your description
     """
		# Go to dir
		self._scc.select_file(['3f00', '7f4d'])

		# Home PLMN in PLMN_Sel format
		hplmn = enc_plmn(p['mcc'], p['mnc'])

		# Operator name ( 3f00/7f4d/8f0c )
		self._scc.update_record(self._files['name'][0], 2,
			rpad(b2h(p['name']), 32)  + ('%02x' % len(p['name'])) + '01'
		)

		# ICCID/IMSI/Ki/HPLMN ( 3f00/7f4d/8f0d )
		v = ''

			# inline Ki
		if self._ki_file is None:
			v += p['ki']

			# ICCID
		v += '3f00' + '2fe2' + '0a' + enc_iccid(p['iccid'])

			# IMSI
		v += '7f20' + '6f07' + '09' + enc_imsi(p['imsi'])

			# Ki
		if self._ki_file:
			v += self._ki_file + '10' + p['ki']

			# PLMN_Sel
		v+= '6f30' + '18' +  rpad(hplmn, 36)

			# ACC
			# This doesn't work with "fake" SuperSIM cards,
			# but will hopefully work with real SuperSIMs.
		if p.get('acc') is not None:
			v+= '6f78' + '02' + lpad(p['acc'], 4)

		self._scc.update_record(self._files['b_ef'][0], 1,
			rpad(v, self._files['b_ef'][1]*2)
		)

		# SMSP ( 3f00/7f4d/8f0e )
			# FIXME

		# Write PLMN_Sel forcefully as well
		r = self._scc.select_file(['3f00', '7f20', '6f30'])
		tl = int(r[-1][4:8], 16)

		hplmn = enc_plmn(p['mcc'], p['mnc'])
		self._scc.update_binary('6f30', hplmn + 'ff' * (tl-3))

	def erase(self):
     """
     Erase all records

     Args:
         self: (todo): write your description
     """
		# Dummy
		df = {}
		for k, v in self._files.iteritems():
			ofs = 1
			fv = v[1] * 'ff'
			if k == 'name':
				ofs = 2
				fv = fv[0:-4] + '0000'
			df[v[0]] = (fv, ofs)

		# Write
		for n in range(0,self._get_count()):
			for k, (msg, ofs) in df.iteritems():
				self._scc.update_record(['3f00', '7f4d', k], n + ofs, msg)


class SuperSim(_MagicSimBase):

	name = 'supersim'

	_files = {
		'name' : ('8f0c', 18, True),
		'b_ef' : ('8f0d', 74, True),
		'r_ef' : ('8f0e', 50, True),
	}

	_ki_file = None


class MagicSim(_MagicSimBase):

	name = 'magicsim'

	_files = {
		'name' : ('8f0c', 18, True),
		'b_ef' : ('8f0d', 130, True),
		'r_ef' : ('8f0e', 102, False),
	}

	_ki_file = '6f1b'


class FakeMagicSim(Card):
	"""
	Theses cards have a record based EF 3f00/000c that contains the provider
	informations. See the program method for its format. The records go from
	1 to N.
	"""

	name = 'fakemagicsim'

	@classmethod
	def autodetect(kls, scc):
     """
     Return autodet size of record

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			if scc.record_size(['3f00', '000c']) != 0x5a:
				return None
		except:
			return None

		return kls(scc)

	def _get_infos(self):
		"""
		Selects the file and returns the total number of entries
		and entry size
		"""

		r = self._scc.select_file(['3f00', '000c'])
		rec_len = int(r[-1][28:30], 16)
		tlen = int(r[-1][4:8],16)
		rec_cnt = (tlen / rec_len) - 1

		if (rec_cnt < 1) or (rec_len != 0x5a):
			raise RuntimeError('Bad card type')

		return rec_cnt, rec_len

	def program(self, p):
     """
     Program :

     Args:
         self: (todo): write your description
         p: (array): write your description
     """
		# Home PLMN
		r = self._scc.select_file(['3f00', '7f20', '6f30'])
		tl = int(r[-1][4:8], 16)

		hplmn = enc_plmn(p['mcc'], p['mnc'])
		self._scc.update_binary('6f30', hplmn + 'ff' * (tl-3))

		# Get total number of entries and entry size
		rec_cnt, rec_len = self._get_infos()

		# Set first entry
		entry = (
			'81' +					#  1b  Status: Valid & Active
			rpad(b2h(p['name'][0:14]), 28) +	# 14b  Entry Name
			enc_iccid(p['iccid']) +			# 10b  ICCID
			enc_imsi(p['imsi']) +			#  9b  IMSI_len + id_type(9) + IMSI
			p['ki'] +				# 16b  Ki
			lpad(p['smsp'], 80)			# 40b  SMSP (padded with ff if needed)
		)
		self._scc.update_record('000c', 1, entry)

	def erase(self):
     """
     Erase infos.

     Args:
         self: (todo): write your description
     """
		# Get total number of entries and entry size
		rec_cnt, rec_len = self._get_infos()

		# Erase all entries
		entry = 'ff' * rec_len
		for i in range(0, rec_cnt):
			self._scc.update_record('000c', 1+i, entry)


class GrcardSim(Card):
	"""
	Greencard (grcard.cn) HZCOS GSM SIM
	These cards have a much more regular ISO 7816-4 / TS 11.11 structure,
	and use standard UPDATE RECORD / UPDATE BINARY commands except for Ki.
	"""

	name = 'grcardsim'

	@classmethod
	def autodetect(kls, scc):
     """
     Autodetetectet

     Args:
         kls: (array): write your description
         scc: (array): write your description
     """
		return None

	def program(self, p):
     """
     Run a program.

     Args:
         self: (todo): write your description
         p: (dict): write your description
     """
		# We don't really know yet what ADM PIN 4 is about
		#self._scc.verify_chv(4, h2b("4444444444444444"))

		# Authenticate using ADM PIN 5
		if p['pin_adm']:
			pin = h2b(p['pin_adm'])
		else:
			pin = h2b("4444444444444444")
		self._scc.verify_chv(5, pin)

		# EF.ICCID
		r = self._scc.select_file(['3f00', '2fe2'])
		data, sw = self._scc.update_binary('2fe2', enc_iccid(p['iccid']))

		# EF.IMSI
		r = self._scc.select_file(['3f00', '7f20', '6f07'])
		data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))

		# EF.ACC
		if p.get('acc') is not None:
			data, sw = self._scc.update_binary('6f78', lpad(p['acc'], 4))

		# EF.SMSP
		if p.get('smsp'):
			r = self._scc.select_file(['3f00', '7f10', '6f42'])
			data, sw = self._scc.update_record('6f42', 1, lpad(p['smsp'], 80))

		# Set the Ki using proprietary command
		pdu = '80d4020010' + p['ki']
		data, sw = self._scc._tp.send_apdu(pdu)

		# EF.HPLMN
		r = self._scc.select_file(['3f00', '7f20', '6f30'])
		size = int(r[-1][4:8], 16)
		hplmn = enc_plmn(p['mcc'], p['mnc'])
		self._scc.update_binary('6f30', hplmn + 'ff' * (size-3))

		# EF.SPN (Service Provider Name)
		r = self._scc.select_file(['3f00', '7f20', '6f30'])
		size = int(r[-1][4:8], 16)
		# FIXME

		# FIXME: EF.MSISDN


class SysmoSIMgr1(GrcardSim):
	"""
	sysmocom sysmoSIM-GR1
	These cards have a much more regular ISO 7816-4 / TS 11.11 structure,
	and use standard UPDATE RECORD / UPDATE BINARY commands except for Ki.
	"""
	name = 'sysmosim-gr1'

	@classmethod
	def autodetect(kls, scc):
     """
     Autodetectet

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			# Look for ATR
			if scc.get_atr() == toBytes("3B 99 18 00 11 88 22 33 44 55 66 77 60"):
				return kls(scc)
		except:
			return None
		return None

class SysmoUSIMgr1(UsimCard):
	"""
	sysmocom sysmoUSIM-GR1
	"""
	name = 'sysmoUSIM-GR1'

	@classmethod
	def autodetect(kls, scc):
     """
     Autodetetectet

     Args:
         kls: (array): write your description
         scc: (array): write your description
     """
		# TODO: Access the ATR
		return None

	def program(self, p):
     """
     Sends checksum.

     Args:
         self: (todo): write your description
         p: (array): write your description
     """
		# TODO: check if verify_chv could be used or what it needs
		# self._scc.verify_chv(0x0A, [0x33,0x32,0x32,0x31,0x33,0x32,0x33,0x32])
		# Unlock the card..
		data, sw = self._scc._tp.send_apdu_checksw("0020000A083332323133323332")

		# TODO: move into SimCardCommands
		par = ( p['ki'] +			# 16b  K
			p['opc'] +				# 32b  OPC
			enc_iccid(p['iccid']) +	# 10b  ICCID
			enc_imsi(p['imsi'])		#  9b  IMSI_len + id_type(9) + IMSI
			)
		data, sw = self._scc._tp.send_apdu_checksw("0099000033" + par)


class SysmoSIMgr2(Card):
	"""
	sysmocom sysmoSIM-GR2
	"""

	name = 'sysmoSIM-GR2'

	@classmethod
	def autodetect(kls, scc):
     """
     Autodetectet

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			# Look for ATR
			if scc.get_atr() == toBytes("3B 7D 94 00 00 55 55 53 0A 74 86 93 0B 24 7C 4D 54 68"):
				return kls(scc)
		except:
			return None
		return None

	def program(self, p):
     """
     Run a p = p ( p. p.

     Args:
         self: (todo): write your description
         p: (dict): write your description
     """

		# select MF
		r = self._scc.select_file(['3f00'])

		# authenticate as SUPER ADM using default key
		self._scc.verify_chv(0x0b, h2b("3838383838383838"))

		# set ADM pin using proprietary command
		# INS: D4
		# P1: 3A for PIN, 3B for PUK
		# P2: CHV number, as in VERIFY CHV for PIN, and as in UNBLOCK CHV for PUK
		# P3: 08, CHV length (curiously the PUK is also 08 length, instead of 10)
		if p['pin_adm']:
			pin = h2b(p['pin_adm'])
		else:
			pin = h2b("4444444444444444")

		pdu = 'A0D43A0508' + b2h(pin)
		data, sw = self._scc._tp.send_apdu(pdu)

		# authenticate as ADM (enough to write file, and can set PINs)

		self._scc.verify_chv(0x05, pin)

		# write EF.ICCID
		data, sw = self._scc.update_binary('2fe2', enc_iccid(p['iccid']))

		# select DF_GSM
		r = self._scc.select_file(['7f20'])

		# write EF.IMSI
		data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))

		# write EF.ACC
		if p.get('acc') is not None:
			data, sw = self._scc.update_binary('6f78', lpad(p['acc'], 4))

		# get size and write EF.HPLMN
		r = self._scc.select_file(['6f30'])
		size = int(r[-1][4:8], 16)
		hplmn = enc_plmn(p['mcc'], p['mnc'])
		self._scc.update_binary('6f30', hplmn + 'ff' * (size-3))

		# set COMP128 version 0 in proprietary file
		data, sw = self._scc.update_binary('0001', '001000')

		# set Ki in proprietary file
		data, sw = self._scc.update_binary('0001', p['ki'], 3)

		# select DF_TELECOM
		r = self._scc.select_file(['3f00', '7f10'])

		# write EF.SMSP
		if p.get('smsp'):
			data, sw = self._scc.update_record('6f42', 1, lpad(p['smsp'], 80))


class SysmoUSIMSJS1(UsimCard):
	"""
	sysmocom sysmoUSIM-SJS1
	"""

	name = 'sysmoUSIM-SJS1'

	def __init__(self, ssc):
     """
     Initialize the class

     Args:
         self: (todo): write your description
         ssc: (todo): write your description
     """
		super(SysmoUSIMSJS1, self).__init__(ssc)
		self._scc.cla_byte = "00"
		self._scc.sel_ctrl = "0004" #request an FCP

	@classmethod
	def autodetect(kls, scc):
     """
     Autodetectet

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			# Look for ATR
			if scc.get_atr() == toBytes("3B 9F 96 80 1F C7 80 31 A0 73 BE 21 13 67 43 20 07 18 00 00 01 A5"):
				return kls(scc)
		except:
			return None
		return None

	def program(self, p):
     """
     Program :

     Args:
         self: (todo): write your description
         p: (dict): write your description
     """

		# authenticate as ADM using default key (written on the card..)
		if not p['pin_adm']:
			raise ValueError("Please provide a PIN-ADM as there is no default one")
		self._scc.verify_chv(0x0A, h2b(p['pin_adm']))

		# select MF
		r = self._scc.select_file(['3f00'])

		# write EF.ICCID
		data, sw = self._scc.update_binary('2fe2', enc_iccid(p['iccid']))

		# select DF_GSM
		r = self._scc.select_file(['7f20'])

		# set Ki in proprietary file
		data, sw = self._scc.update_binary('00FF', p['ki'])

		# set OPc in proprietary file
		if 'opc' in p:
			content = "01" + p['opc']
			data, sw = self._scc.update_binary('00F7', content)

		# set Service Provider Name
		if p.get('name') is not None:
			content = enc_spn(p['name'], True, True)
			data, sw = self._scc.update_binary('6F46', rpad(content, 32))

		if p.get('acc') is not None:
			self.update_acc(p['acc'])

		# write EF.IMSI
		data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))

		# EF.PLMNsel
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_plmnsel(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming PLMNsel failed with code %s"%sw)

		# EF.PLMNwAcT
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_plmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming PLMNwAcT failed with code %s"%sw)

		# EF.OPLMNwAcT
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_oplmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming OPLMNwAcT failed with code %s"%sw)

		# EF.HPLMNwAcT
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_hplmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming HPLMNwAcT failed with code %s"%sw)

		# EF.AD
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_ad(p['mnc'])
			if sw != '9000':
				print("Programming AD failed with code %s"%sw)

		# EF.SMSP
		if p.get('smsp'):
			r = self._scc.select_file(['3f00', '7f10'])
			data, sw = self._scc.update_record('6f42', 1, lpad(p['smsp'], 104), force_len=True)

		# EF.MSISDN
		# TODO: Alpha Identifier (currently 'ff'O * 20)
		# TODO: Capability/Configuration1 Record Identifier
		# TODO: Extension1 Record Identifier
		if p.get('msisdn') is not None:
			msisdn = enc_msisdn(p['msisdn'])
			data = 'ff' * 20 + msisdn + 'ff' * 2

			r = self._scc.select_file(['3f00', '7f10'])
			data, sw = self._scc.update_record('6F40', 1, data, force_len=True)


class FairwavesSIM(UsimCard):
	"""
	FairwavesSIM

	The SIM card is operating according to the standard.
	For Ki/OP/OPC programming the following files are additionally open for writing:
		3F00/7F20/FF01 – OP/OPC:
		byte 1 = 0x01, bytes 2-17: OPC;
		byte 1 = 0x00, bytes 2-17: OP;
		3F00/7F20/FF02: Ki
	"""

	name = 'Fairwaves-SIM'
	# Propriatary files
	_EF_num = {
	'Ki': 'FF02',
	'OP/OPC': 'FF01',
	}
	_EF = {
	'Ki':     DF['GSM']+[_EF_num['Ki']],
	'OP/OPC': DF['GSM']+[_EF_num['OP/OPC']],
	}

	def __init__(self, ssc):
     """
     Initialize the underlying adapter.

     Args:
         self: (todo): write your description
         ssc: (todo): write your description
     """
		super(FairwavesSIM, self).__init__(ssc)
		self._adm_chv_num = 0x11
		self._adm2_chv_num = 0x12


	@classmethod
	def autodetect(kls, scc):
     """
     Autodetectet

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			# Look for ATR
			if scc.get_atr() == toBytes("3B 9F 96 80 1F C7 80 31 A0 73 BE 21 13 67 44 22 06 10 00 00 01 A9"):
				return kls(scc)
		except:
			return None
		return None


	def verify_adm2(self, key):
		'''
		Authenticate with ADM2 key.

		Fairwaves SIM cards support hierarchical key structure and ADM2 key
		is a key which has access to proprietary files (Ki and OP/OPC).
		That said, ADM key inherits permissions of ADM2 key and thus we rarely
		need ADM2 key per se.
		'''
		(res, sw) = self._scc.verify_chv(self._adm2_chv_num, key)
		return sw


	def read_ki(self):
		"""
		Read Ki in proprietary file.

		Requires ADM1 access level
		"""
		return self._scc.read_binary(self._EF['Ki'])


	def update_ki(self, ki):
		"""
		Set Ki in proprietary file.

		Requires ADM1 access level
		"""
		data, sw = self._scc.update_binary(self._EF['Ki'], ki)
		return sw


	def read_op_opc(self):
		"""
		Read Ki in proprietary file.

		Requires ADM1 access level
		"""
		(ef, sw) = self._scc.read_binary(self._EF['OP/OPC'])
		type = 'OP' if ef[0:2] == '00' else 'OPC'
		return ((type, ef[2:]), sw)


	def update_op(self, op):
		"""
		Set OP in proprietary file.

		Requires ADM1 access level
		"""
		content = '00' + op
		data, sw = self._scc.update_binary(self._EF['OP/OPC'], content)
		return sw


	def update_opc(self, opc):
		"""
		Set OPC in proprietary file.

		Requires ADM1 access level
		"""
		content = '01' + opc
		data, sw = self._scc.update_binary(self._EF['OP/OPC'], content)
		return sw


	def program(self, p):
     """
     Program : p

     Args:
         self: (todo): write your description
         p: (dict): write your description
     """
		# authenticate as ADM1
		if not p['pin_adm']:
			raise ValueError("Please provide a PIN-ADM as there is no default one")
		sw = self.verify_adm(h2b(p['pin_adm']))
		if sw != '9000':
			raise RuntimeError('Failed to authenticate with ADM key %s'%(p['pin_adm'],))

		# TODO: Set operator name
		if p.get('smsp') is not None:
			sw = self.update_smsp(p['smsp'])
			if sw != '9000':
				print("Programming SMSP failed with code %s"%sw)
		# This SIM doesn't support changing ICCID
		if p.get('mcc') is not None and p.get('mnc') is not None:
			sw = self.update_hplmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming MCC/MNC failed with code %s"%sw)
		if p.get('imsi') is not None:
			sw = self.update_imsi(p['imsi'])
			if sw != '9000':
				print("Programming IMSI failed with code %s"%sw)
		if p.get('ki') is not None:
			sw = self.update_ki(p['ki'])
			if sw != '9000':
				print("Programming Ki failed with code %s"%sw)
		if p.get('opc') is not None:
			sw = self.update_opc(p['opc'])
			if sw != '9000':
				print("Programming OPC failed with code %s"%sw)
		if p.get('acc') is not None:
			sw = self.update_acc(p['acc'])
			if sw != '9000':
				print("Programming ACC failed with code %s"%sw)

class OpenCellsSim(Card):
	"""
	OpenCellsSim

	"""

	name = 'OpenCells-SIM'

	def __init__(self, ssc):
     """
     Initialize the underlying device.

     Args:
         self: (todo): write your description
         ssc: (todo): write your description
     """
		super(OpenCellsSim, self).__init__(ssc)
		self._adm_chv_num = 0x0A


	@classmethod
	def autodetect(kls, scc):
     """
     Autodetectet

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			# Look for ATR
			if scc.get_atr() == toBytes("3B 9F 95 80 1F C3 80 31 E0 73 FE 21 13 57 86 81 02 86 98 44 18 A8"):
				return kls(scc)
		except:
			return None
		return None


	def program(self, p):
     """
     Program :

     Args:
         self: (todo): write your description
         p: (array): write your description
     """
		if not p['pin_adm']:
			raise ValueError("Please provide a PIN-ADM as there is no default one")
		self._scc.verify_chv(0x0A, h2b(p['pin_adm']))

		# select MF
		r = self._scc.select_file(['3f00'])

		# write EF.ICCID
		data, sw = self._scc.update_binary('2fe2', enc_iccid(p['iccid']))

		r = self._scc.select_file(['7ff0'])

		# set Ki in proprietary file
		data, sw = self._scc.update_binary('FF02', p['ki'])

		# set OPC in proprietary file
		data, sw = self._scc.update_binary('FF01', p['opc'])

		# select DF_GSM
		r = self._scc.select_file(['7f20'])

		# write EF.IMSI
		data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))

class WavemobileSim(UsimCard):
	"""
	WavemobileSim

	"""

	name = 'Wavemobile-SIM'

	def __init__(self, ssc):
     """
     Initialize the class.

     Args:
         self: (todo): write your description
         ssc: (todo): write your description
     """
		super(WavemobileSim, self).__init__(ssc)
		self._adm_chv_num = 0x0A
		self._scc.cla_byte = "00"
		self._scc.sel_ctrl = "0004" #request an FCP

	@classmethod
	def autodetect(kls, scc):
     """
     Autodetectet

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			# Look for ATR
			if scc.get_atr() == toBytes("3B 9F 95 80 1F C7 80 31 E0 73 F6 21 13 67 4D 45 16 00 43 01 00 8F"):
				return kls(scc)
		except:
			return None
		return None

	def program(self, p):
     """
     Program : p

     Args:
         self: (todo): write your description
         p: (dict): write your description
     """
		if not p['pin_adm']:
			raise ValueError("Please provide a PIN-ADM as there is no default one")
		sw = self.verify_adm(h2b(p['pin_adm']))
		if sw != '9000':
			raise RuntimeError('Failed to authenticate with ADM key %s'%(p['pin_adm'],))

		# EF.ICCID
		# TODO: Add programming of the ICCID
		if p.get('iccid'):
			print("Warning: Programming of the ICCID is not implemented for this type of card.")

		# KI (Presumably a propritary file)
		# TODO: Add programming of KI
		if p.get('ki'):
			print("Warning: Programming of the KI is not implemented for this type of card.")

		# OPc (Presumably a propritary file)
		# TODO: Add programming of OPc
		if p.get('opc'):
			print("Warning: Programming of the OPc is not implemented for this type of card.")

		# EF.SMSP
		if p.get('smsp'):
			sw = self.update_smsp(p['smsp'])
			if sw != '9000':
				print("Programming SMSP failed with code %s"%sw)

		# EF.IMSI
		if p.get('imsi'):
			sw = self.update_imsi(p['imsi'])
			if sw != '9000':
				print("Programming IMSI failed with code %s"%sw)

		# EF.ACC
		if p.get('acc'):
			sw = self.update_acc(p['acc'])
			if sw != '9000':
				print("Programming ACC failed with code %s"%sw)

		# EF.PLMNsel
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_plmnsel(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming PLMNsel failed with code %s"%sw)

		# EF.PLMNwAcT
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_plmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming PLMNwAcT failed with code %s"%sw)

		# EF.OPLMNwAcT
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_oplmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming OPLMNwAcT failed with code %s"%sw)

		# EF.AD
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_ad(p['mnc'])
			if sw != '9000':
				print("Programming AD failed with code %s"%sw)

		return None


class SysmoISIMSJA2(UsimCard):
	"""
	sysmocom sysmoISIM-SJA2
	"""

	name = 'sysmoISIM-SJA2'

	def __init__(self, ssc):
     """
     Initialize the class

     Args:
         self: (todo): write your description
         ssc: (todo): write your description
     """
		super(SysmoISIMSJA2, self).__init__(ssc)
		self._scc.cla_byte = "00"
		self._scc.sel_ctrl = "0004" #request an FCP

	@classmethod
	def autodetect(kls, scc):
     """
     Try to find autodet

     Args:
         kls: (array): write your description
         scc: (todo): write your description
     """
		try:
			# Try card model #1
			atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 75 30 34 05 4B A9"
			if scc.get_atr() == toBytes(atr):
				return kls(scc)

			# Try card model #2
			atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 75 31 33 02 51 B2"
			if scc.get_atr() == toBytes(atr):
				return kls(scc)

			# Try card model #3
			atr = "3B 9F 96 80 1F 87 80 31 E0 73 FE 21 1B 67 4A 4C 52 75 31 04 51 D5"
			if scc.get_atr() == toBytes(atr):
				return kls(scc)
		except:
			return None
		return None

	def program(self, p):
     """
     Program : p

     Args:
         self: (todo): write your description
         p: (dict): write your description
     """
		# authenticate as ADM using default key (written on the card..)
		if not p['pin_adm']:
			raise ValueError("Please provide a PIN-ADM as there is no default one")
		self._scc.verify_chv(0x0A, h2b(p['pin_adm']))

		# This type of card does not allow to reprogram the ICCID.
		# Reprogramming the ICCID would mess up the card os software
		# license management, so the ICCID must be kept at its factory
		# setting!
		if p.get('iccid'):
			print("Warning: Programming of the ICCID is not implemented for this type of card.")

		# select DF_GSM
		self._scc.select_file(['7f20'])

		# write EF.IMSI
		if p.get('imsi'):
			self._scc.update_binary('6f07', enc_imsi(p['imsi']))

		# EF.PLMNsel
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_plmnsel(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming PLMNsel failed with code %s"%sw)

		# EF.PLMNwAcT
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_plmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming PLMNwAcT failed with code %s"%sw)

		# EF.OPLMNwAcT
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_oplmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming OPLMNwAcT failed with code %s"%sw)

		# EF.HPLMNwAcT
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_hplmn_act(p['mcc'], p['mnc'])
			if sw != '9000':
				print("Programming HPLMNwAcT failed with code %s"%sw)

		# EF.AD
		if p.get('mcc') and p.get('mnc'):
			sw = self.update_ad(p['mnc'])
			if sw != '9000':
				print("Programming AD failed with code %s"%sw)

		# EF.SMSP
		if p.get('smsp'):
			r = self._scc.select_file(['3f00', '7f10'])
			data, sw = self._scc.update_record('6f42', 1, lpad(p['smsp'], 104), force_len=True)

		# Populate AIDs
		self.read_aids()

		# update EF-SIM_AUTH_KEY (and EF-USIM_AUTH_KEY_2G, which is
		# hard linked to EF-USIM_AUTH_KEY)
		self._scc.select_file(['3f00'])
		self._scc.select_file(['a515'])
		if p.get('ki'):
			self._scc.update_binary('6f20', p['ki'], 1)
		if p.get('opc'):
			self._scc.update_binary('6f20', p['opc'], 17)

		# update EF-USIM_AUTH_KEY in ADF.ISIM
		if '9000' == self.select_adf_by_aid(adf="isim"):
			if p.get('ki'):
				self._scc.update_binary('af20', p['ki'], 1)
			if p.get('opc'):
				self._scc.update_binary('af20', p['opc'], 17)

		if '9000' == self.select_adf_by_aid():
			# update EF-USIM_AUTH_KEY in ADF.USIM
			if p.get('ki'):
				self._scc.update_binary('af20', p['ki'], 1)
			if p.get('opc'):
				self._scc.update_binary('af20', p['opc'], 17)

			# update EF.EHPLMN in ADF.USIM
			if self.file_exists(EF_USIM_ADF_map['EHPLMN']):
				if p.get('mcc') and p.get('mnc'):
					sw = self.update_ehplmn(p['mcc'], p['mnc'])
					if sw != '9000':
						print("Programming EHPLMN failed with code %s"%sw)

			# update EF.ePDGId in ADF.USIM
			if self.file_exists(EF_USIM_ADF_map['ePDGId']):
				if p.get('epdgid'):
					sw = self.update_epdgid(p['epdgid'])
					if sw != '9000':
						print("Programming ePDGId failed with code %s"%sw)

		return


# In order for autodetection ...
_cards_classes = [ FakeMagicSim, SuperSim, MagicSim, GrcardSim,
		   SysmoSIMgr1, SysmoSIMgr2, SysmoUSIMgr1, SysmoUSIMSJS1,
		   FairwavesSIM, OpenCellsSim, WavemobileSim, SysmoISIMSJA2 ]

def card_autodetect(scc):
    """
    Returns a card autodet for a card

    Args:
        scc: (todo): write your description
    """
	for kls in _cards_classes:
		card = kls.autodetect(scc)
		if card is not None:
			card.reset()
			return card
	return None

def card_detect(ctype, scc):
    """
    Detect the card type of ctypes

    Args:
        ctype: (str): write your description
        scc: (array): write your description
    """
	# Detect type if needed
	card = None
	ctypes = dict([(kls.name, kls) for kls in _cards_classes])

	if ctype in ("auto", "auto_once"):
		for kls in _cards_classes:
			card = kls.autodetect(scc)
			if card:
				print("Autodetected card type: %s" % card.name)
				card.reset()
				break

		if card is None:
			print("Autodetection failed")
			return None

		if ctype == "auto_once":
			ctype = card.name

	elif ctype in ctypes:
		card = ctypes[ctype](scc)

	else:
		raise ValueError("Unknown card type: %s" % ctype)

	return card
