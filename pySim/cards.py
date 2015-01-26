#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" pySim: Card programmation logic
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2011  Harald Welte <laforge@gnumonks.org>
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

from pySim.utils import b2h, h2b, swap_nibbles, rpad, lpad, enc_imsi, enc_iccid, enc_plmn


class Card(object):

	def __init__(self, scc):
		self._scc = scc

	def reset(self):
		self._scc.reset_card()


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
		rec_cnt = (tlen / rec_len) - 1;

		if (rec_cnt < 1) or (rec_len != f[1]):
			raise RuntimeError('Bad card type')

		return rec_cnt

	def program(self, p):
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
		rec_cnt = (tlen / rec_len) - 1;

		if (rec_cnt < 1) or (rec_len != 0x5a):
			raise RuntimeError('Bad card type')

		return rec_cnt, rec_len

	def program(self, p):
		# Home PLMN
		r = self._scc.select_file(['3f00', '7f20', '6f30'])
		tl = int(r[-1][4:8], 16)

		hplmn = enc_plmn(p['mcc'], p['mnc'])
		self._scc.update_binary('6f30', hplmn + 'ff' * (tl-3))

		# Get total number of entries and entry size
		rec_cnt, rec_len = self._get_infos()

		# Set first entry
		entry = (
			'81' +								#  1b  Status: Valid & Active
			rpad(b2h(p['name'][0:14]), 28) +	# 14b  Entry Name
			enc_iccid(p['iccid']) +				# 10b  ICCID
			enc_imsi(p['imsi']) +				#  9b  IMSI_len + id_type(9) + IMSI
			p['ki'] +							# 16b  Ki
			lpad(p['smsp'], 80)					# 40b  SMSP (padded with ff if needed)
		)
		self._scc.update_record('000c', 1, entry)

	def erase(self):
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
		return None

	def program(self, p):
		# We don't really know yet what ADM PIN 4 is about
		#self._scc.verify_chv(4, h2b("4444444444444444"))

		# Authenticate using ADM PIN 5
		if p['pin_adm']:
			pin = p['pin_adm']
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

	def erase(self):
		return

class SysmoSIMgr1(GrcardSim):
	"""
	sysmocom sysmoSIM-GR1
	These cards have a much more regular ISO 7816-4 / TS 11.11 structure,
	and use standard UPDATE RECORD / UPDATE BINARY commands except for Ki.
	"""
	name = 'sysmosim-gr1'


class SysmoUSIMgr1(Card):
	"""
	sysmocom sysmoUSIM-GR1
	"""
	name = 'sysmoUSIM-GR1'

	@classmethod
	def autodetect(kls, scc):
		# TODO: Access the ATR
		return None

	def program(self, p):
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

	def erase(self):
		return


class SysmoSIMgr2(Card):
	"""
	sysmocom sysmoSIM-GR2
	"""

	name = 'sysmoSIM-GR2'

	@classmethod
	def autodetect(kls, scc):
		# TODO: look for ATR 3B 7D 94 00 00 55 55 53 0A 74 86 93 0B 24 7C 4D 54 68
		return None

	def program(self, p):

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
			pin = p['pin_adm']
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
		data, sw = self._scc.update_record('6f42', 1, lpad(p['smsp'], 80))

	def erase(self):
		return

class SysmoUSIMSJS1(Card):
	"""
	sysmocom sysmoUSIM-SJS1
	"""

	name = 'sysmoUSIM-SJS1'

	def __init__(self, ssc):
		super(SysmoUSIMSJS1, self).__init__(ssc)
		self._scc.cla_byte = "00"

	@classmethod
	def autodetect(kls, scc):
		# TODO: look for ATR 3B 9F 96 80 1F C7 80 31 A0 73 BE 21 13 67 43 20 07 18 00 00 01 A5
		return None

	def program(self, p):


		# select MF
		r = self._scc.select_file(['3f00'])

		# select DF_GSM
		r = self._scc.select_file(['7f20'])

		# authenticate as ADM using default key (written on the card..)
		if not p['pin_adm']:
			raise ValueError("Please provide a PIN-ADM as there is no default one")

		self._scc.verify_chv(0x0A, h2b(p['pin_adm']))


		# set Ki in proprietary file
		data, sw = self._scc.update_binary('00FF', p['ki'])

		# set Ki in proprietary file
		content = "01" + p['opc']
		data, sw = self._scc.update_binary('00F7', content)


		# write EF.IMSI
		data, sw = self._scc.update_binary('6f07', enc_imsi(p['imsi']))



	def erase(self):
		return



	# In order for autodetection ...
_cards_classes = [ FakeMagicSim, SuperSim, MagicSim, GrcardSim,
		   SysmoSIMgr1, SysmoSIMgr2, SysmoUSIMgr1, SysmoUSIMSJS1 ]
