#!/usr/bin/env python3

#
# Utility to display some informations about a SIM card
#
#
# Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2010  Harald Welte <laforge@gnumonks.org>
# Copyright (C) 2013  Alexander Chemeris <alexander.chemeris@gmail.com>
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

import hashlib
from optparse import OptionParser
import os
import random
import re
import sys
from pySim.ts_51_011 import EF, DF, EF_SST_map, EF_AD_mode_map
from pySim.ts_31_102 import EF_UST_map, EF_USIM_ADF_map
from pySim.ts_31_103 import EF_IST_map, EF_ISIM_ADF_map

from pySim.commands import SimCardCommands
from pySim.cards import card_detect, Card, UsimCard, IsimCard
from pySim.utils import h2b, swap_nibbles, rpad, dec_imsi, dec_iccid, dec_msisdn
from pySim.utils import format_xplmn_w_act, dec_spn, dec_st, init_reader, dec_addr_tlv
from pySim.utils import h2s, format_ePDGSelection

def parse_options():

	parser = OptionParser(usage="usage: %prog [options]")

	parser.add_option("-d", "--device", dest="device", metavar="DEV",
			help="Serial Device for SIM access [default: %default]",
			default="/dev/ttyUSB0",
		)
	parser.add_option("-b", "--baud", dest="baudrate", type="int", metavar="BAUD",
			help="Baudrate used for SIM access [default: %default]",
			default=9600,
		)
	parser.add_option("-p", "--pcsc-device", dest="pcsc_dev", type='int', metavar="PCSC",
			help="Which PC/SC reader number for SIM access",
			default=None,
		)
	parser.add_option("--modem-device", dest="modem_dev", metavar="DEV",
			help="Serial port of modem for Generic SIM Access (3GPP TS 27.007)",
			default=None,
		)
	parser.add_option("--modem-baud", dest="modem_baud", type="int", metavar="BAUD",
			help="Baudrate used for modem's port [default: %default]",
			default=115200,
		)
	parser.add_option("--osmocon", dest="osmocon_sock", metavar="PATH",
			help="Socket path for Calypso (e.g. Motorola C1XX) based reader (via OsmocomBB)",
			default=None,
		)

	(options, args) = parser.parse_args()

	if args:
		parser.error("Extraneous arguments")

	return options


if __name__ == '__main__':

	# Parse options
	opts = parse_options()

	# Init card reader driver
	sl = init_reader(opts)
	if sl is None:
		exit(1)

	# Create command layer
	scc = SimCardCommands(transport=sl)

	# Wait for SIM card
	sl.wait_for_card()

	# Assuming UICC SIM
	scc.cla_byte = "00"
	scc.sel_ctrl = "0004"

	# Testing for Classic SIM or UICC
	(res, sw) = sl.send_apdu(scc.cla_byte + "a4" + scc.sel_ctrl + "02" + "3f00")
	if sw == '6e00':
		# Just a Classic SIM
		scc.cla_byte = "a0"
		scc.sel_ctrl = "0000"

	# Program the card
	print("Reading ...")

	# Initialize Card object by auto detecting the card
	card = card_detect("auto", scc) or Card(scc)

	# Read all AIDs on the UICC
	card.read_aids()

	# EF.ICCID
	(res, sw) = card.read_iccid()
	if sw == '9000':
		print("ICCID: %s" % (res,))
	else:
		print("ICCID: Can't read, response code = %s" % (sw,))

	# EF.IMSI
	(res, sw) = card.read_imsi()
	if sw == '9000':
		print("IMSI: %s" % (res,))
	else:
		print("IMSI: Can't read, response code = %s" % (sw,))

	# EF.GID1
	try:
		(res, sw) = card.read_gid1()
		if sw == '9000':
			print("GID1: %s" % (res,))
		else:
			print("GID1: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("GID1: Can't read file -- %s" % (str(e),))

	# EF.GID2
	try:
		(res, sw) = card.read_binary('GID2')
		if sw == '9000':
			print("GID2: %s" % (res,))
		else:
			print("GID2: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("GID2: Can't read file -- %s" % (str(e),))

	# EF.SMSP
	(res, sw) = card.read_record('SMSP', 1)
	if sw == '9000':
		print("SMSP: %s" % (res,))
	else:
		print("SMSP: Can't read, response code = %s" % (sw,))

	# EF.SPN
	try:
		(res, sw) = card.read_spn()
		if sw == '9000':
			print("SPN: %s" % (res[0] or "Not available"))
			print("Display HPLMN: %s" % (res[1],))
			print("Display OPLMN: %s" % (res[2],))
		else:
			print("SPN: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("SPN: Can't read file -- %s" % (str(e),))

	# EF.PLMNsel
	try:
		(res, sw) = card.read_binary('PLMNsel')
		if sw == '9000':
			print("PLMNsel: %s" % (res))
		else:
			print("PLMNsel: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("PLMNsel: Can't read file -- " + str(e))

	# EF.PLMNwAcT
	try:
		(res, sw) = card.read_plmn_act()
		if sw == '9000':
			print("PLMNwAcT:\n%s" % (res))
		else:
			print("PLMNwAcT: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("PLMNwAcT: Can't read file -- " + str(e))

	# EF.OPLMNwAcT
	try:
		(res, sw) = card.read_oplmn_act()
		if sw == '9000':
			print("OPLMNwAcT:\n%s" % (res))
		else:
			print("OPLMNwAcT: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("OPLMNwAcT: Can't read file -- " + str(e))

	# EF.HPLMNAcT
	try:
		(res, sw) = card.read_hplmn_act()
		if sw == '9000':
			print("HPLMNAcT:\n%s" % (res))
		else:
			print("HPLMNAcT: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("HPLMNAcT: Can't read file -- " + str(e))

	# EF.ACC
	(res, sw) = card.read_binary('ACC')
	if sw == '9000':
		print("ACC: %s" % (res,))
	else:
		print("ACC: Can't read, response code = %s" % (sw,))

	# EF.MSISDN
	try:
		(res, sw) = card.read_msisdn()
		if sw == '9000':
			# (npi, ton, msisdn) = res
			if res is not None:
				print("MSISDN (NPI=%d ToN=%d): %s" % res)
			else:
				print("MSISDN: Not available")
		else:
			print("MSISDN: Can't read, response code = %s" % (sw,))
	except Exception as e:
		print("MSISDN: Can't read file -- " + str(e))

	# EF.AD
	(res, sw) = card.read_binary('AD')
	if sw == '9000':
		print("Administrative data: %s" % (res,))
		if res[:2] in EF_AD_mode_map:
			print("\tMS operation mode: %s" % (EF_AD_mode_map[res[:2]],))
		else:
			print("\tMS operation mode: (unknown 0x%s)" % (res[:2],))
		if int(res[4:6], 16) & 0x01:
			print("\tCiphering Indicator: enabled")
		else:
			print("\tCiphering Indicator: disabled")
	else:
		print("AD: Can't read, response code = %s" % (sw,))

	# EF.SST
	(res, sw) = card.read_binary('SST')
	if sw == '9000':
		print("SIM Service Table: %s" % res)
		# Print those which are available
		print("%s" % dec_st(res))
	else:
		print("SIM Service Table: Can't read, response code = %s" % (sw,))

	# Check whether we have th AID of USIM, if so select it by its AID
	# EF.UST - File Id in ADF USIM : 6f38
	data, sw = card.select_adf_by_aid(adf="usim")
	if sw == '9000':
		# Select USIM profile
		usim_card = UsimCard(scc)

		# EF.EHPLMN
		if usim_card.file_exists(EF_USIM_ADF_map['EHPLMN']):
			(res, sw) = usim_card.read_ehplmn()
			if sw == '9000':
				print("EHPLMN:\n%s" % (res))
			else:
				print("EHPLMN: Can't read, response code = %s" % (sw,))

		# EF.UST
		try:
			if usim_card.file_exists(EF_USIM_ADF_map['UST']):
				# res[0] - EF content of UST
				# res[1] - Human readable format of services marked available in UST
				(res, sw) = usim_card.read_ust()
				if sw == '9000':
					print("USIM Service Table: %s" % res[0])
					print("%s" % res[1])
				else:
					print("USIM Service Table: Can't read, response code = %s" % (sw,))
		except Exception as e:
			print("USIM Service Table: Can't read file -- " + str(e))

		#EF.ePDGId - Home ePDG Identifier
		try:
			if usim_card.file_exists(EF_USIM_ADF_map['ePDGId']):
				(res, sw) = usim_card.read_epdgid()
				if sw == '9000':
					print("ePDGId:\n%s" % (len(res) and res or '\tNot available\n',))
				else:
					print("ePDGId: Can't read, response code = %s" % (sw,))
		except Exception as e:
			print("ePDGId: Can't read file -- " + str(e))

		#EF.ePDGSelection - ePDG Selection Information
		try:
			if usim_card.file_exists(EF_USIM_ADF_map['ePDGSelection']):
				(res, sw) = usim_card.read_ePDGSelection()
				if sw == '9000':
					print("ePDGSelection:\n%s" % (res,))
				else:
					print("ePDGSelection: Can't read, response code = %s" % (sw,))
		except Exception as e:
			print("ePDGSelection: Can't read file -- " + str(e))

	# Select ISIM application by its AID
	data, sw = card.select_adf_by_aid(adf="isim")
	if sw == '9000':
		# Select USIM profile
		isim_card = IsimCard(scc)

		#EF.P-CSCF - P-CSCF Address
		try:
			if isim_card.file_exists(EF_ISIM_ADF_map['PCSCF']):
				res = isim_card.read_pcscf()
				print("P-CSCF:\n%s" % (len(res) and res or '\tNot available\n',))
		except Exception as e:
			print("P-CSCF: Can't read file -- " + str(e))

		# EF.DOMAIN - Home Network Domain Name e.g. ims.mncXXX.mccXXX.3gppnetwork.org
		try:
			if isim_card.file_exists(EF_ISIM_ADF_map['DOMAIN']):
				(res, sw) = isim_card.read_domain()
				if sw == '9000':
					print("Home Network Domain Name: %s" % (len(res) and res or 'Not available',))
				else:
					print("Home Network Domain Name: Can't read, response code = %s" % (sw,))
		except Exception as e:
			print("Home Network Domain Name: Can't read file -- " + str(e))

		# EF.IMPI - IMS private user identity
		try:
			if isim_card.file_exists(EF_ISIM_ADF_map['IMPI']):
				(res, sw) = isim_card.read_impi()
				if sw == '9000':
					print("IMS private user identity: %s" % (len(res) and res or 'Not available',))
				else:
					print("IMS private user identity: Can't read, response code = %s" % (sw,))
		except Exception as e:
			print("IMS private user identity: Can't read file -- " + str(e))

		# EF.IMPU - IMS public user identity
		try:
			if isim_card.file_exists(EF_ISIM_ADF_map['IMPU']):
				res = isim_card.read_impu()
				print("IMS public user identity:\n%s" % (len(res) and res or '\tNot available\n',))
		except Exception as e:
			print("IMS public user identity: Can't read file -- " + str(e))

		# EF.UICCIARI - UICC IARI
		try:
			if isim_card.file_exists(EF_ISIM_ADF_map['UICCIARI']):
				res = isim_card.read_iari()
				print("UICC IARI:\n%s" % (len(res) and res or '\tNot available\n',))
		except Exception as e:
			print("UICC IARI: Can't read file -- " + str(e))

	# Check whether we have th AID of ISIM, if so select it by its AID
	# EF.IST - File Id in ADF ISIM : 6f07
	data, sw = card.select_adf_by_aid(adf="isim")
	if sw == '9000':
		# EF.IST
		(res, sw) = card.read_binary('6f07')
		if sw == '9000':
			print("ISIM Service Table: %s" % res)
			# Print those which are available
			print("%s" % dec_st(res, table="isim"))
		else:
			print("ISIM Service Table: Can't read, response code = %s" % (sw,))

	# Done for this card and maybe for everything ?
	print("Done !\n")
