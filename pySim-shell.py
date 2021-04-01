#!/usr/bin/env python3

# Interactive shell for working with SIM / UICC / USIM / ISIM cards
#
# (C) 2021 by Harald Welte <laforge@osmocom.org>
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

from typing import List

import json

import cmd2
from cmd2 import style, fg, bg
from cmd2 import CommandSet, with_default_category, with_argparser
import argparse

import os
import sys
from optparse import OptionParser
from pathlib import Path

from pySim.ts_51_011 import EF, DF, EF_SST_map, EF_AD_mode_map
from pySim.ts_31_102 import EF_UST_map, EF_USIM_ADF_map
from pySim.ts_31_103 import EF_IST_map, EF_ISIM_ADF_map

from pySim.exceptions import *
from pySim.commands import SimCardCommands
from pySim.cards import card_detect, Card
from pySim.utils import h2b, swap_nibbles, rpad, h2s
from pySim.utils import dec_st, init_reader, sanitize_pin_adm, tabulate_str_list, is_hex
from pySim.card_handler import card_handler

from pySim.filesystem import CardMF, RuntimeState, CardDF, CardADF
from pySim.ts_51_011 import CardProfileSIM, DF_TELECOM, DF_GSM
from pySim.ts_102_221 import CardProfileUICC
from pySim.ts_31_102 import ADF_USIM
from pySim.ts_31_103 import ADF_ISIM

from pySim.card_data import CardDataCsv, card_data_register, card_data_get_field


class PysimApp(cmd2.Cmd):
	CUSTOM_CATEGORY = 'pySim Commands'
	def __init__(self, card, rs, script = None):
		basic_commands = [Iso7816Commands(), UsimCommands()]
		super().__init__(persistent_history_file='~/.pysim_shell_history', allow_cli_args=False,
				 use_ipython=True, auto_load_commands=False, command_sets=basic_commands, startup_script=script)
		self.intro = style('Welcome to pySim-shell!', fg=fg.red)
		self.default_category = 'pySim-shell built-in commands'
		self.card = card
		iccid, sw = self.card.read_iccid()
		self.iccid = iccid
		self.rs = rs
		self.py_locals = { 'card': self.card, 'rs' : self.rs }
		self.numeric_path = False
		self.add_settable(cmd2.Settable('numeric_path', bool, 'Print File IDs instead of names',
						  onchange_cb=self._onchange_numeric_path))
		self.conserve_write = True
		self.add_settable(cmd2.Settable('conserve_write', bool, 'Read and compare before write',
						  onchange_cb=self._onchange_conserve_write))
		self.update_prompt()

	def _onchange_numeric_path(self, param_name, old, new):
		self.update_prompt()

	def _onchange_conserve_write(self, param_name, old, new):
		self.rs.conserve_write = new

	def update_prompt(self):
		path_list = self.rs.selected_file.fully_qualified_path(not self.numeric_path)
		self.prompt = 'pySIM-shell (%s)> ' % ('/'.join(path_list))

	@cmd2.with_category(CUSTOM_CATEGORY)
	def do_intro(self, _):
		"""Display the intro banner"""
		self.poutput(self.intro)

	@cmd2.with_category(CUSTOM_CATEGORY)
	def do_verify_adm(self, arg):
		"""VERIFY the ADM1 PIN"""
		if arg:
			# use specified ADM-PIN
			pin_adm = sanitize_pin_adm(arg)
		else:
			# try to find an ADM-PIN if none is specified
			result = card_data_get_field('ADM1', key='ICCID', value=self.iccid)
			pin_adm = sanitize_pin_adm(result)
			if pin_adm:
				self.poutput("found ADM-PIN '%s' for ICCID '%s'" % (result, self.iccid))
			else:
				self.poutput("cannot find ADM-PIN for ICCID '%s'" % (self._cmd.iccid))
				return

		if pin_adm:
			self.card.verify_adm(h2b(pin_adm))
		else:
			self.poutput("error: cannot authenticate, no adm-pin!")

	@cmd2.with_category(CUSTOM_CATEGORY)
	def do_desc(self, opts):
		"""Display human readable file description for the currently selected file"""
		desc = self.rs.selected_file.desc
		if desc:
			self.poutput(desc)
		else:
			self.poutput("no description available")


@with_default_category('ISO7816 Commands')
class Iso7816Commands(CommandSet):
	def __init__(self):
		super().__init__()

	def do_select(self, opts):
		"""SELECT a File (ADF/DF/EF)"""
		if len(opts.arg_list) == 0:
			path_list = self._cmd.rs.selected_file.fully_qualified_path(True)
			path_list_fid = self._cmd.rs.selected_file.fully_qualified_path(False)
			self._cmd.poutput("currently selected file: " + '/'.join(path_list) + " (" + '/'.join(path_list_fid) + ")")
			return

		path = opts.arg_list[0]
		fcp_dec = self._cmd.rs.select(path, self._cmd)
		self._cmd.update_prompt()
		self._cmd.poutput(json.dumps(fcp_dec, indent=4))

	def complete_select(self, text, line, begidx, endidx) -> List[str]:
		"""Command Line tab completion for SELECT"""
		index_dict = { 1: self._cmd.rs.selected_file.get_selectable_names() }
		return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

	def get_code(self, code):
		"""Use code either directly or try to get it from external data source"""
		auto = ('PIN1', 'PIN2', 'PUK1', 'PUK2')

		if str(code).upper() not in auto:
			return sanitize_pin_adm(code)

		result = card_data_get_field(str(code), key='ICCID', value=self._cmd.iccid)
		result = sanitize_pin_adm(result)
		if result:
			self._cmd.poutput("found %s '%s' for ICCID '%s'" % (code.upper(), result, self._cmd.iccid))
		else:
			self._cmd.poutput("cannot find %s for ICCID '%s'" % (code.upper(), self._cmd.iccid))
		return result

	verify_chv_parser = argparse.ArgumentParser()
	verify_chv_parser.add_argument('--pin-nr', type=int, default=1, help='PIN Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
	verify_chv_parser.add_argument('pin_code', type=str, help='PIN code digits, \"PIN1\" or \"PIN2\" to get PIN code from external data source')

	@cmd2.with_argparser(verify_chv_parser)
	def do_verify_chv(self, opts):
		"""Verify (authenticate) using specified PIN code"""
		pin = self.get_code(opts.pin_code)
		(data, sw) = self._cmd.card._scc.verify_chv(opts.pin_nr, h2b(pin))
		self._cmd.poutput("CHV verfication successful")

	unblock_chv_parser = argparse.ArgumentParser()
	unblock_chv_parser.add_argument('--pin-nr', type=int, default=1, help='PUK Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
	unblock_chv_parser.add_argument('puk_code', type=str, help='PUK code digits \"PUK1\" or \"PUK2\" to get PUK code from external data source')
	unblock_chv_parser.add_argument('new_pin_code', type=str, help='PIN code digits \"PIN1\" or \"PIN2\" to get PIN code from external data source')

	@cmd2.with_argparser(unblock_chv_parser)
	def do_unblock_chv(self, opts):
		"""Unblock PIN code using specified PUK code"""
		new_pin = self.get_code(opts.new_pin_code)
		puk = self.get_code(opts.puk_code)
		(data, sw) = self._cmd.card._scc.unblock_chv(opts.pin_nr, h2b(puk), h2b(new_pin))
		self._cmd.poutput("CHV unblock successful")

	change_chv_parser = argparse.ArgumentParser()
	change_chv_parser.add_argument('--pin-nr', type=int, default=1, help='PUK Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
	change_chv_parser.add_argument('pin_code', type=str, help='PIN code digits \"PIN1\" or \"PIN2\" to get PIN code from external data source')
	change_chv_parser.add_argument('new_pin_code', type=str, help='PIN code digits \"PIN1\" or \"PIN2\" to get PIN code from external data source')

	@cmd2.with_argparser(change_chv_parser)
	def do_change_chv(self, opts):
		"""Change PIN code to a new PIN code"""
		new_pin = self.get_code(opts.new_pin_code)
		pin = self.get_code(opts.pin_code)
		(data, sw) = self._cmd.card._scc.change_chv(opts.pin_nr, h2b(pin), h2b(new_pin))
		self._cmd.poutput("CHV change successful")

	disable_chv_parser = argparse.ArgumentParser()
	disable_chv_parser.add_argument('--pin-nr', type=int, default=1, help='PIN Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
	disable_chv_parser.add_argument('pin_code', type=str, help='PIN code digits, \"PIN1\" or \"PIN2\" to get PIN code from external data source')

	@cmd2.with_argparser(disable_chv_parser)
	def do_disable_chv(self, opts):
		"""Disable PIN code using specified PIN code"""
		pin = self.get_code(opts.pin_code)
		(data, sw) = self._cmd.card._scc.disable_chv(opts.pin_nr, h2b(pin))
		self._cmd.poutput("CHV disable successful")

	enable_chv_parser = argparse.ArgumentParser()
	enable_chv_parser.add_argument('--pin-nr', type=int, default=1, help='PIN Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
	enable_chv_parser.add_argument('pin_code', type=str, help='PIN code digits, \"PIN1\" or \"PIN2\" to get PIN code from external data source')

	@cmd2.with_argparser(enable_chv_parser)
	def do_enable_chv(self, opts):
		"""Enable PIN code using specified PIN code"""
		pin = self.get_code(opts.pin_code)
		(data, sw) = self._cmd.card._scc.enable_chv(opts.pin_nr, h2b(pin))
		self._cmd.poutput("CHV enable successful")

	dir_parser = argparse.ArgumentParser()
	dir_parser.add_argument('--fids', help='Show file identifiers', action='store_true')
	dir_parser.add_argument('--names', help='Show file names', action='store_true')
	dir_parser.add_argument('--apps', help='Show applications', action='store_true')
	dir_parser.add_argument('--all', help='Show all selectable identifiers and names', action='store_true')

	@cmd2.with_argparser(dir_parser)
	def do_dir(self, opts):
		"""Show a listing of files available in currently selected DF or MF"""
		if opts.all:
			flags = []
		elif opts.fids or opts.names or opts.apps:
			flags = ['PARENT', 'SELF']
			if opts.fids:
				flags += ['FIDS', 'AIDS']
			if opts.names:
				flags += ['FNAMES', 'ANAMES']
			if opts.apps:
				flags += ['ANAMES', 'AIDS']
		else:
			flags = ['PARENT', 'SELF', 'FNAMES', 'ANAMES']
		selectables = list(self._cmd.rs.selected_file.get_selectable_names(flags = flags))
		directory_str = tabulate_str_list(selectables, width = 79, hspace = 2, lspace = 1, align_left = True)
		path_list = self._cmd.rs.selected_file.fully_qualified_path(True)
		self._cmd.poutput('/'.join(path_list))
		path_list = self._cmd.rs.selected_file.fully_qualified_path(False)
		self._cmd.poutput('/'.join(path_list))
		self._cmd.poutput(directory_str)
		self._cmd.poutput("%d files" % len(selectables))

	def walk(self, indent = 0, action = None, context = None):
		"""Recursively walk through the file system, starting at the currently selected DF"""
		files = self._cmd.rs.selected_file.get_selectables(flags = ['FNAMES', 'ANAMES'])
		for f in files:
			if not action:
				output_str = "  " * indent + str(f) + (" " * 250)
				output_str = output_str[0:25]
				if isinstance(files[f], CardADF):
					output_str += " " + str(files[f].aid)
				else:
					output_str += " " + str(files[f].fid)
				output_str += " " + str(files[f].desc)
				self._cmd.poutput(output_str)
			if isinstance(files[f], CardDF):
				fcp_dec = self._cmd.rs.select(f, self._cmd)
				self.walk(indent + 1, action, context)
				fcp_dec = self._cmd.rs.select("..", self._cmd)
			elif action:
				df_before_action = self._cmd.rs.selected_file
				action(f, context)
				# When walking through the file system tree the action must not
				# always restore the currently selected file to the file that
				# was selected before executing the action() callback.
				if df_before_action != self._cmd.rs.selected_file:
					raise RuntimeError("inconsistant walk, %s is currently selected but expecting %s to be selected"
							   % (str(self._cmd.rs.selected_file), str(df_before_action)))

	def do_tree(self, opts):
		"""Display a filesystem-tree with all selectable files"""
		self.walk()

	def export(self, filename, context):
		context['COUNT'] += 1
		path_list = self._cmd.rs.selected_file.fully_qualified_path(True)
		path_list_fid = self._cmd.rs.selected_file.fully_qualified_path(False)

		self._cmd.poutput("#" * 80)
		file_str = '/'.join(path_list) + "/" + str(filename) + " " * 80
		self._cmd.poutput("# " + file_str[0:77] + "#")
		self._cmd.poutput("#" * 80)

		self._cmd.poutput("# directory: %s (%s)" % ('/'.join(path_list), '/'.join(path_list_fid)))
		try:
			fcp_dec = self._cmd.rs.select(filename, self._cmd)
			path_list = self._cmd.rs.selected_file.fully_qualified_path(True)
			path_list_fid = self._cmd.rs.selected_file.fully_qualified_path(False)
			self._cmd.poutput("# file: %s (%s)" % (path_list[-1], path_list_fid[-1]))

			fd = fcp_dec['file_descriptor']
			structure = fd['structure']
			self._cmd.poutput("# structure: %s" % str(structure))

			for f in path_list:
				self._cmd.poutput("select " + str(f))

			if structure == 'transparent':
				result = self._cmd.rs.read_binary()
				self._cmd.poutput("update_binary " + str(result[0]))
			if structure == 'cyclic' or structure == 'linear_fixed':
				num_of_rec = fd['num_of_rec']
				for r in range(1, num_of_rec + 1):
					result = self._cmd.rs.read_record(r)
					self._cmd.poutput("update_record %d %s" % (r, str(result[0])))
			fcp_dec = self._cmd.rs.select("..", self._cmd)
		except Exception as e:
			bad_file_str = '/'.join(path_list) + "/" + str(filename) + ", " + str(e)
			self._cmd.poutput("# bad file: %s" % bad_file_str)
			context['ERR'] += 1
			context['BAD'].append(bad_file_str)

		self._cmd.poutput("#")

	export_parser = argparse.ArgumentParser()
	export_parser.add_argument('--filename', type=str, default=None, help='only export specific file')

	@cmd2.with_argparser(export_parser)
	def do_export(self, opts):
		"""Export files to script that can be imported back later"""
		context = {'ERR':0, 'COUNT':0, 'BAD':[]}
		if opts.filename:
			self.export(opts.filename, context)
		else:
			self.walk(0, self.export, context)
		self._cmd.poutput("# total files visited: %u" % context['COUNT'])
		self._cmd.poutput("# bad files:           %u" % context['ERR'])
		for b in context['BAD']:
			self._cmd.poutput("#  " + b)
		if context['ERR']:
			raise RuntimeError("unable to export %i file(s)" % context['ERR'])


@with_default_category('USIM Commands')
class UsimCommands(CommandSet):
	def __init__(self):
		super().__init__()

	def do_read_ust(self, _):
		"""Read + Display the EF.UST"""
		self._cmd.card.select_adf_by_aid(adf="usim")
		(res, sw) = self._cmd.card.read_ust()
		self._cmd.poutput(res[0])
		self._cmd.poutput(res[1])

	def do_read_ehplmn(self, _):
		"""Read EF.EHPLMN"""
		self._cmd.card.select_adf_by_aid(adf="usim")
		(res, sw) = self._cmd.card.read_ehplmn()
		self._cmd.poutput(res)

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
	parser.add_option("--script", dest="script", metavar="PATH",
			help="script with shell commands to be executed automatically",
			default=None,
		)

	parser.add_option("--csv", dest="csv", metavar="FILE",
			help="Read card data from CSV file",
			default=None,
		)

	parser.add_option("-a", "--pin-adm", dest="pin_adm",
			help="ADM PIN used for provisioning (overwrites default)",
		)
	parser.add_option("-A", "--pin-adm-hex", dest="pin_adm_hex",
			help="ADM PIN used for provisioning, as hex string (16 characters long",
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
	if (sl == None):
		exit(1)

	# Create command layer
	scc = SimCardCommands(transport=sl)

	sl.wait_for_card();

	card_handler = card_handler(sl)

	card = card_detect("auto", scc)
	if card is None:
		print("No card detected!")
		sys.exit(2)

	profile = CardProfileUICC()
	profile.add_application(ADF_USIM())
	profile.add_application(ADF_ISIM())

	rs = RuntimeState(card, profile)

	# FIXME: do this dynamically
	rs.mf.add_file(DF_TELECOM())
	rs.mf.add_file(DF_GSM())

	app = PysimApp(card, rs, opts.script)
	rs.select('MF', app)

	# Register csv-file as card data provider, either from specified CSV
	# or from CSV file in home directory
	csv_default = str(Path.home()) + "/.osmocom/pysim/card_data.csv"
	if opts.csv:
		card_data_register(CardDataCsv(opts.csv))
	if os.path.isfile(csv_default):
		card_data_register(CardDataCsv(csv_default))

	# If the user supplies an ADM PIN at via commandline args authenticate
	# immediatley so that the user does not have to use the shell commands
	pin_adm = sanitize_pin_adm(opts.pin_adm, opts.pin_adm_hex)
	if pin_adm:
		try:
			card.verify_adm(h2b(pin_adm))
		except Exception as e:
			print(e)

	app.cmdloop()
