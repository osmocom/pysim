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
import traceback

import cmd2
from cmd2 import style, fg, bg
from cmd2 import CommandSet, with_default_category, with_argparser
import argparse

import os
import sys
from pathlib import Path
from io import StringIO

from pySim.ts_51_011 import EF, DF, EF_SST_map
from pySim.ts_31_102 import EF_UST_map, EF_USIM_ADF_map
from pySim.ts_31_103 import EF_IST_map, EF_ISIM_ADF_map

from pySim.exceptions import *
from pySim.commands import SimCardCommands
from pySim.transport import init_reader, ApduTracer, argparse_add_reader_args
from pySim.cards import card_detect, SimCard
from pySim.utils import h2b, swap_nibbles, rpad, b2h, h2s, JsonEncoder, bertlv_parse_one
from pySim.utils import dec_st, sanitize_pin_adm, tabulate_str_list, is_hex, boxed_heading_str
from pySim.card_handler import CardHandler, CardHandlerAuto

from pySim.filesystem import CardMF, RuntimeState, CardDF, CardADF, CardModel
from pySim.ts_51_011 import CardProfileSIM, DF_TELECOM, DF_GSM
from pySim.ts_102_221 import CardProfileUICC
from pySim.ts_31_102 import CardApplicationUSIM
from pySim.ts_31_103 import CardApplicationISIM
from pySim.gsm_r import DF_EIRENE

# we need to import this module so that the SysmocomSJA2 sub-class of
# CardModel is created, which will add the ATR-based matching and
# calling of SysmocomSJA2.add_files.  See  CardModel.apply_matching_models
import pySim.sysmocom_sja2

from pySim.card_key_provider import CardKeyProviderCsv, card_key_provider_register, card_key_provider_get_field

def init_card(sl):
	"""
	Detect card in reader and setup card profile and runtime state. This
	function must be called at least once on startup. The card and runtime
	state object (rs) is required for all pySim-shell commands.
	"""

	# Wait up to three seconds for a card in reader and try to detect
	# the card type.
	print("Waiting for card...")
	try:
		sl.wait_for_card(3)
	except NoCardError:
		print("No card detected!")
		return None, None;
	except:
		print("Card not readable!")
		return None, None;

	card = card_detect("auto", scc)
	if card is None:
		print("Could not detect card type!")
		return None, None;

	# Create runtime state with card profile
	profile = CardProfileUICC()
	profile.add_application(CardApplicationUSIM())
	profile.add_application(CardApplicationISIM())
	rs = RuntimeState(card, profile)

	# FIXME: do this dynamically
	rs.mf.add_file(DF_TELECOM())
	rs.mf.add_file(DF_GSM())
	rs.mf.add_file(DF_EIRENE())

	CardModel.apply_matching_models(scc, rs)

	# inform the transport that we can do context-specific SW interpretation
	sl.set_sw_interpreter(rs)

	return rs, card

class PysimApp(cmd2.Cmd):
	CUSTOM_CATEGORY = 'pySim Commands'
	def __init__(self, card, rs, sl, ch, script = None):
		super().__init__(persistent_history_file='~/.pysim_shell_history', allow_cli_args=False,
				 use_ipython=True, auto_load_commands=False, startup_script=script)
		self.intro = style('Welcome to pySim-shell!', fg=fg.red)
		self.default_category = 'pySim-shell built-in commands'
		self.card = None
		self.rs = None
		self.py_locals = { 'card': self.card, 'rs' : self.rs }
		self.sl = sl
		self.ch = ch

		self.numeric_path = False
		self.add_settable(cmd2.Settable('numeric_path', bool, 'Print File IDs instead of names',
						  onchange_cb=self._onchange_numeric_path))
		self.conserve_write = True
		self.add_settable(cmd2.Settable('conserve_write', bool, 'Read and compare before write',
						  onchange_cb=self._onchange_conserve_write))
		self.json_pretty_print = True
		self.add_settable(cmd2.Settable('json_pretty_print', bool, 'Pretty-Print JSON output'))
		self.apdu_trace = False
		self.add_settable(cmd2.Settable('apdu_trace', bool, 'Trace and display APDUs exchanged with card',
						  onchange_cb=self._onchange_apdu_trace))

		self.equip(card, rs)

	def equip(self, card, rs):
		"""
		Equip pySim-shell with the supplied card and runtime state, add (or remove) all required settables and
		and commands to enable card operations.
		"""

		rc = False

		# Unequip everything from pySim-shell that would not work in unequipped state
		if self.rs:
			self.rs.unregister_cmds(self)
		for cmds in [Iso7816Commands, PySimCommands]:
			cmd_set = self.find_commandsets(cmds)
			if cmd_set:
				self.unregister_command_set(cmd_set[0])

		self.card = card
		self.rs = rs

		# When a card object and a runtime state is present, (re)equip pySim-shell with everything that is
		# needed to operate on cards.
		if self.card and self.rs:
			self._onchange_conserve_write('conserve_write', False, self.conserve_write)
			self._onchange_apdu_trace('apdu_trace', False, self.apdu_trace)
			self.register_command_set(Iso7816Commands())
			self.register_command_set(PySimCommands())
			self.iccid, sw = self.card.read_iccid()
			rs.select('MF', self)
			rc = True
		else:
			self.poutput("pySim-shell not equipped!")

		self.update_prompt()
		return rc

	def poutput_json(self, data, force_no_pretty = False):
		"""like cmd2.poutput() but for a JSON serializable dict."""
		if force_no_pretty or self.json_pretty_print == False:
			output = json.dumps(data, cls=JsonEncoder)
		else:
			output = json.dumps(data, cls=JsonEncoder, indent=4)
		self.poutput(output)

	def _onchange_numeric_path(self, param_name, old, new):
		self.update_prompt()

	def _onchange_conserve_write(self, param_name, old, new):
		if self.rs:
			self.rs.conserve_write = new

	def _onchange_apdu_trace(self, param_name, old, new):
		if self.card:
			if new == True:
				self.card._scc._tp.apdu_tracer = self.Cmd2ApduTracer(self)
			else:
				self.card._scc._tp.apdu_tracer = None

	class Cmd2ApduTracer(ApduTracer):
		def __init__(self, cmd2_app):
			self.cmd2 = app

		def trace_response(self, cmd, sw, resp):
			self.cmd2.poutput("-> %s %s" % (cmd[:10], cmd[10:]))
			self.cmd2.poutput("<- %s: %s" % (sw, resp))

	def update_prompt(self):
		if self.rs:
			path_list = self.rs.selected_file.fully_qualified_path(not self.numeric_path)
			self.prompt = 'pySIM-shell (%s)> ' % ('/'.join(path_list))
		else:
			self.prompt = 'pySIM-shell (no card)> '

	@cmd2.with_category(CUSTOM_CATEGORY)
	def do_intro(self, _):
		"""Display the intro banner"""
		self.poutput(self.intro)

	@cmd2.with_category(CUSTOM_CATEGORY)
	def do_equip(self, opts):
		"""Equip pySim-shell with card"""
		rs, card = init_card(sl);
		self.equip(card, rs)

	class InterceptStderr(list):
		def __init__(self):
			self._stderr_backup = sys.stderr
		def __enter__(self):
			self._stringio_stderr = StringIO()
			sys.stderr = self._stringio_stderr
			return self
		def __exit__(self, *args):
			self.stderr = self._stringio_stderr.getvalue().strip()
			del self._stringio_stderr
			sys.stderr = self._stderr_backup

	def _show_failure_sign(self):
		self.poutput(style("  +-------------+", fg=fg.bright_red))
		self.poutput(style("  +   ##   ##   +", fg=fg.bright_red))
		self.poutput(style("  +    ## ##    +", fg=fg.bright_red))
		self.poutput(style("  +     ###     +", fg=fg.bright_red))
		self.poutput(style("  +    ## ##    +", fg=fg.bright_red))
		self.poutput(style("  +   ##   ##   +", fg=fg.bright_red))
		self.poutput(style("  +-------------+", fg=fg.bright_red))
		self.poutput("")

	def _show_success_sign(self):
		self.poutput(style("  +-------------+", fg=fg.bright_green))
		self.poutput(style("  +          ## +", fg=fg.bright_green))
		self.poutput(style("  +         ##  +", fg=fg.bright_green))
		self.poutput(style("  +  #    ##    +", fg=fg.bright_green))
		self.poutput(style("  +   ## #      +", fg=fg.bright_green))
		self.poutput(style("  +    ##       +", fg=fg.bright_green))
		self.poutput(style("  +-------------+", fg=fg.bright_green))
		self.poutput("")

	def _process_card(self, first, script_path):

		# Early phase of card initialzation (this part may fail with an exception)
		try:
			rs, card = init_card(self.sl)
			rc = self.equip(card, rs)
		except:
			self.poutput("")
			self.poutput("Card initialization failed with an exception:")
			self.poutput("---------------------8<---------------------")
			traceback.print_exc()
			self.poutput("---------------------8<---------------------")
			self.poutput("")
			return -1

		# Actual card processing step. This part should never fail with an exception since the cmd2
		# do_run_script method will catch any exception that might occur during script execution.
		if rc:
			self.poutput("")
			self.poutput("Transcript stdout:")
			self.poutput("---------------------8<---------------------")
			with self.InterceptStderr() as logged:
				self.do_run_script(script_path)
			self.poutput("---------------------8<---------------------")

			self.poutput("")
			self.poutput("Transcript stderr:")
			if logged.stderr:
				self.poutput("---------------------8<---------------------")
				self.poutput(logged.stderr)
				self.poutput("---------------------8<---------------------")
			else:
				self.poutput("(none)")

			# Check for exceptions
			self.poutput("")
			if "EXCEPTION of type" not in logged.stderr:
				return 0

		return -1

	bulk_script_parser = argparse.ArgumentParser()
	bulk_script_parser.add_argument('script_path', help="path to the script file")
	bulk_script_parser.add_argument('--halt_on_error', help='stop card handling if an exeption occurs',
					action='store_true')
	bulk_script_parser.add_argument('--tries', type=int, default=2,
					help='how many tries before trying the next card')
	bulk_script_parser.add_argument('--on_stop_action', type=str, default=None,
					help='commandline to execute when card handling has stopped')
	bulk_script_parser.add_argument('--pre_card_action', type=str, default=None,
					help='commandline to execute before actually talking to the card')

	@cmd2.with_argparser(bulk_script_parser)
	@cmd2.with_category(CUSTOM_CATEGORY)
	def do_bulk_script(self, opts):
		"""Run script on multiple cards (bulk provisioning)"""

		# Make sure that the script file exists and that it is readable.
		if not os.access(opts.script_path, os.R_OK):
			self.poutput("Invalid script file!")
			return

		success_count = 0
		fail_count = 0

		first = True
		while 1:
			# TODO: Count consecutive failures, if more than N consecutive failures occur, then stop.
			# The ratinale is: There may be a problem with the device, we do want to prevent that
			# all remaining cards are fired to the error bin. This is only relevant for situations
			# with large stacks, probably we do not need this feature right now.

			try:
				# In case of failure, try multiple times.
				for i in range(opts.tries):
					# fetch card into reader bay
					ch.get(first)

					# if necessary execute an action before we start processing the card
					if(opts.pre_card_action):
						os.system(opts.pre_card_action)

					# process the card
					rc = self._process_card(first, opts.script_path)
					if rc == 0:
						success_count = success_count + 1
						self._show_success_sign()
						self.poutput("Statistics: success :%i, failure: %i" % (success_count, fail_count))
						break
					else:
						fail_count = fail_count + 1
						self._show_failure_sign()
						self.poutput("Statistics: success :%i, failure: %i" % (success_count, fail_count))


				# Depending on success or failure, the card goes either in the "error" bin or in the
				# "done" bin.
				if rc < 0:
					ch.error()
				else:
					ch.done()

				# In most cases it is possible to proceed with the next card, but the
				# user may decide to halt immediately when an error occurs
				if opts.halt_on_error and rc < 0:
					return

			except (KeyboardInterrupt):
				self.poutput("")
				self.poutput("Terminated by user!")
				return;
			except (SystemExit):
				# When all cards are processed the card handler device will throw a SystemExit
				# exception. Also Errors that are not recoverable (cards stuck etc.) will end up here.
				# The user has the option to execute some action to make aware that the card handler
				# needs service.
				if(opts.on_stop_action):
					os.system(opts.on_stop_action)
				return
			except:
				self.poutput("")
				self.poutput("Card handling failed with an exception:")
				self.poutput("---------------------8<---------------------")
				traceback.print_exc()
				self.poutput("---------------------8<---------------------")
				self.poutput("")
				fail_count = fail_count + 1
				self._show_failure_sign()
				self.poutput("Statistics: success :%i, failure: %i" % (success_count, fail_count))

			first = False

	echo_parser = argparse.ArgumentParser()
	echo_parser.add_argument('string', help="string to echo on the shell")

	@cmd2.with_argparser(echo_parser)
	@cmd2.with_category(CUSTOM_CATEGORY)
	def do_echo(self, opts):
		"""Echo (print) a string on the console"""
		self.poutput(opts.string)

@with_default_category('pySim Commands')
class PySimCommands(CommandSet):
	def __init__(self):
		super().__init__()

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
				skip_df=False
				try:
					fcp_dec = self._cmd.rs.select(f, self._cmd)
				except Exception as e:
					skip_df=True
					df = self._cmd.rs.selected_file
					df_path_list = df.fully_qualified_path(True)
					df_skip_reason_str = '/'.join(df_path_list) + "/" + str(f) + ", " + str(e)
					if context:
						context['DF_SKIP'] += 1
						context['DF_SKIP_REASON'].append(df_skip_reason_str)

				# If the DF was skipped, we never have entered the directory
				# below, so we must not move up.
				if skip_df == False:
					self.walk(indent + 1, action, context)
					fcp_dec = self._cmd.rs.select("..", self._cmd)

			elif action:
				df_before_action = self._cmd.rs.selected_file
				action(f, context)
				# When walking through the file system tree the action must not
				# always restore the currently selected file to the file that
				# was selected before executing the action() callback.
				if df_before_action != self._cmd.rs.selected_file:
					raise RuntimeError("inconsistent walk, %s is currently selected but expecting %s to be selected"
							   % (str(self._cmd.rs.selected_file), str(df_before_action)))

	def do_tree(self, opts):
		"""Display a filesystem-tree with all selectable files"""
		self.walk()

	def export(self, filename, context):
		""" Select and export a single file """
		context['COUNT'] += 1
		df = self._cmd.rs.selected_file

		if not isinstance(df, CardDF):
			raise RuntimeError("currently selected file %s is not a DF or ADF" % str(df))

		df_path_list = df.fully_qualified_path(True)
		df_path_list_fid = df.fully_qualified_path(False)

		file_str = '/'.join(df_path_list) + "/" + str(filename)
		self._cmd.poutput(boxed_heading_str(file_str))

		self._cmd.poutput("# directory: %s (%s)" % ('/'.join(df_path_list), '/'.join(df_path_list_fid)))
		try:
			fcp_dec = self._cmd.rs.select(filename, self._cmd)
			self._cmd.poutput("# file: %s (%s)" % (self._cmd.rs.selected_file.name, self._cmd.rs.selected_file.fid))

			fd = fcp_dec['file_descriptor']
			structure = fd['structure']
			self._cmd.poutput("# structure: %s" % str(structure))

			for f in df_path_list:
				self._cmd.poutput("select " + str(f))
			self._cmd.poutput("select " + self._cmd.rs.selected_file.name)

			if structure == 'transparent':
				result = self._cmd.rs.read_binary()
				self._cmd.poutput("update_binary " + str(result[0]))
			elif structure == 'cyclic' or structure == 'linear_fixed':
				num_of_rec = fd['num_of_rec']
				for r in range(1, num_of_rec + 1):
					result = self._cmd.rs.read_record(r)
					self._cmd.poutput("update_record %d %s" % (r, str(result[0])))
			elif structure == 'ber_tlv':
				tags = self._cmd.rs.retrieve_tags()
				for t in tags:
					result = self._cmd.rs.retrieve_data(t)
					(tag, l, val, remainer) = bertlv_parse_one(h2b(result[0]))
					self._cmd.poutput("set_data 0x%02x %s" % (t, b2h(val)))
			else:
				raise RuntimeError('Unsupported structure "%s" of file "%s"' % (structure, filename))
		except Exception as e:
			bad_file_str = '/'.join(df_path_list) + "/" + str(filename) + ", " + str(e)
			self._cmd.poutput("# bad file: %s" % bad_file_str)
			context['ERR'] += 1
			context['BAD'].append(bad_file_str)

		# When reading the file is done, make sure the parent file is
		# selected again. This will be the usual case, however we need
		# to check before since we must not select the same DF twice
		if df != self._cmd.rs.selected_file:
			self._cmd.rs.select(df.fid or df.aid, self._cmd)

		self._cmd.poutput("#")

	export_parser = argparse.ArgumentParser()
	export_parser.add_argument('--filename', type=str, default=None, help='only export specific file')

	@cmd2.with_argparser(export_parser)
	def do_export(self, opts):
		"""Export files to script that can be imported back later"""
		context = {'ERR':0, 'COUNT':0, 'BAD':[], 'DF_SKIP':0, 'DF_SKIP_REASON':[]}
		if opts.filename:
			self.export(opts.filename, context)
		else:
			self.walk(0, self.export, context)

		self._cmd.poutput(boxed_heading_str("Export summary"))

		self._cmd.poutput("# total files visited: %u" % context['COUNT'])
		self._cmd.poutput("# bad files:           %u" % context['ERR'])
		for b in context['BAD']:
			self._cmd.poutput("#  " + b)

		self._cmd.poutput("# skipped dedicated files(s): %u" % context['DF_SKIP'])
		for b in context['DF_SKIP_REASON']:
			self._cmd.poutput("#  " + b)

		if context['ERR'] and context['DF_SKIP']:
			raise RuntimeError("unable to export %i elementary file(s) and %i dedicated file(s)" % (context['ERR'], context['DF_SKIP']))
		elif context['ERR']:
			raise RuntimeError("unable to export %i elementary file(s)" % context['ERR'])
		elif context['DF_SKIP']:
			raise RuntimeError("unable to export %i dedicated files(s)" % context['ERR'])

	def do_reset(self, opts):
		"""Reset the Card."""
		atr = self._cmd.rs.reset(self._cmd)
		self._cmd.poutput('Card ATR: %s' % atr)
		self._cmd.update_prompt()

	def do_desc(self, opts):
		"""Display human readable file description for the currently selected file"""
		desc = self._cmd.rs.selected_file.desc
		if desc:
			self._cmd.poutput(desc)
		else:
			self._cmd.poutput("no description available")

	def do_verify_adm(self, arg):
		"""VERIFY the ADM1 PIN"""
		if arg:
			# use specified ADM-PIN
			pin_adm = sanitize_pin_adm(arg)
		else:
			# try to find an ADM-PIN if none is specified
			result = card_key_provider_get_field('ADM1', key='ICCID', value=self._cmd.iccid)
			pin_adm = sanitize_pin_adm(result)
			if pin_adm:
				self._cmd.poutput("found ADM-PIN '%s' for ICCID '%s'" % (result, self._cmd.iccid))
			else:
				raise ValueError("cannot find ADM-PIN for ICCID '%s'" % (self._cmd.iccid))

		if pin_adm:
			self._cmd.card.verify_adm(h2b(pin_adm))
		else:
			raise ValueError("error: cannot authenticate, no adm-pin!")

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
		self._cmd.poutput_json(fcp_dec)

	def complete_select(self, text, line, begidx, endidx) -> List[str]:
		"""Command Line tab completion for SELECT"""
		index_dict = { 1: self._cmd.rs.selected_file.get_selectable_names() }
		return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

	def get_code(self, code):
		"""Use code either directly or try to get it from external data source"""
		auto = ('PIN1', 'PIN2', 'PUK1', 'PUK2')

		if str(code).upper() not in auto:
			return sanitize_pin_adm(code)

		result = card_key_provider_get_field(str(code), key='ICCID', value=self._cmd.iccid)
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
		self._cmd.poutput("CHV verification successful")

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

	def do_deactivate_file(self, opts):
		"""Deactivate the current EF"""
		(data, sw) = self._cmd.card._scc.deactivate_file()

	def do_activate_file(self, opts):
		"""Activate the specified EF"""
		path = opts.arg_list[0]
		(data, sw) = self._cmd.rs.activate_file(path)

	def complete_activate_file(self, text, line, begidx, endidx) -> List[str]:
		"""Command Line tab completion for ACTIVATE FILE"""
		index_dict = { 1: self._cmd.rs.selected_file.get_selectable_names() }
		return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

	open_chan_parser = argparse.ArgumentParser()
	open_chan_parser.add_argument('chan_nr', type=int, default=0, help='Channel Number')

	@cmd2.with_argparser(open_chan_parser)
	def do_open_channel(self, opts):
		"""Open a logical channel."""
		(data, sw) = self._cmd.card._scc.manage_channel(mode='open', lchan_nr=opts.chan_nr)

	close_chan_parser = argparse.ArgumentParser()
	close_chan_parser.add_argument('chan_nr', type=int, default=0, help='Channel Number')

	@cmd2.with_argparser(close_chan_parser)
	def do_close_channel(self, opts):
		"""Close a logical channel."""
		(data, sw) = self._cmd.card._scc.manage_channel(mode='close', lchan_nr=opts.chan_nr)

	def do_status(self, opts):
		"""Perform the STATUS command."""
		fcp_dec = self._cmd.rs.status()
		self._cmd.poutput_json(fcp_dec)

	suspend_uicc_parser = argparse.ArgumentParser()
	suspend_uicc_parser.add_argument('--min-duration-secs', type=int, default=60,
									 help='Proposed minimum duration of suspension')
	suspend_uicc_parser.add_argument('--max-duration-secs', type=int, default=24*60*60,
									 help='Proposed maximum duration of suspension')

	# not ISO7816-4 but TS 102 221
	@cmd2.with_argparser(suspend_uicc_parser)
	def do_suspend_uicc(self, opts):
		"""Perform the SUSPEND UICC command. Only supported on some UICC."""
		(duration, token, sw) = self._cmd.card._scc.suspend_uicc(min_len_secs=opts.min_duration_secs,
																 max_len_secs=opts.max_duration_secs)
		self._cmd.poutput('Negotiated Duration: %u secs, Token: %s, SW: %s' % (duration, token, sw))


option_parser = argparse.ArgumentParser(prog='pySim-shell', description='interactive SIM card shell',
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
argparse_add_reader_args(option_parser)

global_group = option_parser.add_argument_group('General Options')
global_group.add_argument('--script', metavar='PATH', default=None,
                          help='script with pySim-shell commands to be executed automatically at start-up')
global_group.add_argument('--csv', metavar='FILE', default=None, help='Read card data from CSV file')
global_group.add_argument("--card_handler", dest="card_handler_config", metavar="FILE",
			  help="Use automatic card handling machine")

adm_group = global_group.add_mutually_exclusive_group()
adm_group.add_argument('-a', '--pin-adm', metavar='PIN_ADM1', dest='pin_adm', default=None,
                       help='ADM PIN used for provisioning (overwrites default)')
adm_group.add_argument('-A', '--pin-adm-hex', metavar='PIN_ADM1_HEX', dest='pin_adm_hex', default=None,
                       help='ADM PIN used for provisioning, as hex string (16 characters long)')


if __name__ == '__main__':

	# Parse options
	opts = option_parser.parse_args()

	# If a script file is specified, be sure that it actually exists
	if opts.script:
		if not os.access(opts.script, os.R_OK):
			print("Invalid script file!")
			sys.exit(2)

	# Register csv-file as card data provider, either from specified CSV
	# or from CSV file in home directory
	csv_default = str(Path.home()) + "/.osmocom/pysim/card_data.csv"
	if opts.csv:
		card_key_provider_register(CardKeyProviderCsv(opts.csv))
	if os.path.isfile(csv_default):
		card_key_provider_register(CardKeyProviderCsv(csv_default))

	# Init card reader driver
	sl = init_reader(opts)
	if sl is None:
		exit(1)

	# Create command layer
	scc = SimCardCommands(transport=sl)

	# Create a card handler (for bulk provisioning)
	if opts.card_handler_config:
		ch = CardHandlerAuto(None, opts.card_handler_config)
	else:
		ch = CardHandler(sl)

	# Detect and initialize the card in the reader. This may fail when there
	# is no card in the reader or the card is unresponsive. PysimApp is
	# able to tolerate and recover from that.
	try:
		rs, card = init_card(sl)
		app = PysimApp(card, rs, sl, ch, opts.script)
	except:
		print("Card initialization failed with an exception:")
		print("---------------------8<---------------------")
		traceback.print_exc()
		print("---------------------8<---------------------")
		print("(you may still try to recover from this manually by using the 'equip' command.)")
		print(" it should also be noted that some readers may behave strangely when no card")
		print(" is inserted.)")
		print("")
		app = PysimApp(None, None, sl, ch, opts.script)

	# If the user supplies an ADM PIN at via commandline args authenticate
	# immediately so that the user does not have to use the shell commands
	pin_adm = sanitize_pin_adm(opts.pin_adm, opts.pin_adm_hex)
	if pin_adm:
		if not card:
			print("Card error, cannot do ADM verification with supplied ADM pin now.")
		try:
			card.verify_adm(h2b(pin_adm))
		except Exception as e:
			print(e)

	app.cmdloop()
