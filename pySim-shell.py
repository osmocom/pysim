#!/usr/bin/env python3

# Interactive shell for working with SIM / UICC / USIM / ISIM cards
#
# (C) 2021-2023 by Harald Welte <laforge@osmocom.org>
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

from typing import List, Optional

import json
import traceback
import re

import cmd2
from packaging import version
from cmd2 import style
# cmd2 >= 2.3.0 has deprecated the bg/fg in favor of Bg/Fg :(
if version.parse(cmd2.__version__) < version.parse("2.3.0"):
    from cmd2 import fg, bg # pylint: disable=no-name-in-module
    RED = fg.red
    LIGHT_RED = fg.bright_red
    LIGHT_GREEN = fg.bright_green
else:
    from cmd2 import Fg, Bg # pylint: disable=no-name-in-module
    RED = Fg.RED
    LIGHT_RED = Fg.LIGHT_RED
    LIGHT_GREEN = Fg.LIGHT_GREEN
from cmd2 import CommandSet, with_default_category, with_argparser
import argparse

import os
import sys
import inspect
from pathlib import Path
from io import StringIO

from pprint import pprint as pp

from osmocom.utils import h2b, b2h, i2h, swap_nibbles, rpad, JsonEncoder, is_hexstr, is_decimal
from osmocom.utils import is_hexstr_or_decimal, Hexstr
from osmocom.tlv import bertlv_parse_one

from pySim.exceptions import *
from pySim.transport import init_reader, ApduTracer, argparse_add_reader_args, ProactiveHandler
from pySim.utils import sanitize_pin_adm, tabulate_str_list, boxed_heading_str, dec_iccid, sw_match
from pySim.card_handler import CardHandler, CardHandlerAuto

from pySim.filesystem import CardMF, CardEF, CardDF, CardADF, LinFixedEF, TransparentEF, BerTlvEF
from pySim.ts_102_221 import pin_names
from pySim.ts_102_222 import Ts102222Commands
from pySim.gsm_r import DF_EIRENE
from pySim.cat import ProactiveCommand

from pySim.card_key_provider import CardKeyProviderCsv, card_key_provider_register, card_key_provider_get_field

from pySim.app import init_card


class Cmd2Compat(cmd2.Cmd):
    """Backwards-compatibility wrapper around cmd2.Cmd to support older and newer
    releases. See https://github.com/python-cmd2/cmd2/blob/master/CHANGELOG.md"""
    def run_editor(self, file_path: Optional[str] = None) -> None:
        if version.parse(cmd2.__version__) < version.parse("2.0.0"):
            return self._run_editor(file_path) # pylint: disable=no-member
        else:
            return super().run_editor(file_path) # pylint: disable=no-member

class Settable2Compat(cmd2.Settable):
    """Backwards-compatibility wrapper around cmd2.Settable to support older and newer
    releases. See https://github.com/python-cmd2/cmd2/blob/master/CHANGELOG.md"""
    def __init__(self, name, val_type, description, settable_object, **kwargs):
        if version.parse(cmd2.__version__) < version.parse("2.0.0"):
            super().__init__(name, val_type, description, **kwargs) # pylint: disable=no-value-for-parameter
        else:
            super().__init__(name, val_type, description, settable_object, **kwargs) # pylint: disable=too-many-function-args

class PysimApp(Cmd2Compat):
    CUSTOM_CATEGORY = 'pySim Commands'
    BANNER = """Welcome to pySim-shell!
(C) 2021-2023 by Harald Welte, sysmocom - s.f.m.c. GmbH and contributors
Online manual available at https://downloads.osmocom.org/docs/pysim/master/html/shell.html """

    def __init__(self, card, rs, sl, ch, script=None):
        if version.parse(cmd2.__version__) < version.parse("2.0.0"):
            kwargs = {'use_ipython': True}
        else:
            kwargs = {'include_ipy': True}

        # pylint: disable=unexpected-keyword-arg
        super().__init__(persistent_history_file='~/.pysim_shell_history', allow_cli_args=False,
                         auto_load_commands=False, startup_script=script, **kwargs)
        self.intro = style(self.BANNER, fg=RED)
        self.default_category = 'pySim-shell built-in commands'
        self.card = None
        self.rs = None
        self.lchan = None
        self.py_locals = {'card': self.card, 'rs': self.rs, 'lchan': self.lchan}
        self.sl = sl
        self.ch = ch

        self.numeric_path = False
        self.conserve_write = True
        self.json_pretty_print = True
        self.apdu_trace = False
        self.apdu_strict = False

        self.add_settable(Settable2Compat('numeric_path', bool, 'Print File IDs instead of names', self,
                                          onchange_cb=self._onchange_numeric_path))
        self.add_settable(Settable2Compat('conserve_write', bool, 'Read and compare before write', self,
                                          onchange_cb=self._onchange_conserve_write))
        self.add_settable(Settable2Compat('json_pretty_print', bool, 'Pretty-Print JSON output', self))
        self.add_settable(Settable2Compat('apdu_trace', bool, 'Trace and display APDUs exchanged with card', self,
                                          onchange_cb=self._onchange_apdu_trace))
        self.add_settable(Settable2Compat('apdu_strict', bool,
                                          'Enforce APDU responses according to ISO/IEC 7816-3, table 12', self,
                                          onchange_cb=self._onchange_apdu_strict))
        self.equip(card, rs)

    def equip(self, card, rs):
        """
        Equip pySim-shell with the supplied card and runtime state, add (or remove) all required settables and
        and commands to enable card operations.
        """

        rc = False

        # Unequip everything from pySim-shell that would not work in unequipped state
        if self.rs:
            lchan = self.rs.lchan[0]
            lchan.unregister_cmds(self)
            if self.rs.profile:
                for cmd_set in self.rs.profile.shell_cmdsets:
                    self.unregister_command_set(cmd_set)

        for cmds in [Iso7816Commands, Ts102222Commands, PySimCommands]:
            cmd_set = self.find_commandsets(cmds)
            if cmd_set:
                self.unregister_command_set(cmd_set[0])

        self.card = card
        self.rs = rs

        # When a card object and a runtime state is present, (re)equip pySim-shell with everything that is
        # needed to operate on cards.
        if self.card and self.rs:
            self.rs.reset()
            self.lchan = self.rs.lchan[0]
            self._onchange_conserve_write(
                'conserve_write', False, self.conserve_write)
            self._onchange_apdu_trace('apdu_trace', False, self.apdu_trace)
            if self.rs.profile:
                for cmd_set in self.rs.profile.shell_cmdsets:
                    self.register_command_set(cmd_set)
            self.register_command_set(Iso7816Commands())
            self.register_command_set(Ts102222Commands())
            self.register_command_set(PySimCommands())

            try:
                self.lchan.select('MF/EF.ICCID', self)
                rs.identity['ICCID'] = dec_iccid(self.lchan.read_binary()[0])
            except:
                rs.identity['ICCID'] = None

            self.lchan.select('MF', self)
            rc = True
        else:
            self.poutput("pySim-shell not equipped!")

        self.update_prompt()
        return rc

    def poutput_json(self, data, force_no_pretty=False):
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

    def _onchange_apdu_strict(self, param_name, old, new):
        if self.card:
            if new == True:
                self.card._scc._tp.apdu_strict = True
            else:
                self.card._scc._tp.apdu_strict = False

    class Cmd2ApduTracer(ApduTracer):
        def __init__(self, cmd2_app):
            self.cmd2 = cmd2_app

        def trace_response(self, cmd, sw, resp):
            self.cmd2.poutput("-> %s %s" % (cmd[:10], cmd[10:]))
            self.cmd2.poutput("<- %s: %s" % (sw, resp))

    def update_prompt(self):
        if self.rs and self.rs.adm_verified:
            prompt_char = '#'
        else:
            prompt_char = '>'

        if self.lchan:
            path_str = self.lchan.selected_file.fully_qualified_path_str(not self.numeric_path)
            scp = self.lchan.scc.scp
            if scp:
                self.prompt = 'pySIM-shell (%s:%02u:%s)%c ' % (str(scp), self.lchan.lchan_nr, path_str, prompt_char)
            else:
                self.prompt = 'pySIM-shell (%02u:%s)%c ' % (self.lchan.lchan_nr, path_str, prompt_char)
        else:
            if self.card:
                self.prompt = 'pySIM-shell (no card profile)%c ' % prompt_char
            else:
                self.prompt = 'pySIM-shell (no card)%c ' % prompt_char

    @cmd2.with_category(CUSTOM_CATEGORY)
    def do_intro(self, _):
        """Display the intro banner"""
        self.poutput(self.intro)

    def do_eof(self, _: argparse.Namespace) -> bool:
        self.poutput("")
        return self.do_quit('')

    @cmd2.with_category(CUSTOM_CATEGORY)
    def do_equip(self, opts):
        """Equip pySim-shell with card"""
        if self.rs and self.rs.profile:
            for cmd_set in self.rs.profile.shell_cmdsets:
                self.unregister_command_set(cmd_set)
        rs, card = init_card(self.sl)
        self.equip(card, rs)

    apdu_cmd_parser = argparse.ArgumentParser()
    apdu_cmd_parser.add_argument('--expect-sw', help='expect a specified status word', type=str, default=None)
    apdu_cmd_parser.add_argument('--expect-response-regex', help='match response against regex', type=str, default=None)
    apdu_cmd_parser.add_argument('--raw', help='Bypass the logical channel (and secure channel)', action='store_true')
    apdu_cmd_parser.add_argument('APDU', type=is_hexstr, help='APDU as hex string')

    @cmd2.with_argparser(apdu_cmd_parser)
    def do_apdu(self, opts):
        """Send a raw APDU to the card, and print SW + Response.
        CAUTION: this command bypasses the logical channel handling of pySim-shell and card state changes are not
        tracked. Dpending on the raw APDU sent, pySim-shell may not continue to work as expected if you e.g. select
        a different file."""

        # When sending raw APDUs we access the scc object through _scc member of the card object. It should also be
        # noted that the apdu command plays an exceptional role since it is the only card accessing command that
        # can be executed without the presence of a runtime state (self.rs) object. However, this also means that
        # self.lchan is also not present (see method equip).
        if opts.raw or self.lchan is None:
            data, sw = self.card._scc.send_apdu(opts.APDU, apply_lchan = False)
        else:
            data, sw = self.lchan.scc.send_apdu(opts.APDU, apply_lchan = False)
        if data:
            self.poutput("SW: %s, RESP: %s" % (sw, data))
        else:
            self.poutput("SW: %s" % sw)
        if opts.expect_sw:
            if not sw_match(sw, opts.expect_sw):
                raise SwMatchError(sw, opts.expect_sw)
        if opts.expect_response_regex:
            response_regex_compiled = re.compile(opts.expect_response_regex)
            if  re.match(response_regex_compiled, data) is None:
                raise ValueError("RESP does not match regex \'%s\'" % opts.expect_response_regex)

    @cmd2.with_category(CUSTOM_CATEGORY)
    def do_reset(self, opts):
        """Reset the Card."""
        if self.rs is None:
            # In case no runtime state is available we go the direct route
            self.card._scc.reset_card()
            atr = self.card._scc.get_atr()
        else:
            atr = self.rs.reset(self)
        self.poutput('Card ATR: %s' % atr)
        self.update_prompt()

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
        self.poutput(style("  +-------------+", fg=LIGHT_RED))
        self.poutput(style("  +   ##   ##   +", fg=LIGHT_RED))
        self.poutput(style("  +    ## ##    +", fg=LIGHT_RED))
        self.poutput(style("  +     ###     +", fg=LIGHT_RED))
        self.poutput(style("  +    ## ##    +", fg=LIGHT_RED))
        self.poutput(style("  +   ##   ##   +", fg=LIGHT_RED))
        self.poutput(style("  +-------------+", fg=LIGHT_RED))
        self.poutput("")

    def _show_success_sign(self):
        self.poutput(style("  +-------------+", fg=LIGHT_GREEN))
        self.poutput(style("  +          ## +", fg=LIGHT_GREEN))
        self.poutput(style("  +         ##  +", fg=LIGHT_GREEN))
        self.poutput(style("  +  #    ##    +", fg=LIGHT_GREEN))
        self.poutput(style("  +   ## #      +", fg=LIGHT_GREEN))
        self.poutput(style("  +    ##       +", fg=LIGHT_GREEN))
        self.poutput(style("  +-------------+", fg=LIGHT_GREEN))
        self.poutput("")

    def _process_card(self, first, script_path):

        # Early phase of card initialzation (this part may fail with an exception)
        try:
            rs, card = init_card(self.sl)
            rc = self.equip(card, rs)
        except:
            self.poutput("")
            self.poutput("Card initialization (%s) failed with an exception:" % str(self.sl))
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
    bulk_script_parser.add_argument('SCRIPT_PATH', help="path to the script file")
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
        if not os.access(opts.SCRIPT_PATH, os.R_OK):
            self.poutput("Invalid script file!")
            return

        success_count = 0
        fail_count = 0

        first = True
        while 1:
            # TODO: Count consecutive failures, if more than N consecutive failures occur, then stop.
            # The rationale is: There may be a problem with the device, we do want to prevent that
            # all remaining cards are fired to the error bin. This is only relevant for situations
            # with large stacks, probably we do not need this feature right now.

            try:
                # In case of failure, try multiple times.
                for i in range(opts.tries):
                    # fetch card into reader bay
                    self.ch.get(first)

                    # if necessary execute an action before we start processing the card
                    if(opts.pre_card_action):
                        os.system(opts.pre_card_action)

                    # process the card
                    rc = self._process_card(first, opts.SCRIPT_PATH)
                    if rc == 0:
                        success_count = success_count + 1
                        self._show_success_sign()
                        self.poutput("Statistics: success :%i, failure: %i" % (
                            success_count, fail_count))
                        break
                    else:
                        fail_count = fail_count + 1
                        self._show_failure_sign()
                        self.poutput("Statistics: success :%i, failure: %i" % (
                            success_count, fail_count))

                # Depending on success or failure, the card goes either in the "error" bin or in the
                # "done" bin.
                if rc < 0:
                    self.ch.error()
                else:
                    self.ch.done()

                # In most cases it is possible to proceed with the next card, but the
                # user may decide to halt immediately when an error occurs
                if opts.halt_on_error and rc < 0:
                    return

            except (KeyboardInterrupt):
                self.poutput("")
                self.poutput("Terminated by user!")
                return
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
                self.poutput("Card handling (%s) failed with an exception:" % str(self.sl))
                self.poutput("---------------------8<---------------------")
                traceback.print_exc()
                self.poutput("---------------------8<---------------------")
                self.poutput("")
                fail_count = fail_count + 1
                self._show_failure_sign()
                self.poutput("Statistics: success :%i, failure: %i" %
                             (success_count, fail_count))

            first = False

    echo_parser = argparse.ArgumentParser()
    echo_parser.add_argument('STRING', help="string to echo on the shell", nargs='+')

    @cmd2.with_argparser(echo_parser)
    @cmd2.with_category(CUSTOM_CATEGORY)
    def do_echo(self, opts):
        """Echo (print) a string on the console"""
        self.poutput(' '.join(opts.STRING))

    @cmd2.with_category(CUSTOM_CATEGORY)
    def do_version(self, opts):
        """Print the pySim software version."""
        import pkg_resources
        self.poutput(pkg_resources.get_distribution('pySim'))

@with_default_category('pySim Commands')
class PySimCommands(CommandSet):
    def __init__(self):
        super().__init__()

    dir_parser = argparse.ArgumentParser()
    dir_parser.add_argument(
        '--fids', help='Show file identifiers', action='store_true')
    dir_parser.add_argument(
        '--names', help='Show file names', action='store_true')
    dir_parser.add_argument(
        '--apps', help='Show applications', action='store_true')
    dir_parser.add_argument(
        '--all', help='Show all selectable identifiers and names', action='store_true')

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
        selectables = list(
            self._cmd.lchan.selected_file.get_selectable_names(flags=flags))
        directory_str = tabulate_str_list(
            selectables, width=79, hspace=2, lspace=1, align_left=True)
        path = self._cmd.lchan.selected_file.fully_qualified_path_str(True)
        self._cmd.poutput(path)
        path = self._cmd.lchan.selected_file.fully_qualified_path_str(False)
        self._cmd.poutput(path)
        self._cmd.poutput(directory_str)
        self._cmd.poutput("%d files" % len(selectables))

    def __walk_action(self, action, filename, context, **kwargs):
        # Changing the currently selected file while walking over the filesystem tree would disturb the
        # walk, so we memorize the currently selected file here so that we can select it again after
        # we have executed the action callback.
        selected_file_before_action = self._cmd.lchan.selected_file

        # Perform action
        action(filename, context, **kwargs)

        # When the action callback is done, make sure the file that was selected before is selected again.
        if selected_file_before_action != self._cmd.lchan.selected_file:
            self._cmd.lchan.select_file(selected_file_before_action, self._cmd)

    def __walk(self, indent=0, action_ef=None, action_df=None, context=None, **kwargs):
        """Recursively walk through the file system, starting at the currently selected DF"""

        if isinstance(self._cmd.lchan.selected_file, CardDF):
            if action_df:
                self.__walk_action(action_df, self._cmd.lchan.selected_file.name, context, **kwargs)

        files = self._cmd.lchan.selected_file.get_selectables(
            flags=['FNAMES', 'ANAMES'])
        for f in files:
            # special case: When no action is performed, just output a directory
            if not action_ef and not action_df:
                output_str = "  " * indent + str(f) + (" " * 250)
                output_str = output_str[0:25]
                if isinstance(files[f], CardADF):
                    output_str += " " + str(files[f].aid)
                else:
                    output_str += " " + str(files[f].fid)
                output_str += " " + str(files[f].desc)
                self._cmd.poutput(output_str)

            if isinstance(files[f], CardDF):
                skip_df = False
                try:
                    fcp_dec = self._cmd.lchan.select(f, self._cmd)
                except Exception as e:
                    skip_df = True
                    df = self._cmd.lchan.selected_file
                    df_path = df.fully_qualified_path_str(True)
                    df_skip_reason_str = df_path + \
                        "/" + str(f) + ", " + str(e)
                    if context:
                        context['DF_SKIP'] += 1
                        context['DF_SKIP_REASON'].append(df_skip_reason_str)

                # If the DF was skipped, we never have entered the directory
                # below, so we must not move up.
                if skip_df == False:
                    self.__walk(indent + 1, action_ef, action_df, context, **kwargs)
                    self._cmd.lchan.select_file(self._cmd.lchan.selected_file.parent, self._cmd)

            elif action_ef:
                self.__walk_action(action_ef, f, context, **kwargs)

    def do_tree(self, opts):
        """Display a filesystem-tree with all selectable files"""
        self.__walk()

    def __export_file(self, filename, context, as_json):
        """ Select and export a single file (EF, DF or ADF) """
        context['COUNT'] += 1

        file = self._cmd.lchan.get_file_by_name(filename)
        if file:
            self._cmd.poutput(boxed_heading_str(file.fully_qualified_path_str(True)))
            self._cmd.poutput("# directory: %s (%s)" % (file.fully_qualified_path_str(True),
                                                        file.fully_qualified_path_str(False)))
        else:
            # If this is called from self.__walk(), then it is ensured that the file exists.
            raise RuntimeError("cannot export, file %s does not exist in the file system tree" % filename)

        try:
            fcp_dec = self._cmd.lchan.select_file(file, self._cmd)
            self._cmd.poutput("# file: %s (%s)" %
                              (self._cmd.lchan.selected_file.name, self._cmd.lchan.selected_file.fid))
            if isinstance(self._cmd.lchan.selected_file, CardEF):
                self._cmd.poutput("# structure: %s" % str(self._cmd.lchan.selected_file_structure()))
            self._cmd.poutput("# RAW FCP Template: %s" % str(self._cmd.lchan.selected_file_fcp_hex))
            self._cmd.poutput("# Decoded FCP Template: %s" % str(self._cmd.lchan.selected_file_fcp))
            self._cmd.poutput("select " + self._cmd.lchan.selected_file.fully_qualified_path_str())
            self._cmd.poutput(self._cmd.lchan.selected_file.export(as_json, self._cmd.lchan))
        except Exception as e:
            bad_file_str = file.fully_qualified_path_str(True) + "/" + str(file.name) + ", " + str(e)
            self._cmd.poutput("# bad file: %s" % bad_file_str)
            context['ERR'] += 1
            context['BAD'].append(bad_file_str)

        self._cmd.poutput("#")

    export_parser = argparse.ArgumentParser()
    export_parser.add_argument(
        '--filename', type=str, default=None, help='only export specific file')
    export_parser.add_argument(
        '--json', action='store_true', help='export as JSON (less reliable)')

    @cmd2.with_argparser(export_parser)
    def do_export(self, opts):
        """Export files to script that can be imported back later"""
        context = {'ERR': 0, 'COUNT': 0, 'BAD': [],
                   'DF_SKIP': 0, 'DF_SKIP_REASON': []}
        kwargs_export = {'as_json': opts.json}
        exception_str_add = ""

        if opts.filename:
            self.__walk_action(self.__export_file, opts.filename, context, **kwargs_export)
        else:
            try:
                self.__walk(0, self.__export_file, self.__export_file, context, **kwargs_export)
            except Exception as e:
                print("# Stopping early here due to exception: " + str(e))
                print("#")
                exception_str_add = ", also had to stop early due to exception:" + str(e)

        self._cmd.poutput(boxed_heading_str("Export summary"))

        self._cmd.poutput("# total files visited: %u" % context['COUNT'])
        self._cmd.poutput("# bad files:           %u" % context['ERR'])
        for b in context['BAD']:
            self._cmd.poutput("#  " + b)

        self._cmd.poutput("# skipped dedicated files(s): %u" %
                          context['DF_SKIP'])
        for b in context['DF_SKIP_REASON']:
            self._cmd.poutput("#  " + b)

        if context['ERR'] and context['DF_SKIP']:
            raise RuntimeError("unable to export %i elementary file(s) and %i dedicated file(s)%s" % (
                    context['ERR'], context['DF_SKIP'], exception_str_add))
        elif context['ERR']:
            raise RuntimeError(
                    "unable to export %i elementary file(s)%s" % (context['ERR'], exception_str_add))
        elif context['DF_SKIP']:
            raise RuntimeError(
                    "unable to export %i dedicated files(s)%s" % (context['ERR'], exception_str_add))

    def __dump_file(self, filename, context, as_json):
        """ Select and dump a single file (EF, DF or ADF) """
        file = self._cmd.lchan.get_file_by_name(filename)
        if file:
            res = {
                'path': file.fully_qualified_path(True)
            }
        else:
            # If this is called from self.__walk(), then it is ensured that the file exists.
            raise RuntimeError("cannot dump, file %s does not exist in the file system tree" % filename)

        try:
            fcp_dec = self._cmd.lchan.select(filename, self._cmd)

            # File control parameters (common for EF, DF and ADF files)
            if not self._cmd.lchan.selected_file_fcp_hex:
                # An application without a real ADF (like ADF.ARA-M) / filesystem
                return

            res['fcp_raw'] = str(self._cmd.lchan.selected_file_fcp_hex)
            res['fcp'] = fcp_dec

            # File structure and contents (EF only)
            if isinstance(self._cmd.lchan.selected_file, CardEF):
                structure = self._cmd.lchan.selected_file_structure()
                if structure == 'transparent':
                    if as_json:
                        result = self._cmd.lchan.read_binary_dec()
                        body = result[0]
                    else:
                        result = self._cmd.lchan.read_binary()
                        body = str(result[0])
                elif structure == 'cyclic' or structure == 'linear_fixed':
                    body = []
                    # Use number of records specified in select response
                    num_of_rec = self._cmd.lchan.selected_file_num_of_rec()
                    if num_of_rec:
                        for r in range(1, num_of_rec + 1):
                            if as_json:
                                result = self._cmd.lchan.read_record_dec(r)
                                body.append(result[0])
                            else:
                                result = self._cmd.lchan.read_record(r)
                                body.append(str(result[0]))

                    # When the select response does not return the number of records, read until we hit the
                    # first record that cannot be read.
                    else:
                        r = 1
                        while True:
                            try:
                                if as_json:
                                    result = self._cmd.lchan.read_record_dec(r)
                                    body.append(result[0])
                                else:
                                    result = self._cmd.lchan.read_record(r)
                                    body.append(str(result[0]))
                            except SwMatchError as e:
                                # We are past the last valid record - stop
                                if e.sw_actual == "9402":
                                    break
                                # Some other problem occurred
                                raise e
                            r = r + 1
                elif structure == 'ber_tlv':
                    tags = self._cmd.lchan.retrieve_tags()
                    body = {}
                    for t in tags:
                        result = self._cmd.lchan.retrieve_data(t)
                        (tag, l, val, remainer) = bertlv_parse_one(h2b(result[0]))
                        body[t] = b2h(val)
                else:
                    raise RuntimeError('Unsupported structure "%s" of file "%s"' % (structure, filename))
                res['body'] = body

        except SwMatchError as e:
            res['error'] = {
                'sw_actual': e.sw_actual,
                'sw_expected': e.sw_expected,
                'message': e.description,
            }
        except Exception as e:
            raise(e)
            res['error'] = {
                'message': str(e)
            }

        context['result']['files'][file.fully_qualified_path_str(True)] = res

    fsdump_parser = argparse.ArgumentParser()
    fsdump_parser.add_argument(
        '--filename', type=str, default=None, help='only export specific (named) file')
    fsdump_parser.add_argument(
        '--json', action='store_true', help='export file contents as JSON (less reliable)')

    @cmd2.with_argparser(fsdump_parser)
    def do_fsdump(self, opts):
        """Export filesystem metadata and file contents of all files below current DF in
        machine-readable json format.  This is similar to "export", but much easier to parse by
        downstream processing tools.  You usually may want to call this from the MF and verify
        the ADM1 PIN (if available) to maximize the amount of readable files."""
        result = {
            'name': self._cmd.card.name,
            'atr': self._cmd.rs.identity['ATR'],
            'eid': self._cmd.rs.identity.get('EID', None),
            'iccid': self._cmd.rs.identity.get('ICCID', None),
            'aids': {x.aid:{} for x in self._cmd.rs.mf.applications.values()},
            'files': {},
        }
        context = {'result': result, 'DF_SKIP': 0, 'DF_SKIP_REASON': []}
        kwargs_export = {'as_json': opts.json}
        exception_str_add = ""

        if opts.filename:
            self.__walk_action(self.__dump_file, opts.filename, context, **kwargs_export)
        else:
            # export an entire subtree
            try:
                self.__walk(0, self.__dump_file, self.__dump_file, context, **kwargs_export)
            except Exception as e:
                print("# Stopping early here due to exception: " + str(e))
                print("#")
                exception_str_add = ", also had to stop early due to exception:" + str(e)
                #raise e

        self._cmd.poutput_json(context['result'])


    def do_desc(self, opts):
        """Display human readable file description for the currently selected file"""
        desc = self._cmd.lchan.selected_file.desc
        if desc:
            self._cmd.poutput("%s: %s" % (self._cmd.lchan.selected_file, desc))
        else:
            self._cmd.poutput("%s: no description available" % self._cmd.lchan.selected_file)
        self._cmd.poutput(" file structure: %s" % self._cmd.lchan.selected_file_structure())
        if isinstance(self._cmd.lchan.selected_file, LinFixedEF):
            self._cmd.poutput(" record length:")
            self._cmd.poutput("  minimum_length: %s" % str(self._cmd.lchan.selected_file.rec_len[0]))
            self._cmd.poutput("  recommended_length: %s" % str(self._cmd.lchan.selected_file.rec_len[1]))
            self._cmd.poutput("  actual_length: %s" % str(self._cmd.lchan.selected_file_record_len()))
            self._cmd.poutput(" number of records: %s" % str(self._cmd.lchan.selected_file_num_of_rec()))
        elif isinstance(self._cmd.lchan.selected_file, TransparentEF):
            self._cmd.poutput(" file size:")
            self._cmd.poutput("  minimum_size: %s" % str(self._cmd.lchan.selected_file.size[0]))
            self._cmd.poutput("  recommended_size: %s" % str(self._cmd.lchan.selected_file.size[1]))
            self._cmd.poutput("  actual_size: %s" % str(self._cmd.lchan.selected_file_size()))
        elif isinstance(self._cmd.lchan.selected_file, BerTlvEF):
            self._cmd.poutput(" file size:")
            self._cmd.poutput("  minimum_size: %s" % str(self._cmd.lchan.selected_file.size[0]))
            self._cmd.poutput("  recommended_size: %s" % str(self._cmd.lchan.selected_file.size[1]))
            self._cmd.poutput("  actual_size: %s" % str(self._cmd.lchan.selected_file_size()))
            self._cmd.poutput("  reserved_file_size: %s" % str(self._cmd.lchan.selected_file_reserved_file_size()))
            self._cmd.poutput("  maximum_file_size: %s" % str(self._cmd.lchan.selected_file_maximum_file_size()))

    verify_adm_parser = argparse.ArgumentParser()
    verify_adm_parser.add_argument('--pin-is-hex', action='store_true',
                                   help='ADM pin value is specified as hex-string (not decimal)')
    verify_adm_parser.add_argument('--adm-type',
                                   choices=[x for x in pin_names.values() if x.startswith('ADM')],
                                   help='Override ADM number. Default is card-model-specific, usually 1')
    verify_adm_parser.add_argument('ADM', nargs='?', type=is_hexstr_or_decimal,
                                   help='ADM pin value. If none given, CSV file will be queried')

    @cmd2.with_argparser(verify_adm_parser)
    def do_verify_adm(self, opts):
        """Verify the ADM (Administrator) PIN specified as argument.  This is typically needed in order
        to get write/update permissions to most of the files on SIM cards.
        """
        if opts.adm_type:
            # pylint: disable=unsubscriptable-object
            adm_chv_num = pin_names.inverse[opts.adm_type]
        else:
            adm_chv_num = self._cmd.card._adm_chv_num
        if opts.ADM:
            # use specified ADM-PIN
            if opts.pin_is_hex:
                pin_adm = sanitize_pin_adm(None, opts.ADM)
            else:
                pin_adm = sanitize_pin_adm(opts.ADM)
        else:
            iccid = self._cmd.rs.identity['ICCID']
            adm_type = opts.adm_type or 'ADM1'
            # try to find an ADM-PIN if none is specified
            result = card_key_provider_get_field(adm_type, key='ICCID', value=iccid)
            if opts.pin_is_hex or (result and len(result) > 8):
                pin_adm = sanitize_pin_adm(None, result)
            else:
                pin_adm = sanitize_pin_adm(result)
            if pin_adm:
                self._cmd.poutput("found %s '%s' for ICCID '%s'" % (adm_type, result, iccid))
            else:
                raise ValueError("cannot find %s for ICCID '%s'" % (adm_type, iccid))

        if pin_adm:
            self._cmd.lchan.scc.verify_chv(adm_chv_num, h2b(pin_adm))
        else:
            raise ValueError("error: cannot authenticate, no adm-pin!")
        self._cmd.rs.adm_verified = True
        self._cmd.update_prompt()

    def do_cardinfo(self, opts):
        """Display information about the currently inserted card"""
        self._cmd.poutput("Card info:")
        self._cmd.poutput(" Name: %s" % self._cmd.card.name)
        self._cmd.poutput(" ATR: %s" % self._cmd.rs.identity['ATR'].lower())
        eid = self._cmd.rs.identity.get('EID', None)
        if eid:
            self._cmd.poutput(" EID: %s" % eid.lower())
        self._cmd.poutput(" ICCID: %s" % self._cmd.rs.identity['ICCID'].lower())
        self._cmd.poutput(" Class-Byte: %s" % self._cmd.lchan.scc.cla_byte.lower())
        self._cmd.poutput(" Select-Ctrl: %s" % self._cmd.lchan.scc.sel_ctrl.lower())
        if len(self._cmd.rs.mf.applications) > 0:
            self._cmd.poutput(" AIDs:")
            for a in self._cmd.rs.mf.applications:
                self._cmd.poutput("  %s" % a.lower())

@with_default_category('ISO7816 Commands')
class Iso7816Commands(CommandSet):
    def __init__(self):
        super().__init__()

    def do_select(self, opts):
        """SELECT a File (ADF/DF/EF)"""
        if len(opts.arg_list) == 0:
            path = self._cmd.lchan.selected_file.fully_qualified_path_str(True)
            path_fid = self._cmd.lchan.selected_file.fully_qualified_path_str(False)
            self._cmd.poutput("currently selected file: %s (%s)" % (path, path_fid))
            return

        path = opts.arg_list[0]
        fcp_dec = self._cmd.lchan.select(path, self._cmd)
        self._cmd.update_prompt()
        self._cmd.poutput_json(fcp_dec)

    def complete_select(self, text, line, begidx, endidx) -> List[str]:
        """Command Line tab completion for SELECT"""
        index_dict = {1: self._cmd.lchan.selected_file.get_selectable_names()}
        return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

    def get_code(self, code, field):
        """Use code either directly or try to get it from external data source using the provided field name"""
        if code is not None:
            return sanitize_pin_adm(code)
        iccid = self._cmd.rs.identity['ICCID']
        result = card_key_provider_get_field(field, key='ICCID', value=iccid)
        result = sanitize_pin_adm(result)
        if result:
            self._cmd.poutput("found %s '%s' for ICCID '%s'" % (field, result, iccid))
        else:
            raise RuntimeError("cannot find %s for ICCID '%s'" % (field, iccid))
        return result

    verify_chv_parser = argparse.ArgumentParser()
    verify_chv_parser.add_argument(
        '--pin-nr', type=int, default=1, help='PIN Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
    verify_chv_parser.add_argument('PIN', nargs='?', type=is_decimal,
                                   help='PIN code value. If none given, CSV file will be queried')

    @cmd2.with_argparser(verify_chv_parser)
    def do_verify_chv(self, opts):
        """Verify (authenticate) using specified CHV (PIN) code, which is how the specifications
        call it if you authenticate yourself using the specified PIN.  There usually is at least PIN1 and
        PIN2."""
        pin = self.get_code(opts.PIN, "PIN" + str(opts.pin_nr))
        (data, sw) = self._cmd.lchan.scc.verify_chv(opts.pin_nr, h2b(pin))
        self._cmd.poutput("CHV verification successful")

    unblock_chv_parser = argparse.ArgumentParser()
    unblock_chv_parser.add_argument(
        '--pin-nr', type=int, default=1, help='PUK Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
    unblock_chv_parser.add_argument('PUK', nargs='?', type=is_decimal,
                                   help='PUK code value. If none given, CSV file will be queried')
    unblock_chv_parser.add_argument('NEWPIN', nargs='?', type=is_decimal,
                                   help='PIN code value. If none given, CSV file will be queried')

    @cmd2.with_argparser(unblock_chv_parser)
    def do_unblock_chv(self, opts):
        """Unblock PIN code using specified PUK code"""
        new_pin = self.get_code(opts.NEWPIN, "PIN" + str(opts.pin_nr))
        puk = self.get_code(opts.PUK, "PUK" + str(opts.pin_nr))
        (data, sw) = self._cmd.lchan.scc.unblock_chv(
            opts.pin_nr, h2b(puk), h2b(new_pin))
        self._cmd.poutput("CHV unblock successful")

    change_chv_parser = argparse.ArgumentParser()
    change_chv_parser.add_argument('NEWPIN', nargs='?', type=is_decimal,
                                   help='PIN code value. If none given, CSV file will be queried')
    change_chv_parser.add_argument('PIN', nargs='?', type=is_decimal,
                                   help='PIN code value. If none given, CSV file will be queried')
    change_chv_parser.add_argument(
        '--pin-nr', type=int, default=1, help='PUK Number, 1=PIN1, 2=PIN2 or custom value (decimal)')

    @cmd2.with_argparser(change_chv_parser)
    def do_change_chv(self, opts):
        """Change PIN code to a new PIN code"""
        new_pin = self.get_code(opts.NEWPIN, "PIN" + str(opts.pin_nr))
        pin = self.get_code(opts.PIN, "PIN" + str(opts.pin_nr))
        (data, sw) = self._cmd.lchan.scc.change_chv(
            opts.pin_nr, h2b(pin), h2b(new_pin))
        self._cmd.poutput("CHV change successful")

    disable_chv_parser = argparse.ArgumentParser()
    disable_chv_parser.add_argument(
        '--pin-nr', type=int, default=1, help='PIN Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
    disable_chv_parser.add_argument('PIN', nargs='?', type=is_decimal,
                                   help='PIN code value. If none given, CSV file will be queried')

    @cmd2.with_argparser(disable_chv_parser)
    def do_disable_chv(self, opts):
        """Disable PIN code using specified PIN code"""
        pin = self.get_code(opts.PIN, "PIN" + str(opts.pin_nr))
        (data, sw) = self._cmd.lchan.scc.disable_chv(opts.pin_nr, h2b(pin))
        self._cmd.poutput("CHV disable successful")

    enable_chv_parser = argparse.ArgumentParser()
    enable_chv_parser.add_argument(
        '--pin-nr', type=int, default=1, help='PIN Number, 1=PIN1, 2=PIN2 or custom value (decimal)')
    enable_chv_parser.add_argument('PIN', nargs='?', type=is_decimal,
                                   help='PIN code value. If none given, CSV file will be queried')

    @cmd2.with_argparser(enable_chv_parser)
    def do_enable_chv(self, opts):
        """Enable PIN code using specified PIN code"""
        pin = self.get_code(opts.PIN, "PIN" + str(opts.pin_nr))
        (data, sw) = self._cmd.lchan.scc.enable_chv(opts.pin_nr, h2b(pin))
        self._cmd.poutput("CHV enable successful")

    def do_deactivate_file(self, opts):
        """Deactivate the currently selected EF"""
        (data, sw) = self._cmd.lchan.scc.deactivate_file()

    activate_file_parser = argparse.ArgumentParser()
    activate_file_parser.add_argument('NAME', type=str, help='File name or FID of file to activate')
    @cmd2.with_argparser(activate_file_parser)
    def do_activate_file(self, opts):
        """Activate the specified EF by sending an ACTIVATE FILE apdu command (used to be called REHABILITATE
        in TS 11.11 for classic SIM).

        This command is used to (re-)activate a file that is currently in deactivated (sometimes also called
        "invalidated") state.  You need to call this from the DF above the to-be-activated EF and specify the name or
        FID of the file to activate.

        Note that for *deactivation* the to-be-deactivated EF must be selected, but for *activation*, the DF
        above the to-be-activated EF must be selected!"""
        (data, sw) = self._cmd.lchan.activate_file(opts.NAME)

    def complete_activate_file(self, text, line, begidx, endidx) -> List[str]:
        """Command Line tab completion for ACTIVATE FILE"""
        index_dict = {1: self._cmd.lchan.selected_file.get_selectable_names()}
        return self._cmd.index_based_complete(text, line, begidx, endidx, index_dict=index_dict)

    open_chan_parser = argparse.ArgumentParser()
    open_chan_parser.add_argument(
        'chan_nr', type=int, default=1, choices=range(1,16), help='Channel Number')

    @cmd2.with_argparser(open_chan_parser)
    def do_open_channel(self, opts):
        """Open a logical channel."""
        (data, sw) = self._cmd.lchan.scc.manage_channel(
            mode='open', lchan_nr=opts.chan_nr)
        # this is executed only in successful case, as unsuccessful raises exception
        self._cmd.lchan.add_lchan(opts.chan_nr)

    close_chan_parser = argparse.ArgumentParser()
    close_chan_parser.add_argument(
        'chan_nr', type=int, default=1, choices=range(1,16), help='Channel Number')

    @cmd2.with_argparser(close_chan_parser)
    def do_close_channel(self, opts):
        """Close a logical channel."""
        (data, sw) = self._cmd.lchan.scc.manage_channel(
            mode='close', lchan_nr=opts.chan_nr)
        # this is executed only in successful case, as unsuccessful raises exception
        self._cmd.rs.del_lchan(opts.chan_nr)

    switch_chan_parser = argparse.ArgumentParser()
    switch_chan_parser.add_argument(
        'chan_nr', type=int, default=0, choices=range(0,16), help='Channel Number')

    @cmd2.with_argparser(switch_chan_parser)
    def do_switch_channel(self, opts):
        """Switch currently active logical channel."""
        self._cmd.lchan.unregister_cmds(self._cmd)
        self._cmd.lchan = self._cmd.rs.lchan[opts.chan_nr]
        self._cmd.lchan.register_cmds(self._cmd)
        self._cmd.update_prompt()

    def do_status(self, opts):
        """Perform the STATUS command."""
        fcp_dec = self._cmd.lchan.status()
        self._cmd.poutput_json(fcp_dec)


class Proact(ProactiveHandler):
    def receive_fetch(self, pcmd: ProactiveCommand):
        # print its parsed representation
        print(pcmd.decoded)
        # TODO: implement the basics, such as SMS Sending, ...



option_parser = argparse.ArgumentParser(description='interactive SIM card shell',
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
argparse_add_reader_args(option_parser)

global_group = option_parser.add_argument_group('General Options')
global_group.add_argument('--script', metavar='PATH', default=None,
                          help='script with pySim-shell commands to be executed automatically at start-up')
global_group.add_argument('--csv', metavar='FILE',
                          default=None, help='Read card data from CSV file')
global_group.add_argument('--csv-column-key', metavar='FIELD:AES_KEY_HEX', default=[], action='append',
                          help='per-CSV-column AES transport key')
global_group.add_argument("--card_handler", dest="card_handler_config", metavar="FILE",
                          help="Use automatic card handling machine")
global_group.add_argument("--noprompt", help="Run in non interactive mode",
                          action='store_true', default=False)
global_group.add_argument("--skip-card-init", help="Skip all card/profile initialization",
                          action='store_true', default=False)

adm_group = global_group.add_mutually_exclusive_group()
adm_group.add_argument('-a', '--pin-adm', metavar='PIN_ADM1', dest='pin_adm', default=None,
                       help='ADM PIN used for provisioning (overwrites default)')
adm_group.add_argument('-A', '--pin-adm-hex', metavar='PIN_ADM1_HEX', dest='pin_adm_hex', default=None,
                       help='ADM PIN used for provisioning, as hex string (16 characters long)')

option_parser.add_argument('-e', '--execute-command', action='append', default=[],
                           help='A pySim-shell command that will be executed at startup')
option_parser.add_argument("command", nargs='?',
                           help="A pySim-shell command that would optionally be executed at startup")
option_parser.add_argument('command_args', nargs=argparse.REMAINDER,
                           help="Optional Arguments for command")


if __name__ == '__main__':

    startup_errors = False
    opts = option_parser.parse_args()

    # Register csv-file as card data provider, either from specified CSV
    # or from CSV file in home directory
    csv_column_keys = {}
    for par in opts.csv_column_key:
        name, key = par.split(':')
        csv_column_keys[name] = key
    csv_default = str(Path.home()) + "/.osmocom/pysim/card_data.csv"
    if opts.csv:
        card_key_provider_register(CardKeyProviderCsv(opts.csv, csv_column_keys))
    if os.path.isfile(csv_default):
        card_key_provider_register(CardKeyProviderCsv(csv_default, csv_column_keys))

    # Init card reader driver
    sl = init_reader(opts, proactive_handler = Proact())

    # Create a card handler (for bulk provisioning)
    if opts.card_handler_config:
        ch = CardHandlerAuto(None, opts.card_handler_config)
    else:
        ch = CardHandler(sl)

    # Detect and initialize the card in the reader. This may fail when there
    # is no card in the reader or the card is unresponsive. PysimApp is
    # able to tolerate and recover from that.
    try:
        rs, card = init_card(sl, opts.skip_card_init)
        app = PysimApp(card, rs, sl, ch)
    except:
        startup_errors = True
        print("Card initialization (%s) failed with an exception:" % str(sl))
        print("---------------------8<---------------------")
        traceback.print_exc()
        print("---------------------8<---------------------")
        if not opts.noprompt:
            print("(you may still try to recover from this manually by using the 'equip' command.)")
            print(" it should also be noted that some readers may behave strangely when no card")
            print(" is inserted.)")
            print("")
        app = PysimApp(None, None, sl, ch)

    # If the user supplies an ADM PIN at via commandline args authenticate
    # immediately so that the user does not have to use the shell commands
    pin_adm = sanitize_pin_adm(opts.pin_adm, opts.pin_adm_hex)
    if pin_adm:
        if not card:
            print("Card error, cannot do ADM verification with supplied ADM pin now.")
        try:
            card._scc.verify_chv(card._adm_chv_num, h2b(pin_adm))
        except Exception as e:
            startup_errors = True
            print("ADM verification (%s) failed with an exception:" % str(pin_adm))
            print("---------------------8<---------------------")
            print(e)
            print("---------------------8<---------------------")

    # Run optional commands
    for c in opts.execute_command:
        if not startup_errors:
            stop = app.onecmd_plus_hooks(c)
            if stop == True:
                sys.exit(0)
        else:
            print("Errors during startup, refusing to execute command (%s)" % c)

    # Run optional command
    if opts.command:
        if not startup_errors:
            stop = app.onecmd_plus_hooks('{} {}'.format(opts.command, ' '.join(opts.command_args)))
            if stop == True:
                sys.exit(0)
        else:
            print("Errors during startup, refusing to execute command (%s)" % opts.command)

    # Run optional script file
    if opts.script:
        if not startup_errors:
            if not os.access(opts.script, os.R_OK):
                print("Error: script file (%s) not readable!" % opts.script)
                startup_errors = True
            else:
                stop = app.onecmd_plus_hooks('{} {}'.format('run_script', opts.script), add_to_history = False)
                if stop == True:
                    sys.exit(0)
        else:
            print("Errors during startup, refusing to execute script (%s)" % opts.script)

    if not opts.noprompt:
        app.cmdloop()
    elif startup_errors:
        sys.exit(2)
