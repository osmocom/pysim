#!/usr/bin/env python3

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier
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

import sys
import websockets
import asyncio
import argparse
import logging
from copy import deepcopy
from pathlib import Path
from pySim.log import PySimLogger
from rcp_utils import CltConnHdlr, backtrace, pytype_to_type, load_ca_cert
from pySim.transport import init_reader, argparse_add_reader_args, LinkBase

SERVER_TIMEOUT = 10

log = PySimLogger.get(Path(__file__).stem)
option_parser = argparse.ArgumentParser(description='RCP Client',
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
argparse_add_reader_args(option_parser)
option_parser.add_argument("--verbose", help="Enable verbose logging",
                           action='store_true', default=False)
option_parser.add_argument("--uri", help="URI of the RCP-Server")
option_parser.add_argument("--ca-cert", help="SSL/TLS CA-Certificate of the RCP-Server")

class RcpcCltConnHdlr(CltConnHdlr):
    def __init__(self, sl, *args, **kwargs):
        self.sl = sl
        super().__init__(*args, **kwargs)

    async def describe(self, suitable_for:dict) -> list:
        log.info("Requesting module descriptions from RCP Server ...")
        tx_json = {'rcpc_hello': {'suitable_for' : suitable_for}}
        rx_json = await self._transact(tx_json)
        module_descr = rx_json['rcpc_welcome']['module_descr']
        if not module_descr:
            raise ValueError("No RCP module available for this card")
        return module_descr

    async def run(self, cmd:str, cmd_argv) -> int:
        log.info("Executing command with RCP Server ...")
        tx_json = {'rcpc_command': {'cmd' : cmd, 'cmd_argv' : cmd_argv}}
        while(True):
            rx_json = await self._transact(tx_json)
            tx_json = None
            if 'rcpc_instr' in rx_json:
                rcpc_instr = rx_json['rcpc_instr']
                if 'c_apdu' in rcpc_instr:
                    c_apdu = rx_json['rcpc_instr']['c_apdu']
                    data, sw = sl.send_apdu(c_apdu)
                    tx_json = {'rcpc_result': {'r_apdu' : {'data': data.upper(), 'sw': sw.upper()}}}
                elif 'reset' in rcpc_instr:
                    sl.reset_card()
                    atr = sl.get_atr()
                    tx_json = {'rcpc_result': {'atr' : atr.upper()}}
                elif 'print' in rcpc_instr:
                    log.info(str(self) + " -- %s", rx_json['rcpc_instr']['print'])
                    tx_json = {'rcpc_result': {'empty' : None}}
            elif 'rcpc_goodbye' in rx_json:
                rc = rx_json['rcpc_goodbye']
                log.info("Command execution done, rc: %d", rc)
                return rc

def check_if_user_needs_basic_help(argv):
    """
    The '--uri' argument is the minimum requirement to connect to the RCP Server to retrieve the information about the
    dynamic commandline arguments. In case this argument is missing while '--help' or '-h' arguments are present. Then
    we will fall back to display only a basic help that contains only the static commandline arguments (see above).
    """

    if '--help' in argv or '-h' in argv:
        if '--uri' not in argv:
            option_parser.parse_args()
            sys.exit(1)

def parse_known_arguemnts(argv):
    """
    Parse the commandline arguments we know so far. Ignore unknown arguments and filter out '--help' and '-h'
    arguments, in case those are present.
    """

    argv_filtered = deepcopy(argv)
    if '--help' in argv_filtered:
        argv_filtered.remove('--help')
    if '-h' in argv_filtered:
        argv_filtered.remove('-h')
    opts, unknown = option_parser.parse_known_args(argv_filtered)
    return opts

async def run_rcp_session(opts, sl, ssl_context) -> int:
    """
    Connect to the RCP Server, retrieve the module description, use the module description to complete the commandline
    argument parser, execute the command that the user has selected.
    """

    # Request ATR from card
    card_atr = sl.get_atr().upper()
    log.info("Detected Card with ATR: %s" % card_atr)

    # Connect to RCP server
    log.info("RCP Server URI: %s" % opts.uri)
    async with websockets.connect(opts.uri, ssl=ssl_context) as websocket:
        client = RcpcCltConnHdlr(sl, websocket, SERVER_TIMEOUT)

        # Retrieve module description
        module_descrs = await client.describe({"atr" : card_atr})

        # Complete the commandlie parser and set up a dict that we can use as filter
        # TODO: Maybe it makes sense to integrate this as a method into the RcpcCltConnHdlr class?
        option_subparsers = option_parser.add_subparsers(dest='command', help="RCP command to use", required=True)
        sys_argv_filter = {}
        for module_descr in module_descrs:
            cmd_descr = module_descr['cmd_descr']
            for cmd in cmd_descr:
                command_name = module_descr['name'] + "_" + cmd['name']
                option_parser_cmd = option_subparsers.add_parser(command_name, help=cmd['help'])
                sys_argv_filter[command_name] = []
                for arg in cmd['args']:
                    arg['spec'] = pytype_to_type(arg['spec'])
                    option_parser_cmd.add_argument(arg['name'], **arg['spec'])
                    sys_argv_filter[command_name].append(arg['name'])

        # Re-Parse commandline options with the completed commandline parser. In case commandline help is
        # requested. The program is able to display the full helpscreen and exists.
        opts = option_parser.parse_args()

        # Filter the relevant command arguments from sys.argv
        cmd_argv = []
        next_is_value=False
        for arg in sys.argv:
            if arg in sys_argv_filter[opts.command]:
                cmd_argv.append(arg)
                next_is_value=True
            elif next_is_value is True:
                next_is_value=False
                cmd_argv.append(arg)

        # Run the command and close the connection
        rc = await client.run(opts.command, cmd_argv)
        await client.close()
        return rc

if __name__ == '__main__':

    # Setup logging
    PySimLogger.setup(print, {logging.WARN: "\033[33m", logging.DEBUG: "\033[90m"}, '--verbose' in sys.argv)

    # Since parts of the commandline arguments are retrieved dynamically, we have to resolve a chicken-egg-problem.
    # We cannot call option_parser.parse_args() at the beginning, since we haven't received all information to
    # complete the option_parser yet. However in order to retrieve the arguments correctly we need to get the
    # URI and the parameters for the smartcard reader before we make the connection. The situation is even further
    # complicated in case the user requests commandline help.

    # To resolve the problem we first check if the user needs basic help (no '--uri' parameter present). If this is the
    # case, the program will exit with a basic helpscreen.
    check_if_user_needs_basic_help(sys.argv)

    # In all other cases we parse the arguments we know so far. In case the user requests commandline help, we will
    # ignore this request and continue. The full help is then displayed later when the option_parser is completed
    # afer we have requested the commandline argument descriptions from the RCP Server. (see below)
    opts = parse_known_arguemnts(sys.argv)

    # Load SSL/TLS CA certificate from file
    if opts.ca_cert:
        ssl_context = load_ca_cert("RCP Server CA", opts.ca_cert)
    else:
        ssl_context = None

    # Initialize card reader
    try:
        sl = init_reader(opts)
        sl.connect()
    except Exception as e:
        backtrace("Card reader initialization")
        sys.exit(1)

    # Run the RCP session
    try:
        rc = asyncio.run(run_rcp_session(opts, sl, ssl_context))
        sys.exit(rc)
    except SystemExit as rc:
        sys.exit(rc)
    except:
        backtrace("RCP session")
        sys.exit(1)


