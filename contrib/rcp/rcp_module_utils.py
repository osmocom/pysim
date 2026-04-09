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


import abc
import os
import argparse
import logging
import threading
import asyncio
import websockets
from argparse import Namespace
from copy import deepcopy
from pathlib import Path
from typing import Optional
from osmocom.utils import Hexstr, is_hexstr
from pySim.utils import ResTuple
from pySim.transport import LinkBase
from pySim.commands import SimCardCommands
from pySim.log import PySimLogger
from rcp_utils import SrvSyncConnHdlr, CltConnHdlr, backtrace, pytype_to_type, load_server_cert, load_ca_cert
from rcp_utils import dict_from_key_value_pairs
from websockets.sync.server import serve, ServerConnection

# Response timeout towards the RCP Server (includes RCP Client latency)
RCP_SERVER_TIMEOUT = 30 # sec.

log = PySimLogger.get(Path(__file__).stem)

class RcpsSimLink(LinkBase):
    """
    pySim: Transport Link for RCPM (Remote Card Procedure Module)
    This is a 'headless' transport link implementation that can only be used from an RCPM module. It merely serves as
    an adapter between the pySim transport API and the RCPM command server connection handler.
    """

    name = 'RCPM'

    def __init__(self, conn_hdlr: SrvSyncConnHdlr, **kwargs):
        self.conn_hdlr = conn_hdlr
        self._atr = None
        super().__init__(**kwargs)

    def __str__(self) -> str:
        return "rcpm:" + str(self.conn_hdlr)

    def _send_apdu(self, apdu: Hexstr) -> ResTuple:
        tx_json = {'rcpc_instr': {'c_apdu' : apdu.upper()}}
        rx_json = self.conn_hdlr._transact(tx_json)
        data = rx_json['rcpc_result']['r_apdu']['data']
        sw = rx_json['rcpc_result']['r_apdu']['sw']
        return data, sw

    def wait_for_card(self, timeout: Optional[int] = None, newcardonly: bool = False):
        # In this setting, we do not have/cannot to wait for a card since we are not the entity that handles the
        # direct connection to the card. When the procedure begins, we assume that the remote end already has set up
        # a connection to the card and made it ready to perform operations on it.
        pass

    def connect(self):
        # In this setting, we do not have/cannot to connect because we are not the entity that handles the direct
        # connection to the card. The connection is established by the remote end.
        pass

    def get_atr(self) -> Hexstr:
        return self._atr

    def disconnect(self):
        # In this setting, we do not have/cannot disconnect because we are not the enitity that handles the direct
        # connection to the card. The disconnect is eventually done by the remote end when the procedure has finished.
        pass

    def _reset_card(self):
        tx_json = {'rcpc_instr': {'reset' : None}}
        rx_json = self.conn_hdlr._transact(tx_json)
        self._atr = rx_json['rcpc_result']['atr']
        return 1

class RcpsCltConnHdlr(CltConnHdlr):
    """
    The RCP Server client handler is used to connect to the RCP Server when RCP Module is started. The connection is
    kept alive until the RCP Module is terminated. This connection is used to exchange management data with the RCP
    Server.
    """

    def __init__(self, cmd_srv_addr: str, cmd_srv_port: int, module, *args, **kwargs):
        self.cmd_srv_addr = cmd_srv_addr
        self.cmd_srv_port = cmd_srv_port
        self.module = module
        super().__init__(*args, **kwargs)

    async def describe(self):
        """
        Send a detailed description about this RCP Module to the RCP Server. This is also the initial message that
        the RCP Server expects when an RCP Module connects.
        """

        # The rules (dict) in suitable_for (array of dict) may contain hexstrings. Here we go through those rules
        # and convert those hexstrings to uppercase, since this is the standard we have set for the JSON messages.
        suitable_for = []
        for rule in self.module.suitable_for:
            rule_filtered = {}
            for k in rule:
                if is_hexstr(rule[k]):
                    rule_filtered[k] = rule[k].upper()
                else:
                    rule_filtered[k] = rule[k]
            suitable_for.append(rule_filtered)

        # Publish RCP Module description on the RCP server
        tx_json = {'rcpm_hello':
                   {'name' : self.module.name,
                    'cmd_descr' : self.module.cmd_descr,
                    'suitable_for' : suitable_for,
                    'retrieve_keys' : {
                        'euicc' : self.module.retrieve_euicc_keys,
                        'uicc' : self.module.retrieve_uicc_keys
                    },
                    'addr' : self.cmd_srv_addr,
                    'port' : self.cmd_srv_port
                    }
                   }
        rx_json = await self._transact(tx_json)
        if 'rcpm_welcome' not in rx_json:
            raise ValueError("description not accepted by RCP Server")

class RcpModule(abc.ABC):
    """
    Base class to implement to derive a concrete RCPM module class
    """

    # Module name used to identify the module in logs and user output. This module name should be short and concise.
    name = "RCPM"

    # Command description of this module. The command description consists of a short and concise command name, a
    # helpstring and an argument specification in the form of a python dict. This specificaton dict is directly
    # passed to agparse on the client side.
    #
    # Example:
    # [{"name" : "reset",
    #  "help": "reset the card",
    #  "args" : []},
    # {"name" : "read_binary",
    #  "help": "read binary data from a transparent file.",
    #  "args" : [ { "name" : "--fid",
    #               "spec" : {"required" : True,
    #                         "help" : "File identifier to of the file to read",
    #                         "action" : "append"},
    #              }
    #            ]}
    # ]
    cmd_descr = []

    # List with UICC (or eSIM) keys (columns) that the RCP Server shall retrieve before a command is executed.
    # Execution will not continue in case any of the requested keys is not found.
    # (see also: pySim.card_key_provider)
    #
    # Example: ['kic1', 'kid1', 'kik1']
    retrieve_uicc_keys = []

    # Same as retrieve_uicc_keys (see above), but only applicable with eUICCs
    #
    # Example: ['isdr_kic1', 'isdr_kid1', 'isdr_kik1']
    retrieve_euicc_keys = []

    # Card properties to determine if this module is suitable for a specific card type or card types. The RCP Server
    # will match those properties against user requests to determine which module provides useful services to the
    # user's card.
    #
    # Example: [{"atr" : "3b9f96803f87828031e073fe211f574543753130136502"}]
    suitable_for = []

    # In addition the above, the derived class must implement command methods for each command that is defined in the
    # command description (see above). Each command method must begin with the prefix "cmd_" followed by the command
    # name used in the command description. A command method must have the form as shown in the example shown below.
    # Each method should return an integer value which will become the final return code of the RCP client program.
    #
    # Args:
    #     hdlr:     RcpModuleHdlr object, this object is provided by the RcpmCmdSrvConnHdlr object, which calls
    #               the command method of the module. Through the RcpModuleHdlr object, the API user gets access
    #               to special service methods (e.g. print) and other required properties (e.g. the SimCardCommands
    #               objects, key material and others (see above).
    #
    # Example:
    # def cmd_reset(self, hdlr: RcpModuleHdlr) -> int: ...
    # def cmd_read_binary(self, hdlr: RcpModuleHdlr) -> int: ...

class RcpmCmdSrvConnHdlr(SrvSyncConnHdlr):
    """
    The RCP Module command server connection handler is used to handle dedicated connections from the RCP Server. Those
    dedicated connections are technically transparent connections between the RCP Client and the RCP Module (this). The
    RCP Server merely acts as a proxy at that point.
    """

    def __init__(self, module: RcpModule, *args, **kwargs):
        SrvSyncConnHdlr.__init__(self, *args, *kwargs)
        self.module = module

    def _parse_cmd_argv(self, cmd_suffix: str, cmd_argv: list[str]) -> Namespace:
        """ Parse (and validate) the received argument vector """
        # Use the cmd_descr of the module to create a (temporary) argument parser for the received argument vector
        cmd_parser = argparse.ArgumentParser()
        for cmd in self.module.cmd_descr:
            if cmd['name'] == cmd_suffix:
                args = deepcopy(cmd['args'])
                for arg in args:
                    arg['spec'] = pytype_to_type(arg['spec'])
                    cmd_parser.add_argument(arg['name'], **arg['spec'])

        # Parse the arguments and return the parsed Namespace object.
        try:
            return cmd_parser.parse_args(cmd_argv)
        except SystemExit:
            raise ValueError("unable to parse arguments: %s", str(cmd_argv), )

    def print(self, message: str):
        """ Print a message on the client side """
        log.info(str(self) + " -- %s" % message)
        tx_json = {'rcpc_instr': {'print' : message}}
        rx_json = self._transact(tx_json)
        if rx_json != {'rcpc_result': {'empty' : None}}:
            raise ValueError("unexpected response from RCP Client: %s", rx_json)

    def procedure(self):
        """ Receive and process a command from the RCP Client (via RCP Server) """

        # Receive the command request
        rx_json = self._recv()
        cmd = rx_json['rcpc_command']['cmd']
        cmd_argv = rx_json['rcpc_command']['cmd_argv']
        keys = rx_json['rcpc_command']['keys']
        keys_uicc = dict_from_key_value_pairs(keys['uicc'], keylabel='key', valuelabel='value')
        keys_euicc = dict_from_key_value_pairs(keys['euicc'], keylabel='key', valuelabel='value')

        log.info(str(self) + " -- executing command: %s %s", cmd, " ".join(cmd_argv))

        try:
            # Make sure the command actually addresses this module
            cmd_prefix = self.module.name + "_"
            if not cmd.startswith(cmd_prefix):
                raise ValueError("invalid command: %s" % cmd)

            # Make sure the module actually provides a command method for the requested command
            cmd_suffix = cmd[len(cmd_prefix):]
            cmd_method = "cmd_" + cmd_suffix
            if not hasattr(self.module, cmd_method):
                raise ValueError("missing command method: %s" % cmd_method)

            # Parse and validate command arguments
            cmd_args = self._parse_cmd_argv(cmd_suffix, cmd_argv)

            # TODO: Perform a proper setup, similar to the one we have in pySim-shell, so that we have proper
            # runtime states and full access to the pySim API
            self.scc = SimCardCommands(transport=RcpsSimLink(self))
            self.scc.cla_byte = "00"
            self.scc.sel_ctrl = "0004"

            # Hand over control to the command method provided by the specific module implementation
            try:
                rcp_module_hdlr = RcpModuleHdlr(self, cmd_args, keys_uicc, keys_euicc)
                rc = getattr(self.module, cmd_method)(rcp_module_hdlr)
            except Exception as e:
                backtrace("command method")
                rc = 1 # general error

        except Exception as e:
            backtrace("command parsing")
            rc = 126 # cannot execute

        # The prodedure is done, send "goodbye" message
        log.info(str(self) + " -- command execution done, rc: %d" % rc)
        tx_json = {'rcpc_goodbye': rc}
        self._send(tx_json)

class RcpModuleHdlr():
    """
    RCP Module handler class. This class is used by the RcpmCmdSrvConnHdlr to create the handler RcpModuleHdlr object
    (hdlr), which is is passed to the command method. The RcpModuleHdlr gives the API user access to resources he can
    use carry out the command.
    """

    # The scc property contains the SimCardCommands object may be used to send APDUs, retrieve the ATR, or even more
    # complex tasks like selecting a file (see also pysim.commands)
    scc = None

    # The cmd_args property contains the parsed command arguments which were passed by the end-user to the RCP Client.
    # The arguments are already parsed and validated against the cmd_dscr property of the RcpModule. The arguments are
    # in the form of a Namespace object and can be accessed like any argparse output. However, since the arguments
    # contain user input, some caution is required.
    cmd_args = None

    # In case the retrieve_uicc_keys property of the RcpModule is used retrieve UICC key material, this property will
    # contain the key material in the form of a dictionary. The format is similar to the return value of
    # card_key_provider_get() (see also pySim.card_key_provider)
    keys_uicc = {}

    # Same as self.keys_uicc, but contains eUICC related key material in case requested using retrieve_uicc_keys
    keys_euicc = {}

    def __init__(self, hdlr: RcpmCmdSrvConnHdlr, cmd_args: Namespace, keys_uicc: dict, keys_euicc: dict):
        # The command method (API user) must not access the related RcpmCmdSrvConnHdlr (see below) directly. Only
        # the resources below may be accessed.
        self.__hdlr = hdlr

        # Assign properties intended to be used by the command method (API user)
        self.scc = self.__hdlr.scc
        self.cmd_args = cmd_args
        self.keys_uicc = keys_uicc
        self.keys_euicc = keys_euicc

    def print(self, message: str):
        """ Print a message on the client side """
        self.__hdlr.print(message)

def rcpm_setup_argparse(description: str):
    """Create argument parser and add the basic arguments all RCP Modules should have"""

    option_parser = argparse.ArgumentParser(description='RCP Module: ' + description,
                                            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    option_parser.add_argument("--verbose", help="Enable verbose logging", action='store_true', default=False)
    option_parser.add_argument("--uri", help="URI of the RCP-Server", required=True)
    option_parser.add_argument("--rcps-ca-cert", help="SSL/TLS CA-Certificate of the RCP-Server", required=True)
    option_parser.add_argument("--rcpm-cmd-server-addr", help="Local Host/IP to bind RCP-Module-Command-Server to",
                               required=True)
    option_parser.add_argument("--rcpm-cmd-server-port", help="Local TCP port to bind RCP-Module-Command-Server to",
                               required=True, type=int)
    option_parser.add_argument("--rcpm-cmd-server-cert", help="SSL/TLS Certificate of the RCP-Module-Command-Server",
                               required=True)
    return option_parser

def rcpm_run_module(opts: Namespace, module: RcpModule, *args, **kwargs):

    PySimLogger.setup(print, {logging.WARN: "\033[33m", logging.DEBUG: "\033[90m"}, opts.verbose)
    log.info("RCP Module startup: %s", module.name)
    log.debug("Main process ID: %d", os.getpid())

    # Load SSL/TLS certificates
    rcpm_cmd_ssl_context = load_server_cert("RCPM Command Server", opts.rcpm_cmd_server_cert)
    ssl_context = load_ca_cert("RCPM Server Client", opts.rcps_ca_cert)

    # Start local RCP Client Command Server
    log.info("RCPC command server at: %s:%d" % (opts.rcpm_cmd_server_addr, opts.rcpm_cmd_server_port))
    def rcpm_cmd_conn_hdlr(websocket: ServerConnection):
        hdlr = RcpmCmdSrvConnHdlr(module(*args, *kwargs), websocket, RCP_SERVER_TIMEOUT)
        hdlr.procedure()
        hdlr.close()

    server = serve(rcpm_cmd_conn_hdlr, opts.rcpm_cmd_server_addr, opts.rcpm_cmd_server_port, ssl=rcpm_cmd_ssl_context)
    def rcpm_cmd_server():
        log.debug("RCPC command server thread ID: %d", threading.get_native_id())
        server.serve_forever()
    rcpm_cmd_server_thread = threading.Thread(target = rcpm_cmd_server)
    rcpm_cmd_server_thread.start()

    # Connect to RCP Server and publish module description
    async def rcps_client():
        async with websockets.connect(opts.uri, ping_timeout=10.0, ping_interval=1.0, ssl=ssl_context) as websocket:
            client = RcpsCltConnHdlr(opts.rcpm_cmd_server_addr, opts.rcpm_cmd_server_port, module, websocket,
                                     RCP_SERVER_TIMEOUT)
            await client.describe()
            await client.wait_close()
    try:
        asyncio.run(rcps_client())
    except Exception as e:
        backtrace("RCPS client")

    # Shutdown
    server.shutdown()
    rcpm_cmd_server_thread.join()
    log.info("RCP Module shutdown: %s", module.name)
