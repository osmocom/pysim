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
from rcp_utils import dict_from_key_value_pairs, load_json_schema, JsonValidator
from rcp_server import RCPM_VERSION_PROTOCOL
from websockets.sync.server import serve, ServerConnection
from pySim.app import init_card
from pySim.runtime import RuntimeState
from pySim.cards import CardBase
from pySim.card_key_provider import CardKeyFieldCryptor
from packaging.version import Version

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
        tx_json = {'rcps_instr': {'c_apdu' : apdu.upper()}}
        rx_json = self.conn_hdlr._transact(tx_json)
        data = rx_json['rcps_result']['r_apdu']['data']
        sw = rx_json['rcps_result']['r_apdu']['sw']
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
        # In this setting, we do not have/cannot disconnect because we are not the entity that handles the direct
        # connection to the card. The disconnect is eventually done by the remote end when the procedure has finished.
        pass

    def _reset_card(self):
        tx_json = {'rcps_instr': {'reset' : None}}
        rx_json = self.conn_hdlr._transact(tx_json)
        self._atr = rx_json['rcps_result']['atr']
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

    async def check_version(self):
        """
        Send the Protocol and Software version of this RCP Module to the RCP Server. The RCP Server and the RCP Module
        must always use the same protrocol version.
        """
        tx_json = {'rcpm_version': {'protocol' : RCPM_VERSION_PROTOCOL}}
        rx_json = await self._transact(tx_json)
        rcpm_version_protocol = Version(rx_json['rcpm_version']['protocol'])
        if Version(RCPM_VERSION_PROTOCOL) != rcpm_version_protocol:
            raise ValueError("Incompatible protocol version %s != %s", Version(RCPM_VERSION_PROTOCOL), rcpm_version_protocol)

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
                    'addr' : self.cmd_srv_addr,
                    'port' : self.cmd_srv_port
                    }
                   }
        rx_json = await self._transact(tx_json)
        if 'rcpm_welcome' not in rx_json:
            raise ValueError("description not accepted by RCP Server")

class RcpModule(abc.ABC):
    """
    Base class to implement to derive a concrete RCP module class
    """

    # Module name used to identify the module in logs and user output. This module name should be short and concise.
    name = "RCPM"

    # Command description of this module. The command description consists of a short and concise command name, a
    # helpstring and an argument specification in the form of a python dict. This specification, consisting of
    # 'name', 'help', and 'args' is is directly passed to agparse on the client side.
    #
    # In addition to that, the API user may specify which keys the RCP Server shall retrieve before a command is
    # executed. This is done via the 'get_keys' field. This field is optional and has the form of a dict with
    # two optional fields 'uicc' and 'euicc'. The value part of both fields is a list of strings which name the
    # columns that are passed to the CardKeyProvider for lookup. When the 'uicc' field is set, then the RCP Server
    # will automatically request the ICCID from the card and do the lookup. When the 'euicc' field is set, the RCP
    # Server will do the same with the EID. It is possible to mix both fields to request keys for the eUICC and the
    # currently activated eSIM profile at the same time. However, this may be a very rare corner case.
    #
    # Example:
    # cmd_descr = [{'name' : 'reset',
    #               'help': 'reset the card',
    #               'args' : []},
    #              {'name' : 'read_binary',
    #               'help': 'read binary data from a transparent file.',
    #               'args' : [{ 'name' : '--fid',
    #                            'spec' : {'required' : True,
    #                                      'help' : 'File identifier to of the file to read',
    #                                      'action' : 'append',
    #                                      'pytype' : 'str'},
    #                         }
    #                        ]},
    #              {'name' : 'unlock_aram',
    #               'help': 'unlock a locked ARA-M applet on a sysmoISIM-SJA5',
    #               'args' : [],
    #               'get_keys' : {'uicc' : ['KIC', 'KID', 'KIK']}}
    #              ]
    cmd_descr = []

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
    #               objects, key material and others (see RcpModuleHdlr).
    #
    # Example:
    # def cmd_reset(self, hdlr: RcpModuleHdlr) -> int: ...
    # def cmd_read_binary(self, hdlr: RcpModuleHdlr) -> int: ...
    # def cmd_unlock_aram(self, hdlr: RcpModuleHdlr) -> int: ...

    # When the RCP Module class is passed to rcpm_run_module(), rcpm_run_module() also accepts *args and **kwargs
    # parameter. Those parameters are passed to the constructor of RCP Module class when it is instaniated by
    # rcpm_run_module(). API may override this constructor (below) with a custom implementation, if required.
    def __init__(self, *args, **kwargs):
        pass

class RcpmCmdSrvConnHdlr(SrvSyncConnHdlr):
    """
    The RCP Module command server connection handler is used to handle dedicated connections from the RCP Server. Those
    dedicated connections are technically transparent connections between the RCP Client and the RCP Module (this). The
    RCP Server merely acts as a proxy at that point.
    """

    def __init__(self, module: RcpModule, field_cryptor: CardKeyFieldCryptor, *args, **kwargs):
        SrvSyncConnHdlr.__init__(self, *args, *kwargs)
        self.module = module
        self.crypt = field_cryptor

    def _parse_cmd_argv(self, cmd_suffix: str, cmd_argv: list[str]) -> Namespace:
        """ Parse (and validate) the received argument vector """
        # Use the cmd_descr of the module to create a (temporary) argument parser for the received argument vector.
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
        tx_json = {'rcps_instr': {'print' : message}}
        rx_json = self._transact(tx_json)
        if rx_json != {'rcps_result': {'empty' : None}}:
            raise ValueError("unexpected response from RCP Client: %s", rx_json)

    def procedure(self):
        """ Receive and process a command from the RCP Client (via RCP Server) """

        # Receive the command request.
        rx_json = self._recv()
        cmd = rx_json['rcps_command']['cmd']
        cmd_argv = rx_json['rcps_command']['cmd_argv']
        keys = rx_json['rcps_command'].get('keys')
        log.info(str(self) + " -- executing command: %s %s", cmd, str(cmd_argv))

        try:
            # Make sure the command actually addresses this module.
            cmd_prefix = self.module.name + "_"
            if not cmd.startswith(cmd_prefix):
                raise ValueError("invalid command: %s" % cmd)

            # Make sure the module actually provides a command method for the requested command.
            cmd_suffix = cmd[len(cmd_prefix):]
            cmd_method = "cmd_" + cmd_suffix
            if not hasattr(self.module, cmd_method):
                raise ValueError("missing command method: %s" % cmd_method)

            # Parse and validate command arguments.
            cmd_args = self._parse_cmd_argv(cmd_suffix, cmd_argv)

            # Setup a pySim RuntimeState, CardBase and a RuntimeLchan.
            rs, card = init_card(RcpsSimLink(self))

            # Hand over control to the command method provided by the specific module implementation.
            rcp_module_hdlr = RcpModuleHdlr(self.print, rs, card, cmd_args, keys, self.crypt)
            rs.reset()
            try:
                rc = getattr(self.module, cmd_method)(rcp_module_hdlr)
            except Exception as e:
                backtrace("command method")
                rc = 1 # general error

        except Exception as e:
            backtrace("command parsing")
            rc = 126 # cannot execute

        # The prodedure is done, send "goodbye" message.
        log.info(str(self) + " -- command execution done, rc: %d" % rc)
        tx_json = {'rcps_goodbye': rc}
        self._send(tx_json)

class RcpModuleHdlr():
    """
    RCP Module handler class. This class is used by the RcpmCmdSrvConnHdlr to create the handler RcpModuleHdlr object
    (hdlr), which is is passed to the command method. The RcpModuleHdlr gives the API user access to resources he can
    use carry out the command.
    """

    # The RuntimeState (rs), the CardBase (card) and the RuntimeLchan (lchan) are the three major objects through which
    # an API user may interact with the UICC/eUICC on the other remote end. Those objects have the same objectives as
    # in pySim-shell.py, with lchan representing the currently selected lchan (set to self.rs.lchan[0] by default, API
    # users may change the reference to a different lchan)
    rs = None
    card = None
    lchan = None

    # The cmd_args property contains the parsed command arguments which were passed by the end-user to the RCP Client.
    # The arguments are already parsed and validated against the cmd_dscr property of the RcpModule. The arguments are
    # in the form of a Namespace object and can be accessed like any argparse output. However, since the arguments
    # contain user input, some caution is required.
    cmd_args = None

    # In case the retrieve_uicc_keys property of the RcpModule is used retrieve UICC key material, this property will
    # contain the key material in the form of a dictionary. The format is similar to the return value of
    # card_key_provider_get() (see also pySim.card_key_provider).
    keys_uicc = {}

    # Same as self.keys_uicc, but contains eUICC related key material in case requested using retrieve_uicc_keys.
    keys_euicc = {}

    def __init__(self, print: callable, rs: RuntimeState, card: CardBase, cmd_args: Namespace,
                 keys: dict, field_cryptor: CardKeyFieldCryptor):
        self.print = print
        self.rs = rs
        self.card = card
        self.lchan = self.rs.lchan[0]
        self.cmd_args = cmd_args
        if keys:
            if 'uicc' in keys:
                self.keys_uicc = dict_from_key_value_pairs(keys['uicc'], keylabel='key', valuelabel='value')
                for key in self.keys_uicc.keys():
                    self.keys_uicc[key] = field_cryptor.decrypt_field(key, self.keys_uicc.get(key))
            if 'euicc' in keys:
                self.keys_euicc = dict_from_key_value_pairs(keys['euicc'], keylabel='key', valuelabel='value')
                for key in self.keys_euicc.keys():
                    self.keys_euicc[key] = field_cryptor.decrypt_field(key, self.keys_euicc.get(key))

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
    CardKeyFieldCryptor.argparse_add_args(option_parser)
    return option_parser

def rcpm_run_module(opts: Namespace, module: RcpModule, *args, **kwargs):

    PySimLogger.setup(print, {logging.WARN: "\033[33m", logging.DEBUG: "\033[90m"}, opts.verbose)
    log.info("RCP Module startup: %s", module.name)
    log.debug("Main process ID: %d", os.getpid())

    # Load SSL/TLS certificates.
    rcpm_cmd_ssl_context = load_server_cert("RCPM Command Server", opts.rcpm_cmd_server_cert)
    ssl_context = load_ca_cert("RCPM Server Client", opts.rcps_ca_cert)

    # Load JSON schema for message validation between RCP Server and RCP Module (this process)
    rcpm_to_rcps_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(), "rcpm_to_rcps_schema.json"))
    rcps_to_rcpm_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(), "rcps_to_rcpm_schema.json"))

    # Load JSON schema for message validation between RCP Server and RCP Module Command Server (this process)
    rcpmcs_to_rcps_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(), "rcpmcs_to_rcps_schema.json"))
    rcps_to_rcpmcs_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(), "rcps_to_rcpmcs_schema.json"))

    # Start local RCP Client Command Server.
    log.info("RCPC command server at: %s:%d" % (opts.rcpm_cmd_server_addr, opts.rcpm_cmd_server_port))
    def rcpm_cmd_conn_hdlr(websocket: ServerConnection):
        json_validator = JsonValidator(rcps_to_rcpmcs_schema, rcpmcs_to_rcps_schema)
        transport_keys = CardKeyFieldCryptor.transport_keys_from_opts(opts)
        field_cryptor = CardKeyFieldCryptor(transport_keys)
        hdlr = RcpmCmdSrvConnHdlr(module(*args, *kwargs), field_cryptor, websocket, RCP_SERVER_TIMEOUT, json_validator)
        hdlr.procedure()
        hdlr.close()

    server = serve(rcpm_cmd_conn_hdlr, opts.rcpm_cmd_server_addr, opts.rcpm_cmd_server_port, ssl=rcpm_cmd_ssl_context)
    def rcpm_cmd_server():
        log.debug("RCPC command server thread ID: %d", threading.get_native_id())
        server.serve_forever()
    rcpm_cmd_server_thread = threading.Thread(target = rcpm_cmd_server)
    rcpm_cmd_server_thread.start()

    # Connect to RCP Server and publish module description.
    async def rcps_client():
        async with websockets.connect(opts.uri, ping_timeout=10.0, ping_interval=1.0, ssl=ssl_context) as websocket:
            json_validator = JsonValidator(rcps_to_rcpm_schema, rcpm_to_rcps_schema)
            client = RcpsCltConnHdlr(opts.rcpm_cmd_server_addr, opts.rcpm_cmd_server_port, module, websocket,
                                     RCP_SERVER_TIMEOUT, json_validator)
            await client.check_version()
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
