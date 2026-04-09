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

import os
import sys
import argparse
import asyncio
import logging
from osmocom.utils import Hexstr
from pySim.utils import ResTuple
from copy import deepcopy
from pathlib import Path
from pySim.log import PySimLogger
from pySim.utils import dec_iccid
import websockets
from websockets.asyncio.server import serve, ServerConnection
from rcp_utils import SrvConnHdlr, CltConnHdlr, JsonValidator
from rcp_utils import load_json_schema, backtrace, pytype_to_type, load_server_cert, load_ca_cert
from rcp_utils import key_value_pairs_from_dict
from pySim.card_key_provider import argparse_add_card_key_provider_args, init_card_key_provider
from pySim.card_key_provider import card_key_provider_get_field, card_key_provider_get

# TODO: Logging is fine, however it may also be a good idea to log some higher level events to some sort of journal.
# We could use OpenObserve for that.

CLIENT_TIMEOUT = 10

log = PySimLogger.get(Path(__file__).stem)
runtime_state = None
option_parser = argparse.ArgumentParser(description='RCP Server',
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
option_parser.add_argument("--verbose", help="Enable verbose logging",
                           action='store_true', default=False)
option_parser.add_argument("--rcpc-server-addr", help="Local Host/IP to bind RCP-Client-Server to",
                           required=True)
option_parser.add_argument("--rcpc-server-port", help="Local TCP port to bind RCP-Client-Server to",
                           required=True, type=int)
option_parser.add_argument("--rcpc-server-cert", help="SSL/TLS Certificate of the RCP-Client-Server",
                           required=True)
option_parser.add_argument("--rcpm-server-addr", help="Local Host/IP to bind RCP-Module-Server to",
                           required=True)
option_parser.add_argument("--rcpm-server-port", help="Local TCP port to bind RCP-Module-Server to",
                           required=True, type=int)
option_parser.add_argument("--rcpm-server-cert", help="SSL/TLS Certificate of the RCP-Module-Server",
                           required=True)
option_parser.add_argument("--rcpm-module-ca-cert", help="SSL/TLS CA-Certificate of the RCP-Module-Command-Server",
                           required=True)
argparse_add_card_key_provider_args(option_parser)

# TODO move those into the RuntimeState?
rcpc_rx_schema = None
rcpc_tx_schema = None
rcpm_ca_ssl_contextssl_context = None

class ModuleRuntimeState:
    def __init__(self, websocket:ServerConnection, name:str, cmd_descr:list, suitable_for:list, retrieve_keys:dict,
                 addr:str, port:int):
        self.name = name
        self.websocket = websocket

        # Run the cmd_descr through argparse to catch malformed arguments early
        for cmd in cmd_descr:
            args = deepcopy(cmd['args'])
            cmd_parser = argparse.ArgumentParser()
            for arg in args:
                # TODO: wrap this into a try/catch block and log broken arguments?
                arg['spec'] = pytype_to_type(arg['spec'])
                cmd_parser.add_argument(arg['name'], **arg['spec'])

        self.cmd_descr = cmd_descr
        self.suitable_for = suitable_for
        self.retrieve_keys = retrieve_keys
        self.addr = addr
        self.port = port
        log.debug("new RCP module context created: '%s'", name)

    def is_suitable(self, suitable_for:dict) -> bool:
        if suitable_for in self.suitable_for:
            return True
        return False

    def describe(self) -> dict:
        return {'name': self.name,
                'cmd_descr': self.cmd_descr}

    def __str__(self) -> str:
        return self.name

    def __del__(self):
        log.debug("RCP module context destroyed: '%s'", self.name)

class RuntimeState:
    def __init__(self):
        self.module_runtime_states = []
        log.debug("new runtime context created.")

    def __log_modules_available(self) -> str:
        if self.module_runtime_states:
            modules_str = ""
            for module in self.module_runtime_states:
                modules_str += "'" + str(module) + "', "
            return "RCP modules available: %s" % modules_str[:-2]
        else:
            return "RCP modules available: none"

    def module_add(self, module: ModuleRuntimeState):
        self.module_runtime_states.append(module)
        log.info("new RCP module, %s", self.__log_modules_available())

    def module_remove(self, websocket:ServerConnection):
        for module in self.module_runtime_states:
            if module.websocket == websocket:
                self.module_runtime_states.remove(module)
                log.info("RCP module removed, %s", self.__log_modules_available())
                return
        log.warning("cannot remove RCP module, no RCP module associated with RCPC connection: %s:%d, %s" %
                    (*websocket.remote_address, self.__log_modules_available()))

    def modules_find(self, suitable_for:dict) -> list[dict]:
        modules = []
        for module in self.module_runtime_states:
            if module.is_suitable(suitable_for):
                modules.append(module.describe())
        if modules:
            return modules
        # It is absolutely tolerable if no suitable RCP module can be found. If this is the case, the client should
        # display an empty help screen and exit normally.
        log.warning("no suitable RCP module found, %s", self.__log_modules_available())
        return []

    def module_find(self, suitable_for:dict, cmd:str) -> ModuleRuntimeState:
        modules = self.modules_find(suitable_for)
        for m in modules:
            module_name = m['name']
            cmd_descr = m['cmd_descr']
            for c in cmd_descr:
                cmd_name = c['name']
                if module_name + "_" + cmd_name == cmd:
                    break
        for module_runtime_state in self.module_runtime_states:
            if module_runtime_state.name == module_name:
                return module_runtime_state
        # Normally we should find the RCP module. When this method is called, we have already called modules_find
        # before because we had to return the command descriptions to the client. If we cannot find the RCP module
        # now, the module have been disconnected or the client somehow called a command that does not exist. In any
        # case, ending up here means we cannot continue.
        raise ValueError("RCP module not found for command: %s, ", cmd, self.__log_modules_available())

class RcpmCltConnHdlr(CltConnHdlr):
    """
    The RCP Module client connection handler is the dedicated client that is used by the RCP Client connection handler
    to handle the dedicated connection towards the RCP Module (see below)
    """

class RcpcSrvConnHdlr(SrvConnHdlr):
    """
    The RCP Client connection handler takes care of the handling of client requests. Througout the lifetime of a
    connection, the client will request a description of the available commands and then request the execution of a
    procedure. To execute the procedure, the handler will make a dedicated connection to the RCP Module and then
    transparently pass the messages from the RCP Client to the RCP Module and vice versa.
    """

    async def describe(self):
        """
        Collect the command/argument description of suitable modules and forward that definition to the RCP client. The
        RCP client will then build an argument parser (commmandlien help, argument validation) from this information.
        """
        rx_json = await self._recv()
        self.suitable_for = rx_json['rcpc_hello']['suitable_for']
        modules = runtime_state.modules_find(self.suitable_for)
        tx_json = {'rcpc_welcome':
                   {'module_descr' : modules}
                   }
        await self._send(tx_json)

    async def _transact_apdu(self, apdu: Hexstr) -> ResTuple:
        """Private low level method to exchange an APDU"""
        tx_json = {'rcpc_instr': {'c_apdu' : apdu.upper()}}
        rx_json = await self._transact(tx_json)
        data = rx_json['rcpc_result']['r_apdu']['data']
        sw = rx_json['rcpc_result']['r_apdu']['sw']
        return data, sw

    async def _reset(self) -> Hexstr:
        """Private low level method to reset the UICC/eUICC"""
        tx_json = {'rcpc_instr': {'reset' : None}}
        rx_json = await self._transact(tx_json)
        return rx_json['rcpc_result']['atr']

    async def _read_iccid(self) -> Hexstr:
        """Private low level method to read the EID from an UICC (or eSIM)"""
        data, sw = await self._transact_apdu("00A40000022FE200")
        if sw != "9000":
            raise ValueError("Unable to select EF.ICCID, sw: %s, " % sw)
        data, sw = await self._transact_apdu("00B000000A")
        if sw != "9000":
            raise ValueError("Unable to read EF.ICCID, sw: %s, " % sw)
        return dec_iccid(data)

    async def _read_eid(self) -> Hexstr:
        """Private low level method to read the EID from an eUICC"""
        data, sw = await self._transact_apdu("00A4040410A0000005591010FFFFFFFF890000010000")
        if sw != "9000":
            raise ValueError("Unable to select ISD-R, sw: %s, " % sw)
        data, sw = await self._transact_apdu("80E2910006BF3E035C015A00")
        if sw != "9000":
            raise ValueError("Unable to retrieve EID, sw: %s, " % sw)
        return data[10:]

    async def print(self, message: str):
        """ Print a message on the client side """
        tx_json = {'rcpc_instr': {'print' : message}}
        rx_json = await self._transact(tx_json)
        if rx_json != {'rcpc_result': {'empty' : None}}:
            raise ValueError("unexpected response from RCP Client: %s", rx_json)

    async def procedure(self):
        """
        Receive a command from the client, pick a matching module, make a decdicated connection to that module and
        forward instruction/response messages between RCP Client and RCP Module until the procedure is done.
        """

        # Expect a command from the client
        rx_json = await self._recv()
        if rx_json is None:
            log.debug(str(self) + " -- RCP client has closed the connection, no procedure executed")
            return
        command = rx_json['rcpc_command']

        # Pick the matching RCP Module
        module = runtime_state.module_find(self.suitable_for, command['cmd'])

        # Retrieve keys (if module requires them)
        keys = {}
        if module.retrieve_keys['uicc']:
            iccid = await self._read_iccid()
            keys_uicc = card_key_provider_get(module.retrieve_keys['uicc'], 'ICCID', iccid)
            keys['uicc'] = key_value_pairs_from_dict(keys_uicc, keylabel='key', valuelabel='value')
        else:
            keys['uicc'] = []
        if module.retrieve_keys['euicc']:
            eid = await self._read_eid()
            keys_euicc = card_key_provider_get(module.retrieve_keys['euicc'], 'EID', eid)
            keys['euicc'] = key_value_pairs_from_dict(keys_euicc, keylabel='key', valuelabel='value')
        else:
            keys['euicc'] = []
        command['keys'] = keys

        # Resetting card to ensure the card is in a defined state
        await self._reset()

        # Transparently forward messages between RCP Client and RCP Module
        module_uri = "wss://%s:%d" % (module.addr, module.port)
        log.info(str(self) + " -- executing procedure for command \"%s\" on module \"%s\" at: %s" %
                 (command['cmd'], module.name, module_uri))
        async with websockets.connect(module_uri, ssl=rcpm_ca_ssl_context) as websocket:
            module_client = RcpmCltConnHdlr(websocket, CLIENT_TIMEOUT)
            rx_json = {'rcpc_command' : command}
            while(True):
                module_rx_json = await module_client._transact(rx_json)
                await self._send(module_rx_json)
                if 'rcpc_goodbye' in module_rx_json:
                    log.info(str(self) + " -- command execution done, rc: %d" % module_rx_json['rcpc_goodbye'])
                    break
                rx_json = await self._recv()
            await module_client.close()

class RcpmSrvConnHdlr(SrvConnHdlr):
    """
    The RCP Module connection handler is responsible to handle connect and disconnect events of RCP Modules. This
    connection between the RCP Module and the RCP Server is used for management purposes only.
    """

    async def describe(self):
        """
        Receive the module description from an RCP Module. This description will be stored in an internal list until
        the module is disconnected from the server.
        """
        rx_json = await self._recv()
        runtime_state.module_add(module = ModuleRuntimeState(self.websocket, **rx_json['rcpm_hello']))
        tx_json = {'rcpm_welcome': {}}
        await self._send(tx_json)

    def __del__(self):
        """
        Remove RCPM from internal list when the connection is closed (and the handler is deleted)
        """
        runtime_state.module_remove(self.websocket)
        super().__del__()

async def rcpc_conn_hdlr(websocket: ServerConnection):
    # TODO: Implement some sort of rate limit to protect against DoS. We may count the requests for each requesting
    # IP address and reject the connection once a certain threshold is reached. (we plan to use the CardKeyProvider
    # together with a database)
    try:
        json_validator = JsonValidator(rcpc_rx_schema, rcpc_tx_schema)
        hdlr = RcpcSrvConnHdlr(websocket, CLIENT_TIMEOUT, json_validator)
        await hdlr.describe()
        await hdlr.procedure()
        await hdlr.close()
    except:
        backtrace("RCPC connection handler")

async def rcpm_conn_hdlr(websocket: ServerConnection):
    try:
        hdlr = RcpmSrvConnHdlr(websocket, CLIENT_TIMEOUT)
        await hdlr.describe()
        await hdlr.close()
    except:
        backtrace("RCPM connection handler")

if __name__ == '__main__':
    opts = option_parser.parse_args()

    PySimLogger.setup(print, {logging.WARN: "\033[33m", logging.DEBUG: "\033[90m"}, opts.verbose)
    runtime_state = RuntimeState()

    # TODO: Modularize the JSON schemas. We already repeat ourselves with multiple definitions of the ATR fields.
    rcpc_rx_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(), "rcpc_rx_schema.json"))
    rcpc_tx_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(), "rcpc_tx_schema.json"))

    # Load SSL/TLS certificates
    rcpc_ssl_context = load_server_cert("RCP Client Server", opts.rcpc_server_cert)
    rcpm_ssl_context = load_server_cert("RCP Module Server", opts.rcpm_server_cert)
    rcpm_ca_ssl_context = load_ca_cert("RCP Module Command Server Client", opts.rcpm_module_ca_cert)

    # Init card key provider for automatic card key retrieval
    init_card_key_provider(opts)

    # Start RCP server
    async def rcp_server():
        log.info("RCP Client Server at: %s:%d" % (opts.rcpc_server_addr, opts.rcpc_server_port))
        log.info("RCP Module server at: %s:%d" % (opts.rcpm_server_addr, opts.rcpm_server_port))
        async with serve(rcpc_conn_hdlr, opts.rcpc_server_addr, opts.rcpc_server_port, ssl=rcpc_ssl_context), \
                   serve(rcpm_conn_hdlr, opts.rcpm_server_addr, opts.rcpm_server_port, ssl=rcpm_ssl_context):
            await asyncio.get_running_loop().create_future()
    try:
        asyncio.run(rcp_server())
    except SystemExit:
        pass
    except:
        backtrace("RCP Server")
        sys.exit(1)

