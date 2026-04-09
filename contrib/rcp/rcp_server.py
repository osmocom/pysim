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
import time
import requests
import json
import websockets
from osmocom.utils import Hexstr
from pySim.utils import ResTuple
from copy import deepcopy
from pathlib import Path
from pySim.log import PySimLogger
from pySim.utils import dec_iccid
from websockets.asyncio.server import serve, ServerConnection
from rcp_utils import SrvConnHdlr, CltConnHdlr, JsonValidator, FlightRecorder
from rcp_utils import load_json_schema, backtrace, pytype_to_type, load_server_cert, load_ca_cert
from rcp_utils import key_value_pairs_from_dict
from pySim.card_key_provider import card_key_provider_argparse_add_args, card_key_provider_init
from pySim.card_key_provider import card_key_provider_get_field, card_key_provider_get
from packaging.version import Version

CLIENT_TIMEOUT = 10

# The protocol version between the RCP Server and the RCP Module must always match up. In case there as changes to
# the protocol (JSON Schema and/or application logic). This version number shall be incremented accordingly. Since
# RCP Modules usually run from the same pySim modules as the RCP Server, a change to this version number should
# not affect the RCP Module implementation itself.
RCPM_VERSION_PROTOCOL = "1.0.0"

# The RCP Server software version shall be incremented when there are changes to the RCP Sever (this module) or changes
# to other related modules, which affect the RCP Server. The RCP Server software version is also disclosed towards the
# RCP Client.
RCPS_VERSION_SOFTWARE = "1.0.0"

# The RCP Server protocol version refers to the protocol spoken between RCP Client and RCP Server. The protocol version
# shall be incremented when there are changes to the protocol (JSON Schema and/or application logic). When an
# RCP Client connects, this protocol version is compared against the protocol version that the client sends
# (see also RCPC_VERSION_PROTOCOL in rcp_client.py). It is up to the RCP Server to decide whether or not a deviation
# between protocol versions is tolerable or not.
RCPS_VERSION_PROTOCOL = "1.0.0"

log = PySimLogger.get(Path(__file__).stem)
runtime_state = None
rate_limiter = None
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
option_parser.add_argument("--rcpc-request-limit", help="number of RCP Client requests per minute",
                           default=600)
option_parser.add_argument("--rcpm-server-addr", help="Local Host/IP to bind RCP-Module-Server to",
                           required=True)
option_parser.add_argument("--rcpm-server-port", help="Local TCP port to bind RCP-Module-Server to",
                           required=True, type=int)
option_parser.add_argument("--rcpm-server-cert", help="SSL/TLS Certificate of the RCP-Module-Server",
                           required=True)
option_parser.add_argument("--rcpm-module-ca-cert", help="SSL/TLS CA-Certificate of the RCP-Module-Command-Server",
                           required=True)
option_parser.add_argument("--open-observe-url", help="OpenObserve API endpoint URL")
option_parser.add_argument("--open-observe-email", help="OpenObserve service email address")
option_parser.add_argument("--open-observe-token", help="OpenObserve service token")

card_key_provider_argparse_add_args(option_parser)

class ModuleRuntimeState:
    def __init__(self, websocket:ServerConnection, name:str, cmd_descr:list, suitable_for:list, addr:str, port:int):
        self.name = name
        self.websocket = websocket

        # Run the cmd_descr through argparse to catch malformed argument specifications early
        for cmd in cmd_descr:
            args = deepcopy(cmd['args'])
            cmd_parser = argparse.ArgumentParser()
            for arg in args:
                try:
                    arg['spec'] = pytype_to_type(arg['spec'])
                    cmd_parser.add_argument(arg['name'], **arg['spec'])
                except:
                    raise ValueError("invalid argument spec %s -- check RCP Module" % str(arg))

        self.cmd_descr = cmd_descr
        self.suitable_for = suitable_for
        self.addr = addr
        self.port = port
        log.debug("new RCP Module context created: '%s'", name)

    def is_suitable(self, suitable_for:dict) -> bool:
        """Check if this module is 'suitable_for' a specific card"""
        if suitable_for in self.suitable_for:
            return True
        return False

    def describe(self) -> dict:
        """Describe this module towards the RCP Client"""

        # The command description sent by the RCP Module also includes fields that are intended to be seen
        # only by the RCP Server. Here we set up the command description as it is expected by the RCP Client.
        cmd_descr = []
        for descr in self.cmd_descr:
            cmd_descr.append({'name' : descr['name'],
                              'help' : descr['help'],
                              'args' : descr['args']})

        # Return module description
        return {'name': self.name,
                'cmd_descr': cmd_descr}

    def get_cmd_descr(self, cmd: str) -> dict:
        """Get the description for a specific command of this module"""
        for descr in self.cmd_descr:
            if self.name + "_" + descr['name'] == cmd:
                return descr
        raise ValueError("command %s not found in command description %s" % (cmd_name, str(self.cmd_descr)))

    def __str__(self) -> str:
        return self.name

    def __del__(self):
        log.debug("RCP module context destroyed: '%s'", self.name)

class RuntimeState:
    def __init__(self, rcpm_ca_ssl_context, open_observe_pars):
        self.module_runtime_states = []
        self.rcpm_ca_ssl_context = rcpm_ca_ssl_context
        self.open_observe_pars = open_observe_pars

        # Load JSON schema for message validation between RCP Client and RCP Server (this process)
        self.rcpc_to_rcps_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(),
                                                                 "rcpc_to_rcps_schema.json"))
        self.rcps_to_rcpc_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(),
                                                                 "rcps_to_rcpc_schema.json"))

        # Load JSON schema for message validation between RCP Module and RCP Server (this process)
        self.rcpm_to_rcps_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(),
                                                                 "rcpm_to_rcps_schema.json"))
        self.rcps_to_rcpm_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(),
                                                                 "rcps_to_rcpm_schema.json"))

        # Load JSON schema for message validation between RCP Module Command Server and RCP Server (this process)
        self.rcpmcs_to_rcps_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(),
                                                                 "rcpmcs_to_rcps_schema.json"))
        self.rcps_to_rcpmcs_schema = load_json_schema(os.path.join(Path(__file__).parent.resolve(),
                                                                 "rcps_to_rcpmcs_schema.json"))

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
        raise ValueError("RCP module not found for command: %s, " % (cmd, self.__log_modules_available()))

class RcpmCltConnHdlr(CltConnHdlr):
    """
    The RCP Module client connection handler is the dedicated client that is used by the RCP Client connection handler
    to handle the dedicated connection towards the RCP Module (see below)
    """

class RcpcSrvConnHdlr(SrvConnHdlr):
    """
    The RCP Client connection handler takes care of the handling of client requests. Throughout the lifetime of a
    connection, the client will request a description of the available commands and then request the execution of a
    procedure. To execute the procedure, the handler will make a dedicated connection to the RCP Module and then
    transparently pass the messages from the RCP Client to the RCP Module and vice versa.
    """

    module_client = None

    async def check_version(self):
        """
        Check the RCP Client software and protocol version to ensure the requesting RCP Client is compatible with this
        RCP Server version.
        """

        # Receive version info from RCP client
        rx_json = await self._recv()
        rcpc_version_software = Version(rx_json['rcpc_version']['software'])
        rcpc_version_protocol = Version(rx_json['rcpc_version']['protocol'])
        log.debug("RCP Client version: software=%s, protocol=%s",
                  rcpc_version_software, rcpc_version_protocol)
        if self.flight_recorder:
            self.flight_recorder.record_meta('rcpc_version_software', str(rcpc_version_software))
            self.flight_recorder.record_meta('rcpc_version_protocol', str(rcpc_version_protocol))

        # Check if the RCP Client is compatible with this RCP Server. As of now we expect that the client uses the
        # exact same protocol version as the server.
        rcpc_version_protocol_expected = Version(RCPS_VERSION_PROTOCOL)
        if rcpc_version_protocol != rcpc_version_protocol_expected:
            info = "RCP Client uses unsupported protocol version (%s != %s)" % (rcpc_version_protocol, rcpc_version_protocol_expected)
            raise_exception = True
        else:
            info = None
            raise_exception = False

        # Respond with RCP Server version info. We do this before we potentially raise an exception to make sure the
        # RCP Server version info arrives at the client.
        tx_json = {'rcpc_version': {'software' : RCPS_VERSION_SOFTWARE,
                                    'protocol' : RCPS_VERSION_PROTOCOL}}
        if info:
            tx_json['rcpc_version']['info'] = info
        await self._send(tx_json)

        # Raise exception in case problems were detected. This will close the connection, but the client still has the
        # version info (see above)
        if raise_exception:
            raise ValueError(info)

    async def describe(self):
        """
        Collect the command/argument description of suitable modules and forward that definition to the RCP client. The
        RCP client will then build an argument parser (commandline help, argument validation) from this information.
        """
        rx_json = await self._recv()
        self.suitable_for = rx_json['rcpc_hello']['suitable_for']
        if self.flight_recorder:
            self.flight_recorder.record_meta('suitable_for', self.suitable_for)
        modules = runtime_state.modules_find(self.suitable_for)
        if self.flight_recorder:
            suitable_modules = []
            for m in modules:
                suitable_modules.append(m['name'])
            self.flight_recorder.record_meta('suitable_modules', suitable_modules)
        tx_json = {'rcpc_welcome':
                   {'module_descr' : modules}
                   }
        await self._send(tx_json)

    async def _transact_apdu(self, apdu: Hexstr) -> ResTuple:
        """Private low level method to exchange an APDU"""
        tx_json = {'rcpc_instr': {'c_apdu' : apdu.upper()}}
        rx_json = await self._transact(tx_json)
        if rx_json is None:
            raise ValueError("RCP Client vanished unexpectetly")
        data = rx_json['rcpc_result']['r_apdu']['data']
        sw = rx_json['rcpc_result']['r_apdu']['sw']
        return data, sw

    async def _reset(self) -> Hexstr:
        """Private low level method to reset the UICC/eUICC"""
        tx_json = {'rcpc_instr': {'reset' : None}}
        rx_json = await self._transact(tx_json)
        if rx_json is None:
            raise ValueError("RCP Client vanished unexpectetly")
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
        if rx_json is None:
            raise ValueError("RCP Client vanished unexpectedly")
        if rx_json != {'rcpc_result': {'empty' : None}}:
            raise ValueError("unexpected response from RCP Client: %s" % rx_json)

    async def procedure(self):
        """
        Receive a command from the client, pick a matching module, make a dedicated connection to that module and
        forward instruction/response messages between RCP Client and RCP Module until the procedure is done.
        """
        # Receive a command from the client.
        rx_json = await self._recv()

        # The procedure step is not mandatory. In case no procedure shall be executed, the client may close the
        # connection early on his behalf. This is normal behavior and usually the case when the user instructs the
        # RCP client to display the commandline help screens.
        if rx_json is None:
            log.debug(str(self) + " -- RCP client has closed the connection, no procedure executed")
            return

        # The RCP client has sent a command, so we continue with the procedure.
        command = rx_json['rcpc_command']
        if self.flight_recorder:
            self.flight_recorder.record_meta('cmd', command['cmd'])
            self.flight_recorder.record_meta('cmd_argv', command['cmd_argv'])

        # Pick the matching RCP Module
        module = runtime_state.module_find(self.suitable_for, command['cmd'])
        if self.flight_recorder:
            self.flight_recorder.record_meta('module', module.name)

        # Retrieve keys (if the command requires them)
        cmd_descr = module.get_cmd_descr(command['cmd'])
        get_keys = cmd_descr.get('get_keys')
        if get_keys:
            keys = {}
            get_keys_uicc = get_keys.get('uicc')
            if get_keys_uicc:
                iccid = await self._read_iccid()
                if self.flight_recorder:
                    self.flight_recorder.record_meta('iccid', iccid)
                keys_uicc = card_key_provider_get(get_keys_uicc, 'ICCID', iccid)
                keys['uicc'] = key_value_pairs_from_dict(keys_uicc, keylabel='key', valuelabel='value')
            get_keys_euicc = get_keys.get('euicc')
            if get_keys_euicc:
                eid = await self._read_eid()
                if self.flight_recorder:
                    self.flight_recorder.record_meta('eid', eid)
                keys_euicc = card_key_provider_get(get_keys_euicc, 'EID', eid)
                keys['euicc'] = key_value_pairs_from_dict(keys_euicc, keylabel='key', valuelabel='value')
            command['keys'] = keys

        # Resetting card to ensure the card is in a defined state
        await self._reset()

        # Create a dedicated connection to the RCP Module and proxy the messages between RCP Client and RCP Module.
        module_uri = "wss://%s:%d" % (module.addr, module.port)
        log.info(str(self) + " -- executing procedure for command \"%s\" on module \"%s\" at: %s" %
                 (command['cmd'], module.name, module_uri))
        async with websockets.connect(module_uri, ssl=runtime_state.rcpm_ca_ssl_context) as websocket:
            # Create a connection to the RCP Module Command Server
            json_validator = JsonValidator(runtime_state.rcpmcs_to_rcps_schema, runtime_state.rcps_to_rcpmcs_schema)
            self.module_client = RcpmCltConnHdlr(websocket, CLIENT_TIMEOUT, json_validator, self.flight_recorder)

            # Prepare initial request to be send to the RCP Module Command Server
            module_tx_json = {'rcps_command' : command}

            # Forward messages between RCP Module Command Server and RCP Client until the procedure ends.
            while(True):
                # Send request to the RCP Module Command Server
                module_rx_json = await self.module_client._transact(module_tx_json)

                # Forward the response to the RCP Client
                if 'rcps_instr' in module_rx_json:
                    client_tx_json = {'rcpc_instr' : module_rx_json['rcps_instr']}
                    await self._send(client_tx_json)
                elif 'rcps_goodbye' in module_rx_json:
                    rc = module_rx_json['rcps_goodbye']
                    log.info(str(self) + " -- command execution done, rc: %d" % rc)
                    if self.flight_recorder:
                        self.flight_recorder.record_meta('rc', rc)
                        if rc != 0:
                            self.flight_recorder.crash_report()
                    client_tx_json = {'rcpc_goodbye' : rc}
                    await self._send(client_tx_json)
                    break
                else:
                    raise ValueError("Unexpected response from RCP Module: %s" % str(module_rx_json))

                # Receive the Result from the client, prepare request (module_tx_json) for the next turn
                client_rx_json = await self._recv()
                if client_rx_json is None:
                    raise ValueError("RCP client vanished unexpectedly")
                if 'rcpc_result' in client_rx_json:
                    module_tx_json = {'rcps_result' : client_rx_json['rcpc_result']}
                else:
                    raise ValueError("Unexpected result from RCP Client: %s" % str(client_rx_json))

    async def close(self):
        """
        Close the connection towards the RCP Module Command Server, then close the connection towards the RCP Client.
        """
        if self.module_client:
            await self.module_client.close()
        await super().close()

class RcpmSrvConnHdlr(SrvConnHdlr):
    """
    The RCP Module connection handler is responsible to handle connect and disconnect events of RCP Modules. This
    connection between the RCP Module and the RCP Server is used for management purposes only.
    """

    async def check_version(self):
        """
        Send the Protocol and Software version of this RCP Module to the RCP Server. The RCP Server and the RCP Module
        must always use the same protocol version.
        """
        tx_json = {'rcpm_version': {'protocol' : RCPM_VERSION_PROTOCOL}}
        rx_json = await self._transact(tx_json)
        rcpm_version_protocol = Version(rx_json['rcpm_version']['protocol'])
        if Version(RCPM_VERSION_PROTOCOL) != rcpm_version_protocol:
            raise ValueError("Incompatible protocol version %s != %s", Version(RCPM_VERSION_PROTOCOL), rcpm_version_protocol)

    async def describe(self):
        """
        Receive the module description from an RCP Module. This description will be stored in an internal list until
        the module is disconnected from the server.
        """
        rx_json = await self._recv()
        runtime_state.module_add(module = ModuleRuntimeState(self.websocket, **rx_json['rcpm_hello']))
        tx_json = {'rcpm_welcome': None}
        await self._send(tx_json)

    def __del__(self):
        """
        Remove RCPM from internal list when the connection is closed (and the handler is deleted)
        """
        runtime_state.module_remove(self.websocket)
        super().__del__()

class RateLimiter():
    """
    Rate limiter: A rate limiter can be used to limit the amount of requests
    per interval. Once the interval expires, the request counter is reset and
    the requestor gets a new request budget to spend.
    """

    def __init__(self, interval:int, requests:int):
        """
        Args:
                interval: reset interval after which request counter is reset.
                requests: maximum number of requests per interval.
        Returns:
                True when rate limit has been exceeded, False otherwise.
        """
        self.table = {}
        self.interval = interval
        self.requests = requests
        self.last_collect = time.time()
        log.info("Rate-Limit: max %d requests per sec.", self.requests / self.interval)

    def __collect_expired(self):
        new_table = {}
        for key in self.table.keys():
            if time.time() - self.table[key]['timestamp'] <= self.interval:
                new_table[key] = self.table[key]
        self.table = new_table

    def limit(self, address:str) -> bool:
        """
        Rate limit request

        Args:
                address: requestor address
        Returns:
                True when rate limit has been exceeded, False otherwise
        """

        timestamp = time.time()

        # Collect expired entries once per minute
        if time.time() - self.last_collect > 60:
            self.__collect_expired()
            self.last_collect = timestamp

        # In case no entry exists yet, create a new one => don't block
        if address not in self.table:
            self.table[address] = {'timestamp' : timestamp, 'counter' : 1}
            log.debug("Rate-Limit: %s (new, counter=%d, next reset in %d sec.)",
                      address, 1, self.interval)
            return False

        # We have to access multiple times, so its better to story the entry
        # in a temporary variable.
        entry = self.table[address]

        # If the entry has expired - delete it => don't block
        if timestamp - entry['timestamp'] > self.interval:
            log.debug("Rate-Limit: %s (reset, counter=%d, next reset in %d sec.)",
                      address, 1, self.interval)
            self.table[address] = {'timestamp' : timestamp, 'counter' : 1}
            return False

        # If the rate limit has been reached => block
        if entry['counter'] >= self.requests:
            log.warning("Rate-Limit: %s (exceeded, counter=%d, next reset in %d sec.)",
                        address, entry['counter'], self.interval - (timestamp - entry['timestamp']))
            return True

        # Increment counter, don't block
        entry['counter'] += 1
        log.debug("Rate-Limit: %s (incrementing, counter=%d, next reset in %d sec.)",
                  address, entry['counter'], self.interval - (timestamp - entry['timestamp']))
        self.table[address] = entry
        return False

class OpenObserveFlightRecorder(FlightRecorder):
    """Concrete implementation of a "flight recorder" using OpenObserve as a monitoring entity."""

    def __init__(self, url: str, email: str, token: str):
        self.service_auth = requests.auth.HTTPBasicAuth(email, token)
        self.url = url
        super().__init__()

    def report(self):
        report_json = json.dumps(self._gen_report())
        rc = requests.post(self.url, auth=self.service_auth, data=report_json)
        if rc.status_code != 200:
            log.error("POST request to OpenObserve failed: %s", str(rc))

async def rcpc_conn_hdlr(websocket: ServerConnection):
    """
    In this handler function we process the request from the the RCP Client. Before we perform any action we check if
    the rate limit is not exceeded. Then we describe the available commands to the client and execute the procedure
    the client asks for. When everything is done we close the connection normally. The client may skip executing any
    procedure by closing the connection early on his behalf.

    The interaction with the client is recorded using a "flight recorder" object. When the interaction is done, the
    records are analyzed and a report is generated and sent to the OpenObserve monitoring entity.
    """

    # Immediately close the connection in case the rate limit has been exceeded.
    if rate_limiter.limit(websocket.remote_address[0]):
        await websocket.close(code=1008) # Policy Violation

    # Create flight-recorder object
    flight_recorder = None
    if runtime_state.open_observe_pars:
        flight_recorder = OpenObserveFlightRecorder(**runtime_state.open_observe_pars)

    # Execute procedure
    try:
        json_validator = JsonValidator(runtime_state.rcpc_to_rcps_schema, runtime_state.rcps_to_rcpc_schema)
        hdlr = RcpcSrvConnHdlr(websocket, CLIENT_TIMEOUT, json_validator, flight_recorder)
        await hdlr.check_version()
        await hdlr.describe()
        await hdlr.procedure()
        await hdlr.close()
    except Exception as e:
        backtrace("RCPC connection handler")
        if flight_recorder:
            flight_recorder.record_backtrace()
            flight_recorder.crash_report()
        await websocket.close(code=1011) # Internal Error

    # Generate report from flight-recorder
    if flight_recorder:
        flight_recorder.report()

async def rcpm_conn_hdlr(websocket: ServerConnection):
    """
    In this handler function we process requests from the RCP Module. We receive the description from the RCP Module.
    We keep the connection open throughout the whole lifetime of the RCP Module process so that we can know when the
    RCP Module becomes unavailable for some reason.
    """
    try:
        json_validator = JsonValidator(runtime_state.rcpm_to_rcps_schema, runtime_state.rcps_to_rcpm_schema)
        hdlr = RcpmSrvConnHdlr(websocket, CLIENT_TIMEOUT, json_validator)
        await hdlr.check_version()
        await hdlr.describe()
        await hdlr.close()
    except:
        backtrace("RCPM connection handler")

if __name__ == '__main__':
    opts = option_parser.parse_args()
    PySimLogger.setup(print, {logging.WARN: "\033[33m", logging.DEBUG: "\033[90m"}, opts.verbose)

    # Load SSL/TLS certificates
    rcpc_ssl_context = load_server_cert("RCP Client Server", opts.rcpc_server_cert)
    rcpm_ssl_context = load_server_cert("RCP Module Server", opts.rcpm_server_cert)
    rcpm_ca_ssl_context = load_ca_cert("RCP Module Command Server Client", opts.rcpm_module_ca_cert)

    # Init card key provider for automatic card key retrieval
    card_key_provider_init(opts)

    # Prepare parameters for OpenObserve
    if opts.open_observe_url and opts.open_observe_email and opts.open_observe_token:
        open_observe_pars = {'url' : opts.open_observe_url,
                             'email': opts.open_observe_email,
                             'token' : opts.open_observe_token}
        log.info("Reporting to OpenObserve: %s", open_observe_pars['url'])
    else:
        log.warning("Reporting to OpenObserve: (disabled)")
        open_observe_pars = None

    # Start RCP server
    runtime_state = RuntimeState(rcpm_ca_ssl_context, open_observe_pars)
    rate_limiter = RateLimiter(interval=60, requests=opts.rcpc_request_limit)
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

