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
import ssl
import json
import abc
import asyncio
import websockets
import traceback
import threading
from copy import deepcopy
from websockets.asyncio.server import ServerConnection
from websockets.asyncio.client import ClientConnection
from pathlib import Path
from jsonschema import validate
from pySim.log import PySimLogger
from ssl import SSLContext

log = PySimLogger.get(Path(__file__).stem)

# TODO: Might be helpful for others as well, move this to pySim.utils?
def backtrace(what: str):
    log.error("%s failed with an exception:", what)
    log.error("---------------------8<---------------------")
    traceback_lines = traceback.format_exc()
    for line in traceback_lines.split("\n"):
        if line:
            log.error(line)
    log.error("---------------------8<---------------------")

# TODO: Might be helpful for others as well, move this to pySim.utils?
def key_value_pairs_from_dict(keys: dict, keylabel: str='key', valuelabel: str='value') -> list:
    key_list = []
    for key in keys:
        key_list.append({keylabel : key, valuelabel : keys[key]})
    return key_list

# TODO: Might be helpful for others as well, move this to pySim.utils?
def dict_from_key_value_pairs(keys: list, keylabel: str='key', valuelabel: str='value') -> dict:
    key_dict = {}
    for key in keys:
        key_dict[key[keylabel]] = key[valuelabel]
    return key_dict

def pytype_to_type(dict_in: dict) -> dict:
    """
    There is no way to properly express python types in JSON. This function can be used to replace
    each ocurrence of "pytype", with "type", where the string type name is replaced with an actual
    python type.
    """
    dict_out = deepcopy(dict_in)
    if dict_out.get('pytype'):
        if dict_out['pytype'] == "str":
            dict_out.pop('pytype')
            dict_out['type'] = str
        elif dict_out['pytype'] == "int":
            dict_out.pop('pytype')
            dict_out['type'] = int
        else:
            raise ValueError("invalid type in command argument specification: %s" % arg['spec']['type'])
    return dict_out

def load_json_schema(filename: str) -> dict:
    """Load a JSON schema from file"""
    log.info("loading JSON schema: %s", filename)
    try:
        with open(filename) as schema_file:
            return json.load(schema_file)
    except Exception as e:
        backtrace("JSON schema load")
        sys.exit(1)

def load_server_cert(what: str, filename: str) -> SSLContext:
    """Load an SSL/TLS server certificate"""
    log.info("loading SSL/TLS server certificate (%s): %s", what, filename)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(filename)
    return ssl_context

def load_ca_cert(what: str, filename: str) -> SSLContext:
    """Load an SSL/TLS CA certificate"""
    log.info("loading SSL/TLS CA certificate (%s): %s", what, filename)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(filename)
    return ssl_context

class JsonValidator():
    """
    JSON validator class, can be passed to any ConnHdlr object to automatically validate the JSON messages which are
    sent and and received.
    """

    def __init__(self, rx_schema: dict, tx_schema: dict = None):
        self.rx_schema = rx_schema
        if tx_schema:
            self.tx_schema = tx_schema
        else:
            self.tx_schema = None

    def valid_rx_json(self, rx_json: dict):
        validate(instance = rx_json, schema = self.rx_schema)

    def valid_tx_json(self, tx_json: dict):
        if self.tx_schema:
            # We intentionally do not prevent the sending of an invalid JSON message. It is the responsibility of the
            # receiving end to detect an invalid message and react accordingly. The purpose of this validation is to
            # make developers/users aware of the problem.
            try:
                validate(instance = tx_json, schema = self.tx_schema)
            except Exception as e:
                backtrace("JSON schema validation (TX)")

class ConnHdlr(abc.ABC):
    """Base class that can be used to create a connection handler"""

    def __init__(self, websocket: ServerConnection | ClientConnection, timeout: int,
                 json_validator: JsonValidator = None):
        self.websocket = websocket
        self.timeout = timeout
        self.json_validator = json_validator
        log.debug(str(self) + " -- new handler, timeout: %d sec.", self.timeout)

    def _log_recv_peer(self, rx_json_str: str):
        peer = "%s:%d<-%s:%d" % (self.websocket.local_address[0],
                           self.websocket.local_address[1],
                           self.websocket.remote_address[0],
                           self.websocket.remote_address[1])
        log.debug(str(self) + " -- RX(%s): %s", peer, rx_json_str)

    def _log_send_peer(self, tx_json_str: str):
        peer = "%s:%d->%s:%d" % (self.websocket.local_address[0],
                           self.websocket.local_address[1],
                           self.websocket.remote_address[0],
                           self.websocket.remote_address[1])
        log.debug(str(self) + " -- TX(%s): %s", peer, tx_json_str)

    def __str__(self) -> str:
        return "%s(%d)" % (type(self).__name__, id(self))

    def __del__(self):
        log.debug(str(self) + " -- closed handler")

class SrvConnHdlr(ConnHdlr):
    """Base class that can be used to create a connection handler for a server"""

    async def _recv(self) -> dict:
        """Receive JSON message from client"""
        async with asyncio.timeout(self.timeout):
            try:
                rx_json_str = await self.websocket.recv()
            except websockets.exceptions.ConnectionClosedOK:
                log.debug(str(self) + " -- no data received, connection is closed")
                return None
        self._log_recv_peer(rx_json_str)
        rx_json = json.loads(rx_json_str)
        if self.json_validator:
            self.json_validator.valid_rx_json(rx_json)
        return rx_json

    async def _send(self, tx_json: dict):
        """Send JSON message to client"""
        if self.json_validator:
            self.json_validator.valid_tx_json(tx_json)
        tx_json_str = json.dumps(tx_json)
        self._log_send_peer(tx_json_str)
        await self.websocket.send(tx_json_str)

    async def _transact(self, tx_json: dict) -> dict:
        """Exchange JSON message with client"""
        await self._send(tx_json)
        return await self._recv()

    async def close(self):
        """Wait for a connecion to close normally"""
        await self.websocket.wait_closed()
        log.debug(str(self) + " -- closed connection")

class SrvSyncConnHdlr(ConnHdlr):
    """Base class that can be used to create a synchronous connection handler for a server"""

    def _recv(self) -> dict:
        """Receive JSON message from client"""
        # TODO: we do not have a timeout here (the self.timeout is currently useless). Check if we can do something
        # about this or if we have to implement some watchdog functionality elsewhere.
        rx_json_str = self.websocket.recv()
        self._log_recv_peer(rx_json_str)
        rx_json = json.loads(rx_json_str)
        if self.json_validator:
            self.json_validator.valid_rx_json(rx_json)
        return rx_json

    def _send(self, tx_json: dict):
        """Send JSON message to client"""
        if self.json_validator:
            self.json_validator.valid_tx_json(tx_json)
        tx_json_str = json.dumps(tx_json)
        self._log_send_peer(tx_json_str)
        self.websocket.send(tx_json_str)

    def _transact(self, tx_json: dict) -> dict:
        """Exchange JSON message with client"""
        self._send(tx_json)
        return self._recv()

    def close(self):
        """Close connection normally"""
        self.websocket.close()
        log.debug(str(self) + " -- closed connection")

class CltConnHdlr(ConnHdlr):
    """Base class that can be used to create a connection handler for a client"""

    async def _transact(self, tx_json: dict) -> dict:
        """Exchange JSON message with server"""
        if self.json_validator:
            self.json_validator.valid_tx_json(tx_json)
        tx_json_str = json.dumps(tx_json)
        self._log_send_peer(tx_json_str)
        async with asyncio.timeout(self.timeout):
            await self.websocket.send(tx_json_str)
            rx_json_str = await self.websocket.recv()
        self._log_recv_peer(rx_json_str)
        rx_json = json.loads(rx_json_str);
        if self.json_validator:
            self.json_validator.valid_rx_json(rx_json)
        return rx_json

    async def close(self):
        """Close connection normally"""
        await self.websocket.close()
        log.debug(str(self) + " -- closed connection")

    async def wait_close(self):
        """Wait for a connecion to close normally"""
        await self.websocket.wait_closed()
        log.debug(str(self) + " -- closed connection")
