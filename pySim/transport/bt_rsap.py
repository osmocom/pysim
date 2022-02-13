# -*- coding: utf-8 -*-

""" pySim: Bluetooth rSAP transport link
"""

#
# Copyright (C) 2021  Gabriel K. Gegenhuber <ggegenhuber@sba-research.org>
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

import time
import struct
import logging
import bluetooth

from pySim.exceptions import ReaderError, NoCardError, ProtocolError
from pySim.transport import LinkBase
from pySim.utils import b2h, h2b, rpad

logger = logging.getLogger(__name__)


# thx to osmocom/softsim
# SAP table 5.16
SAP_CONNECTION_STATUS = {
    0x00: "OK, Server can fulfill requirements",
    0x01: "Error, Server unable to establish connection",
    0x02: "Error, Server does not support maximum message size",
    0x03: "Error, maximum message size by Client is too small",
    0x04: "OK, ongoing call"
}

# SAP table 5.18
SAP_RESULT_CODE = {
    0x00: "OK, request processed correctly",
    0x01: "Error, no reason defined",
    0x02: "Error, card not accessible",
    0x03: "Error, card (already) powered off",
    0x04: "Error, card removed",
    0x05: "Error, card already powered on",
    0x06: "Error, data not available",
    0x07: "Error, not supported"
}

# SAP table 5.19
SAP_STATUS_CHANGE = {
    0x00: "Unknown Error",
    0x01: "Card reset",
    0x02: "Card not accessible",
    0x03: "Card removed",
    0x04: "Card inserted",
    0x05: "Card recovered"
}

# SAP table 5.15
SAP_PARAMETERS = [
    {
        'name': "MaxMsgSize",
        'length': 2,
        'id': 0x00
    },
    {
        'name': "ConnectionStatus",
        'length': 1,
        'id': 0x01
    },
    {
        'name': "ResultCode",
        'length': 1,
        'id': 0x02
    },
    {
        'name': "DisconnectionType",
        'length': 1,
        'id': 0x03
    },
    {
        'name': "CommandAPDU",
        'length': None,
        'id': 0x04
    },
    {
        'name': "ResponseAPDU",
        'length': None,
        'id': 0x05
    },
    {
        'name': "ATR",
        'length': None,
        'id': 0x06
    },
    {
        'name': "CardReaderdStatus",
        'length': 1,
        'id': 0x07
    },
    {
        'name': "StatusChange",
        'length': 1,
        'id': 0x08
    },
    {
        'name': "TransportProtocol",
        'length': 1,
        'id': 0x09
    },
    {
        'name': "CommandAPDU7816",
        'length': 2,
        'id': 0x10
    }
]

# SAP table 5.1
SAP_MESSAGES = [
    {
        'name': 'CONNECT_REQ',
        'client_to_server': True,
        'id': 0x00,
        'parameters': [(0x00, True)]
    },
    {
        'name': 'CONNECT_RESP',
        'client_to_server': False,
        'id': 0x01,
        'parameters': [(0x01, True), (0x00, False)]
    },
    {
        'name': 'DISCONNECT_REQ',
        'client_to_server': True,
        'id': 0x02,
        'parameters': []
    },
    {
        'name': 'DISCONNECT_RESP',
        'client_to_server': False,
        'id': 0x03,
        'parameters': []
    },
    {
        'name': 'DISCONNECT_IND',
        'client_to_server': False,
        'id': 0x04,
        'parameters': [(0x03, True)]
    },
    {
        'name': 'TRANSFER_APDU_REQ',
        'client_to_server': True,
        'id': 0x05,
        'parameters': [(0x04, False), (0x10, False)]
    },
    {
        'name': 'TRANSFER_APDU_RESP',
        'client_to_server': False,
        'id': 0x06,
        'parameters': [(0x02, True), (0x05, False)]
    },
    {
        'name': 'TRANSFER_ATR_REQ',
        'client_to_server': True,
        'id': 0x07,
        'parameters': []
    },
    {
        'name': 'TRANSFER_ATR_RESP',
        'client_to_server': False,
        'id': 0x08,
        'parameters': [(0x02, True), (0x06, False)]
    },
    {
        'name': 'POWER_SIM_OFF_REQ',
        'client_to_server': True,
        'id': 0x09,
        'parameters': []
    },
    {
        'name': 'POWER_SIM_OFF_RESP',
        'client_to_server': False,
        'id': 0x0A,
        'parameters': [(0x02, True)]
    },
    {
        'name': 'POWER_SIM_ON_REQ',
        'client_to_server': True,
        'id': 0x0B,
        'parameters': []
    },
    {
        'name': 'POWER_SIM_ON_RESP',
        'client_to_server': False,
        'id': 0x0C,
        'parameters': [(0x02, True)]
    },
    {
        'name': 'RESET_SIM_REQ',
        'client_to_server': True,
        'id': 0x0D,
        'parameters': []
    },
    {
        'name': 'RESET_SIM_RESP',
        'client_to_server': False,
        'id': 0x0E,
        'parameters': [(0x02, True)]
    },
    {
        'name': 'TRANSFER_CARD_READER_STATUS_REQ',
        'client_to_server': True,
        'id': 0x0F,
        'parameters': []
    },
    {
        'name': 'TRANSFER_CARD_READER_STATUS_RESP',
        'client_to_server': False,
        'id': 0x10,
        'parameters': [(0x02, True), (0x07, False)]
    },
    {
        'name': 'STATUS_IND',
        'client_to_server': False,
        'id': 0x11,
        'parameters': [(0x08, True)]
    },

    {
        'name': 'ERROR_RESP',
        'client_to_server': False,
        'id': 0x12,
        'parameters': []
    },
    {
        'name': 'SET_TRANSPORT_PROTOCOL_REQ',
        'client_to_server': True,
        'id': 0x13,
        'parameters': [(0x09, True)]
    },
    {
        'name': 'SET_TRANSPORT_PROTOCOL_RESP',
        'client_to_server': False,
        'id': 0x14,
        'parameters': [(0x02, True)]
    },

]


class BluetoothSapSimLink(LinkBase):
    # UUID for SIM Access Service
    UUID_SIM_ACCESS = '0000112d-0000-1000-8000-00805f9b34fb'
    SAP_MAX_MSG_SIZE = 0xffff

    def __init__(self, bt_mac_addr, **kwargs):
        super().__init__(**kwargs)
        self._bt_mac_addr = bt_mac_addr
        self._max_msg_size = self.SAP_MAX_MSG_SIZE
        self._atr = None
        self.connected = False
        # at first try to find the bluetooth device
        if not bluetooth.find_service(address=bt_mac_addr):
            raise ReaderError(f"Cannot find bluetooth device [{bt_mac_addr}]")
        # then check for rSAP support
        self._sim_service = next(iter(bluetooth.find_service(
            uuid=self.UUID_SIM_ACCESS, address=bt_mac_addr)), None)
        if not self._sim_service:
            raise ReaderError(
                f"Bluetooth device [{bt_mac_addr}] does not support SIM Access service")

    def __del__(self):
        # TODO: do something here
        pass

    def wait_for_card(self, timeout=None, newcardonly=False):
        self.connect()

    def connect(self):
        try:
            self._sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self._sock.connect(
                (self._sim_service['host'], self._sim_service['port']))
            self.connected = True
            self.establish_sim_connection()
            self.retrieve_atr()
        except:
            raise ReaderError("Cannot connect to SIM Access service")

    # def get_atr(self):
    #	return bytes(self._con.getATR())

    def disconnect(self):
        if self.connected:
            self.send_sap_message("DISCONNECT_REQ")
        self._sock.close()
        self.connected = False

    def reset_card(self):
        if self._connected:
            self.send_sap_message("RESET_SIM_REQ")
            msg_name, param_list = self._recv_sap_response('RESET_SIM_RESP')
            connection_status = next(
                (x[1] for x in param_list if x[0] == 'ConnectionStatus'), 0x01)
            if connection_status == 0x00:
                logger.info("SIM Reset successful")
                return 1
        else:
            self.disconnect()
            self.connect()
        return 1

    def send_sap_message(self, msg_name, param_list=[]):
        # maby check for idle state before sending?
        message = self.craft_sap_message(msg_name, param_list)
        return self._sock.send(message)

    def _recv_sap_message(self):
        resp = self._sock.recv(self._max_msg_size)
        msg_name, param_list = self.parse_sap_message(resp)
        return msg_name, param_list

    def _recv_sap_response(self, waiting_msg_name):
        while self.connected:
            msg_name, param_list = self._recv_sap_message()
            self.handle_sap_response_generic(msg_name, param_list)
            if msg_name == waiting_msg_name:
                return msg_name, param_list

    def establish_sim_connection(self, retries=5):
        self.send_sap_message(
            "CONNECT_REQ", [("MaxMsgSize", self._max_msg_size)])
        msg_name, param_list = self._recv_sap_response('CONNECT_RESP')

        connection_status = next(
            (x[1] for x in param_list if x[0] == 'ConnectionStatus'), 0x01)
        if connection_status == 0x00:
            logger.info("Successfully connected to rSAP server")
            return
        elif connection_status == 0x02:  # invalid max size
            self._max_msg_size = next(
                (x[1] for x in param_list if x[0] == 'MaxMsgSize'), self._max_msg_size)
            return self.establish_sim_connection(retries)
        else:
            logger.info(
                "Wait some seconds and make another connection attempt...")
            time.sleep(5)
            return self.establish_sim_connection(retries-1)

    def retrieve_atr(self):
        self.send_sap_message("TRANSFER_ATR_REQ")
        msg_name, param_list = self._recv_sap_response('TRANSFER_ATR_RESP')
        result_code = next(
            (x[1] for x in param_list if x[0] == 'ResultCode'), 0x01)
        if result_code == 0x00:
            atr = next((x[1] for x in param_list if x[0] == 'ATR'), None)
            self._atr = atr
            logger.debug(f"Recieved ATR from server: {b2h(atr)}")

    def handle_sap_response_generic(self, msg_name, param_list):
        # print stuff
        logger.debug(
            f"Recieved sap message from server: {(msg_name, param_list)}")
        for param in param_list:
            param_name, param_value = param
            if param_name == 'ConnectionStatus':
                new_status = SAP_CONNECTION_STATUS.get(param_value)
                logger.debug(f"Connection Status: {new_status}")
            elif param_name == 'StatusChange':
                new_status = SAP_STATUS_CHANGE.get(param_value)
                logger.debug(f"SIM Status: {new_status}")
            elif param_name == 'ResultCode':
                response_code = SAP_RESULT_CODE.get(param_value)
                logger.debug(f"ResultCode: {response_code}")

        # handle some important stuff:
        if msg_name == 'DISCONNECT_IND':
            # graceful disconnect --> technically could still send some apdus
            # however, we just make it short and sweet and directly disconnect
            self.send_sap_message("DISCONNECT_REQ")
        elif msg_name == 'DISCONNECT_RESP':
            self.connected = False
            logger.info(f"Client disconnected")

        # if msg_name == 'CONNECT_RESP':
        # elif msg_name == 'DISCONNECT_RESP':
        # elif msg_name == 'DISCONNECT_IND':
        # elif msg_name == 'TRANSFER_APDU_RESP':
        # elif msg_name == 'TRANSFER_ATR_RESP':
        # elif msg_name == 'POWER_SIM_OFF_RESP':
        # elif msg_name == 'POWER_SIM_ON_RESP':
        # elif msg_name == 'RESET_SIM_RESP':
        # elif msg_name == 'TRANSFER_CARD_READER_STATUS_RESP':
        # elif msg_name == 'STATUS_IND':
        # elif msg_name == 'ERROR_RESP':
        # elif msg_name == 'SET_TRANSPORT_PROTOCOL_RESP':
        # else:
        #  logger.error("Unknown message...")

    def craft_sap_message(self, msg_name, param_list=[]):
        msg_info = next(
            (x for x in SAP_MESSAGES if x.get('name') == msg_name), None)
        if not msg_info:
            raise ProtocolError(f"Unknown SAP message name ({msg_name})")

        msg_id = msg_info.get('id')
        msg_params = msg_info.get('parameters')
        # msg_direction = msg_info.get('client_to_server')

        param_cnt = len(param_list)

        msg_bytes = struct.pack(
            '!BBH',
            msg_id,
            param_cnt,
            0
        )

        allowed_params = (x[0] for x in msg_params)
        mandatory_params = (x[0] for x in msg_params if x[1] == True)

        collected_param_ids = []

        for p in param_list:
            param_name = p[0]
            param_value = p[1]

            param_id = next(
                (x.get('id') for x in SAP_PARAMETERS if x.get('name') == param_name), None)
            if param_id is None:
                raise ProtocolError(f"Unknown SAP param name ({param_name})")
            if param_id not in allowed_params:
                raise ProtocolError(
                    f"Parameter {param_name} not allowed in message {msg_name}")

            collected_param_ids.append(param_id)
            msg_bytes += self.craft_sap_parameter(param_name, param_value)

        if not set(mandatory_params).issubset(collected_param_ids):
            raise ProtocolError(
                f"Missing mandatory parameter for message {msg_name} (mandatory: {*mandatory_params,}, present: {*collected_param_ids,})")

        return msg_bytes

    def calc_padding_len(self, length, blocksize=4):
        extra = length % blocksize
        if extra > 0:
            return blocksize-extra
        return 0

    def pad_bytes(self, b, blocksize=4):
        padding_len = self.calc_padding_len(len(b), blocksize)
        return b + bytearray(padding_len)

    def craft_sap_parameter(self, param_name, param_value):
        param_info = next(
            (x for x in SAP_PARAMETERS if x.get('name') == param_name), None)
        param_id = param_info.get('id')
        param_len = param_info.get('length')

        if isinstance(param_value, str):
            param_value = h2b(param_value)

        if isinstance(param_value, int):
            # TODO: when param len is not set we have a problem :X
            param_value = (param_value).to_bytes(param_len, byteorder='big')

        if param_len is None:
            # just assume param length from bytearray
            param_len = len(param_value)
        elif param_len != len(param_value):
            raise ProtocolError(
                f"Invalid param length (epected {param_len} but got {len(param_value)} bytes)")

        param_bytes = struct.pack(
            f'!BBH{param_len}s',
            param_id,
            0,  # reserved
            param_len,
            param_value
        )
        param_bytes = self.pad_bytes(param_bytes)
        return param_bytes

    def parse_sap_message(self, msg_bytes):
        header_struct = struct.Struct('!BBH')
        msg_id, param_cnt, reserved = header_struct.unpack_from(msg_bytes)
        msg_bytes = msg_bytes[header_struct.size:]

        msg_info = next(
            (x for x in SAP_MESSAGES if x.get('id') == msg_id), None)

        msg_name = msg_info.get('name')
        msg_params = msg_info.get('parameters')
        # msg_direction = msg_info.get('client_to_server')

        # TODO: check if params allowed etc
        # allowed_params = (x[0] for x in msg_params)
        # mandatory_params = (x[0] for x in msg_params if x[1] == True)

        param_list = []

        for x in range(param_cnt):
            param_name, param_value, total_len = self.parse_sap_parameter(
                msg_bytes)
            param_list.append((param_name, param_value))
            msg_bytes = msg_bytes[total_len:]

        return msg_name, param_list

    def parse_sap_parameter(self, param_bytes):
        header_struct = struct.Struct('!BBH')
        total_len = header_struct.size
        param_id, reserved, param_len = header_struct.unpack_from(param_bytes)
        padding_len = self.calc_padding_len(param_len)
        paramval_struct = struct.Struct(f'!{param_len}s{padding_len}s')
        param_value, padding = paramval_struct.unpack_from(
            param_bytes[total_len:])
        total_len += paramval_struct.size

        param_info = next(
            (x for x in SAP_PARAMETERS if x.get('id') == param_id), None)
        # TODO: check if param found, length plausible, ...
        param_name = param_info.get('name')

        # if it is set then value was int, otherwise it is byte array
        if param_info.get('length') is not None:
            param_value = int.from_bytes(param_value, "big")
        # param_len = param_info.get('length')
        return param_name, param_value, total_len

    def _send_apdu_raw(self, pdu):
        if isinstance(pdu, str):
            pdu = h2b(pdu)
        self.send_sap_message("TRANSFER_APDU_REQ", [("CommandAPDU", pdu)])

        msg_name, param_list = self._recv_sap_response('TRANSFER_APDU_RESP')
        result_code = next(
            (x[1] for x in param_list if x[0] == 'ResultCode'), 0x01)
        if result_code == 0x00:
            response = next(
                (x[1] for x in param_list if x[0] == 'ResponseAPDU'), None)
            sw = response[-2:]
            data = response[0:-2]
            return b2h(data), b2h(sw)
        return None, None
