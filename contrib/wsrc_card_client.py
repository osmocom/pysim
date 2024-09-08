#!/usr/bin/env python3

"""Connect smartcard to a remote server, so the remote server can take control and
perform commands on it."""

import sys
import json
import logging
import argparse
from osmocom.utils import b2h
import websockets

from pySim.transport import init_reader, argparse_add_reader_args, LinkBase
from pySim.commands import SimCardCommands
from pySim.wsrc.client_blocking import WsClientBlocking
from pySim.exceptions import NoCardError
from pySim.wsrc import WSRC_DEFAULT_PORT_CARD

logging.basicConfig(format="[%(levelname)s] %(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

class CardWsClientBlocking(WsClientBlocking):
    """Implementation of the card (reader) client of the WSRC (WebSocket Remote Card) protocol"""

    def __init__(self, ws_uri, tp: LinkBase):
        super().__init__('card', ws_uri)
        self.tp = tp

    def perform_outbound_hello(self):
        hello_data = {
            'atr': b2h(self.tp.get_atr()),
            # TODO: include various card information in the HELLO message
        }
        super().perform_outbound_hello(hello_data)

    def handle_rx_c_apdu(self, rx: dict):
        """handle an inbound APDU transceive command"""
        data, sw = self.tp.send_apdu(rx['command'])
        tx = {
            'response': data,
            'sw': sw,
        }
        self.tx_json('r_apdu', tx)

    def handle_rx_disconnect(self, rx: dict):
        """server tells us to disconnect"""
        self.tx_json('disconnect_ack')
        # FIXME: tear down connection and/or terminate entire program

    def handle_rx_state_notification(self, rx: dict):
        logger.info("State Notification: %s" % rx['new_state'])

    def handle_rx_print(self, rx: dict):
        """print a message (text) given by server to the local console/log"""
        logger.info("SERVER MSG: %s" % rx['message'])
        # no response

    def handle_rx_reset_req(self, rx: dict):
        """server tells us to reset the card"""
        self.tp.reset_card()
        self.tx_json('reset_resp', {'atr': b2h(self.tp.get_atr())})


parser = argparse.ArgumentParser()
argparse_add_reader_args(parser)
parser.add_argument("--uri", default="ws://localhost:%u/" % (WSRC_DEFAULT_PORT_CARD),
                    help="URI of the sever to which to connect")


if __name__ == '__main__':
    opts = parser.parse_args()

    # open the card reader / slot
    logger.info("Initializing Card Reader...")
    try:
        tp = init_reader(opts)
    except Exception as e:
        logger.fatal("Error opening reader: %s" % e)
        sys.exit(1)

    logger.info("Connecting to Card...")
    try:
        tp.connect()
    except NoCardError as e:
        logger.fatal("Error opening card! Is a card inserted in the reader?")
        sys.exit(1)

    scc = SimCardCommands(transport=tp)
    logger.info("Detected Card with ATR: %s" % b2h(tp.get_atr()))

    # TODO: gather various information about the card; print it

    # create + connect the client to the server
    cl = CardWsClientBlocking(opts.uri, tp)
    logger.info("Connecting to remote server...")
    try:
        cl.connect()
        logger.info("Successfully connected to Server")
    except ConnectionRefusedError as e:
        logger.fatal(e)
        sys.exit(1)

    try:
        while True:
            # endless loop: wait for inbound command from server + execute it
            cl.rx_and_execute_cmd()
    except websockets.exceptions.ConnectionClosedOK as e:
        print(e)
        sys.exit(1)
    except KeyboardInterrupt as e:
        print(e.__class__.__name__)
        sys.exit(2)
