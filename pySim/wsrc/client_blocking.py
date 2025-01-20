"""Connect smartcard to a remote server, so the remote server can take control and
perform commands on it."""

import abc
import json
import logging
from typing import Optional
from websockets.sync.client import connect
from osmocom.utils import b2h

logger = logging.getLogger(__name__)

class WsClientBlocking(abc.ABC):
    """Generalized synchronous/blocking client for the WSRC (Web Socket Remote Card) protocol"""

    def __init__(self, cltype: str, ws_uri: str):
        self.client_type = cltype
        self.ws_uri = ws_uri
        self.ws = None

    def connect(self):
        self.ws = connect(uri=self.ws_uri)
        self.perform_outbound_hello()

    def tx_json(self, msg_type: str, d: dict = {}):
        """JSON-Encode and transmit a message to the given websocket."""
        d['msg_type'] = msg_type
        d_js = json.dumps(d)
        logger.debug("Tx: %s", d_js)
        self.ws.send(d_js)

    def tx_error(self, message: str):
        event = {
            'message': message,
        }
        self.tx_json('error', event)

    def rx_json(self):
        """Receive a single message from the given websocket and JSON-decode it."""
        rx = self.ws.recv()
        rx_js = json.loads(rx)
        logger.debug("Rx: %s", rx_js)
        assert 'msg_type' in rx
        return rx_js

    def transceive_json(self, tx_msg_type: str, tx_d: Optional[dict], rx_msg_type: str) -> dict:
        #As far as I understand, this sends something like this:
        #{'command': '00a40004022f0000', 'msg_type': 'c_apdu'}
        #
        #Maybe the message type should be excluded from the dict like:
        #
        #{'msg_type':'c_apdu', 'msg':{'command': '00a40004022f0000'}}
        #
        #I ran into this problem some time ago, when the message type descriptor is part of the message, then
        #things tend to get difficult as soon as there are more then one message item. Then the msg_type mixes with
        #the items of the message. At the moment the protocol is really simple, so this is not a problem yet, but
        #maybe we need to extend it later.
        #
        #Maybe it would be a good idea to write a JSON schema, even if we don't use it to verify the messages, this
        #would definetly help to see if json format definition is clean.
        #
        self.tx_json(tx_msg_type, tx_d)
        rx = self.rx_json()
        assert rx['msg_type'] == rx_msg_type
        return rx

    def perform_outbound_hello(self, tx: dict = {}):
        if not 'client_type' in tx:
            tx['client_type'] = self.client_type
        self.tx_json('hello', tx)
        rx = self.rx_json()
        assert rx['msg_type'] == 'hello_ack'
        return rx

    def rx_and_execute_cmd(self):
        """Receve and dispatch/execute a single command from the server."""
        rx = self.rx_json()
        handler = getattr(self, 'handle_rx_%s' % rx['msg_type'], None)
        if handler:
            handler(rx)
        else:
            logger.error('Received unknown/unsupported msg_type %s' % rx['msg_type'])
            self.tx_error('Message type "%s" is not supported' % rx['msg_type'])
