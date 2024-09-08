#!/usr/bin/env python

import json
import asyncio
import logging
import argparse
from typing import Optional, Tuple
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosedError
from osmocom.utils import Hexstr, swap_nibbles

from pySim.utils import SwMatchstr, ResTuple, sw_match, dec_iccid
from pySim.exceptions import SwMatchError
from pySim.wsrc import WSRC_DEFAULT_PORT_USER, WSRC_DEFAULT_PORT_CARD

logging.basicConfig(format="[%(levelname)s] %(asctime)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

card_clients = set()
user_clients = set()

class WsClientLogAdapter(logging.LoggerAdapter):
    """LoggerAdapter adding context (for now: remote IP/Port of client) to log"""
    def process(self, msg, kwargs):
        return '%s([%s]:%u) %s' % (self.extra['type'], self.extra['remote_addr'][0],
                                   self.extra['remote_addr'][1], msg), kwargs

class WsClient:
    def __init__(self, websocket, hello: dict):
        self.websocket = websocket
        self.hello = hello
        self.identity = {}
        self.logger = WsClientLogAdapter(logger, {'type': self.__class__.__name__,
                                                  'remote_addr': websocket.remote_address})

    def __str__(self):
        return '%s([%s]:%u)' % (self.__class__.__name__, self.websocket.remote_address[0],
                                self.websocket.remote_address[1])

    async def rx_json(self):
        rx = await self.websocket.recv()
        rx_js = json.loads(rx)
        self.logger.debug("Rx: %s", rx_js)
        assert 'msg_type' in rx
        return rx_js

    async def tx_json(self, msg_type:str, d: dict = {}):
        """Transmit a json-serializable dict to the peer"""
        d['msg_type'] = msg_type
        d_js = json.dumps(d)
        self.logger.debug("Tx: %s", d_js)
        await self.websocket.send(d_js)

    async def tx_hello_ack(self):
        await self.tx_json('hello_ack')

    async def xceive_json(self, msg_type:str, d:dict = {}, exp_msg_type:Optional[str] = None) -> dict:
        await self.tx_json(msg_type, d)
        rx = await self.rx_json()
        if exp_msg_type:
            assert rx['msg_type'] == exp_msg_type
        return rx;

    async def tx_error(self, message: str):
        """Transmit an error message to the peer"""
        event = {
            "message": message,
        }
        self.logger.error("Transmitting error message: '%s'" % message)
        await self.tx_json('error', event)

#    async def ws_hdlr(self):
#        """kind of a 'main' function for the websocket client: wait for incoming message,
#        and handle it."""
#        try:
#            async for message in self.websocket:
#                method = getattr(self, 'handle_rx_%s' % message['msg_type'], None)
#                if not method:
#                    await self.tx_error("Unknonw msg_type: %s" % message['msg_type'])
#                else:
#                    method(message)
#        except ConnectionClosedError:
#            # we handle this in the outer loop
#            pass

class CardClient(WsClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identity['ATR'] = self.hello['atr']
        self.state = 'init'

    def __str__(self):
        eid = self.identity.get('EID', None)
        if eid:
            return '%s(EID=%s)' % (self.__class__.__name__, eid)
        iccid = self.identity.get('ICCID', None)
        if iccid:
            return '%s(ICCID=%s)' % (self.__class__.__name__, iccid)
        return super().__str__()

    def listing_entry(self) -> dict:
        return {'remote_addr': self.websocket.remote_address,
                'identities': self.identity,
                'state': self.state}

    """A websocket client that represents a reader/card. This is what we use to talk to a card"""
    async def xceive_apdu_raw(self, cmd: Hexstr) -> ResTuple:
        """transceive a single APDU with the card"""
        message = await self.xceive_json('c_apdu', {'command': cmd}, 'r_apdu')
        return message['response'], message['sw']

    async def xceive_apdu(self, pdu: Hexstr) -> ResTuple:
        """transceive an APDU with the card, handling T=0 GET_RESPONSE cases"""
        prev_pdu = pdu
        data, sw = await self.xceive_apdu_raw(pdu)

        if sw is not None:
            while (sw[0:2] in ['9f', '61', '62', '63']):
                # SW1=9F: 3GPP TS 51.011 9.4.1, Responses to commands which are correctly executed
                # SW1=61: ISO/IEC 7816-4, Table 5 — General meaning of the interindustry values of SW1-SW2
                # SW1=62: ETSI TS 102 221 7.3.1.1.4 Clause 4b): 62xx, 63xx, 9xxx != 9000
                pdu_gr = pdu[0:2] + 'c00000' + sw[2:4]
                prev_pdu = pdu_gr
                d, sw = await self.xceive_apdu_raw(pdu_gr)
                data += d
            if sw[0:2] == '6c':
                # SW1=6C: ETSI TS 102 221 Table 7.1: Procedure byte coding
                pdu_gr = prev_pdu[0:8] + sw[2:4]
                data, sw = await self.xceive_apdu_raw(pdu_gr)

        return data, sw

    async def xceive_apdu_checksw(self, pdu: Hexstr, sw: SwMatchstr = "9000") -> ResTuple:
        """like xceive_apdu, but checking the status word matches the expected pattern"""
        rv = await self.xceive_apdu(pdu)
        last_sw = rv[1]

        if not sw_match(rv[1], sw):
            raise SwMatchError(rv[1], sw.lower())
        return rv

    async def card_reset(self):
        """reset the card"""
        rx = await self.xceive_json('reset_req', exp_msg_type='reset_resp')
        self.identity['ATR'] = rx['atr']

    async def notify_state(self):
        """notify the card client of a state [change]"""
        await self.tx_json('state_notification', {'new_state': self.state})

    async def get_iccid(self):
        """high-level method to obtain the ICCID of the card"""
        await self.xceive_apdu_checksw('00a40000023f00') # SELECT MF
        await self.xceive_apdu_checksw('00a40000022fe2') # SELECT EF.ICCID
        res, sw = await self.xceive_apdu_checksw('00b0000000') # READ BINARY
        return dec_iccid(res)

    async def get_eid_sgp22(self):
        """high-level method to obtain the EID of a SGP.22 consumer eUICC"""
        await self.xceive_apdu_checksw('00a4040410a0000005591010ffffffff8900000100')
        res, sw = await self.xceive_apdu_checksw('80e2910006bf3e035c015a')
        return res[-32:]

    async def set_state(self, new_state:str):
        self.logger.info("Card now in '%s' state" % new_state)
        self.state = new_state
        await self.notify_state()

    async def identify(self):
        # identify the card by asking for its EID and/or ICCID
        try:
            eid = await self.get_eid_sgp22()
            self.logger.debug("EID: %s", eid)
            self.identity['EID'] = eid
        except SwMatchError:
            pass
        try:
            iccid = await self.get_iccid()
            self.logger.debug("ICCID: %s", iccid)
            self.identity['ICCID'] = iccid
        except SwMatchError:
            pass
        await self.set_state('ready')

    async def associate_user(self, user):
        assert self.state == 'ready'
        self.user = user
        await self.set_state('associated')

    async def disassociate_user(self):
        assert self.user
        assert self.state == 'associated'
        await self.set_state('ready')

    @staticmethod
    def find_client_for_id(id_type: str, id_str: str) -> Optional['CardClient']:
        for c in card_clients:
            if c.state != 'ready':
                continue
            c_id = c.identity.get(id_type.upper(), None)
            if c_id and c_id.lower() == id_str.lower():
                return c
        return None

class UserClient(WsClient):
    """A websocket client representing a user application like pySim-shell."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = 'init'
        self.card = None

    async def associate_card(self, card: CardClient):
        assert self.state == 'init'
        self.card = card
        self.state = 'associated'

    async def disassociate_card(self):
        assert self.state == 'associated'
        self.card = None
        self.state = 'init'

    async def state_init(self):
        """Wait for incoming 'select_card' and process it."""
        while True:
            rx = await self.rx_json()
            if rx['msg_type'] == 'select_card':
                # look-up if the card can be found
                card = CardClient.find_client_for_id(rx['id_type'], rx['id_str'])
                if not card:
                    await self.tx_error('No CardClient found for %s == %s' % (rx['id_type'], rx['id_str']))
                    continue
                # transition to next statee
                await card.associate_user(self)
                await self.associate_card(card)
                await self.tx_json('select_card_ack', {'identities': card.identity})
                break
            elif rx['msg_type'] == 'list_cards':
                res = [x.listing_entry() for x in card_clients]
                await self.tx_json('list_cards_ack', {'cards': res})
            else:
                self.tx_error('Unknown message type %s' % rx['msg_type'])

    async def state_selected(self):
        while True:
            rx = await self.rx_json()
            if rx['msg_type'] == 'c_apdu':
                rsp, sw = await self.card.xceive_apdu_raw(rx['command'])
                await self.tx_json('r_apdu', {'response': rsp, 'sw': sw})
            elif rx['msg_type'] == 'reset_req':
                await self.card.card_reset()
                await self.tx_json('reset_resp')
            else:
                self.logger.warning("Unknown/unsupported command '%s' received" % rx['msg_type'])



async def card_conn_hdlr(websocket):
    """Handler for incoming connection to 'card' port."""
    # receive first message, which should be a 'hello'
    rx_raw = await websocket.recv()
    rx = json.loads(rx_raw)
    assert rx['msg_type'] == 'hello'
    client_type = rx['client_type']

    if client_type != 'card':
        logger.error("Rejecting client (unknown type %s) connection", client_type)
        raise ValueError("client_type '%s' != expected 'card'" % client_type)

    card = CardClient(websocket, rx)
    card.logger.info("connection accepted")
    # first go through identity phase
    async with asyncio.timeout(30):
        await card.tx_hello_ack()
        card.logger.info("hello-handshake completed")
        card_clients.add(card)
        # first obtain the identity of the card
        await card.identify()
    # then go into the "main loop"
    try:
        # wait 'indefinitely'. We cannot call websocket.recv() here, as we will call another
        # recv() while waiting for the R-APDU after forwarding one from the user client.
        await websocket.wait_closed()
    finally:
        card.logger.info("connection closed")
        card_clients.remove(card)


async def user_conn_hdlr(websocket):
    """Handler for incoming connection to 'user' port."""
    # receive first message, which should be a 'hello'
    rx_raw = await websocket.recv()
    rx = json.loads(rx_raw)
    assert rx['msg_type'] == 'hello'
    client_type = rx['client_type']

    if client_type != 'user':
        logger.error("Rejecting client (unknown type %s) connection", client_type)
        raise ValueError("client_type '%s' != expected 'card'" % client_type)

    user = UserClient(websocket, rx)
    user.logger.info("connection accepted")
    # first go through hello phase
    async with asyncio.timeout(10):
        await user.tx_hello_ack()
        user.logger.info("hello-handshake completed")
        user_clients.add(user)
        # first wait for the user to specify the select the card
        try:
            await user.state_init()
        except ConnectionClosedError:
            user.logger.info("connection closed")
            user_clients.remove(user)
            return
        except asyncio.exceptions.CancelledError: # direct cause of TimeoutError
            user.logger.error("User failed to transition to 'associated' state within 10s")
            user_clients.remove(user)
            return
        except Exception as e:
            user.logger.error("Unknown exception %s", e)
            raise e
            user_clients.remove(user)
            return
    # then perform APDU exchanges without any time limit
    try:
        await user.state_selected()
    except ConnectionClosedError:
        pass
    finally:
        user.logger.info("connection closed")
        await user.card.disassociate_user()
        await user.disassociate_card()
        user_clients.remove(user)


parser = argparse.ArgumentParser(description="""Osmocom WebSocket Remote Card server""")
parser.add_argument('--user-bind-port', type=int, default=WSRC_DEFAULT_PORT_USER,
                    help="port number to bind for connections from users")
parser.add_argument('--user-bind-host', type=str, default='localhost',
                    help="local Host/IP to bind for connections from users")
parser.add_argument('--card-bind-port', type=int, default=WSRC_DEFAULT_PORT_CARD,
                    help="port number to bind for connections from cards")
parser.add_argument('--card-bind-host', type=str, default='localhost',
                    help="local Host/IP to bind for connections from cards")

if __name__ == '__main__':
    opts = parser.parse_args()

    async def main():
        # we use different ports for user + card connections to ensure they can
        # have different packet filter rules apply to them
        async with serve(card_conn_hdlr, opts.card_bind_host, opts.card_bind_port), serve(user_conn_hdlr, opts.user_bind_host, opts.user_bind_port):
            await asyncio.get_running_loop().create_future() # run forever

    asyncio.run(main())
