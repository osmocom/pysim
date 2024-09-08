# Copyright (C) 2024  Harald Welte <laforge@gnumonks.org>
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

import argparse
from typing import Optional

from osmocom.utils import h2i, i2h, Hexstr, is_hexstr

from pySim.exceptions import NoCardError, ProtocolError, ReaderError
from pySim.transport import LinkBase
from pySim.utils import ResTuple
from pySim.wsrc import WSRC_DEFAULT_PORT_USER
from pySim.wsrc.client_blocking import WsClientBlocking

class UserWsClientBlocking(WsClientBlocking):
    def __init__(self, ws_uri: str, **kwargs):
        super().__init__('user', ws_uri, **kwargs)

    def select_card(self, id_type:str, id_str:str):
        rx = self.transceive_json('select_card', {'id_type': id_type, 'id_str': id_str},
                                  'select_card_ack')
        return rx

    def reset_card(self):
        self.transceive_json('reset_req', {}, 'reset_resp')

    def xceive_apdu_raw(self, cmd: Hexstr) -> ResTuple:
        rx = self.transceive_json('c_apdu', {'command': cmd}, 'r_apdu')
        return rx['response'], rx['sw']


class WsrcSimLink(LinkBase):
    """ pySim: WSRC (WebSocket Remote Card) reader transport link."""
    name = 'WSRC'

    def __init__(self, opts: argparse.Namespace, **kwargs):
        super().__init__(**kwargs)
        self.identities = {}
        self.server_url = opts.wsrc_server_url
        if opts.wsrc_eid:
            self.id_type = 'eid'
            self.id_str = opts.wsrc_eid
        elif opts.wsrc_iccid:
            self.id_type = 'iccid'
            self.id_str = opts.wsrc_iccid
        self.client = UserWsClientBlocking(self.server_url)
        self.client.connect()

    def __del__(self):
       # FIXME: disconnect from server
       pass

    def wait_for_card(self, timeout: Optional[int] = None, newcardonly: bool = False):
        self.connect()

    def connect(self):
        rx = self.client.select_card(self.id_type, self.id_str)
        self.identities = rx['identities']

    def get_atr(self) -> Hexstr:
        return h2i(self.identities['ATR'])

    def disconnect(self):
        self.__delete__()

    def _reset_card(self):
        self.client.reset_card()
        return 1

    def _send_apdu_raw(self, pdu: Hexstr) -> ResTuple:
        return self.client.xceive_apdu_raw(pdu)

    def __str__(self) -> str:
        return "WSRC[%s=%s]" % (self.id_type, self.id_str)

    @staticmethod
    def argparse_add_reader_args(arg_parser: argparse.ArgumentParser):
        wsrc_group = arg_parser.add_argument_group('WebSocket Remote Card',
            """WebSocket Remote Card (WSRC) is a protoocl by which remot cards / card readers
            can be accessed via a network.""")
        wsrc_group.add_argument('--wsrc-server-url', default='ws://localhost:%u' % WSRC_DEFAULT_PORT_USER,
                                help='URI of the WSRC server to connect to')
        wsrc_group.add_argument('--wsrc-iccid', type=is_hexstr,
                                help='ICCID of the card to open via WSRC')
        wsrc_group.add_argument('--wsrc-eid', type=is_hexstr,
                                help='EID of the card to open via WSRC')
