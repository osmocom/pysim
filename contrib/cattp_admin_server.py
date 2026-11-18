#!/usr/bin/env python3
"""CAT_TP Remote Administration Server for RAM/RFM over BIP, ETSI TS 102 225 section 6"""

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Eric Wild <ewild@sysmocom.de>
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

# The UDP end of "OTA over BIP" for cards that do CAT_TP instead of SCP81:
# - contrib/cattp_trigger.py builds the PUSH that makes the card OPEN CHANNEL to us and SYN
# - once the link is OPEN this server sends the queued C-APDUs as TS 102 225 secured
#   command packets, one per SDU, the same SCP80 keys and TAR as OTA over SMS
# - the card answers each with a secured response packet, decoded and logged here
# - after the last one the link is closed with RST, the card then closes the BIP channel
#
# Same command line spirit as scp81_admin_server.py, same OTA options as smpp-ota-tool.py.

import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Callable

from osmocom.utils import h2b, b2h

from pySim.cattp import CatTpServer, CatTpConnection, RST_NORMAL
from pySim.ota import (OtaKeyset, OtaDialectCatTp, OtaCheckError, argparse_add_ota_args,
                       ota_keyset_from_args, ota_spi_from_args)

logger = logging.getLogger(Path(__file__).stem)


def format_decoded_response(res, dec) -> str:
    bits = ['status=%s cntr=%s' % (res.response_status, b2h(res.cntr))]
    if dec is None:
        return bits[0]
    if 'commands' in dec:                        # expanded
        bits.append('%u command(s) executed' % dec.number_of_commands)
        for i, c in enumerate(dec.commands):
            bits.append('  R-APDU[%u]: SW=%s data=%s' % (i, c.status_word, c.response_data or '-'))
        if dec.get('truncated'):
            bits.append('  TRUNCATED: SW 62F1, the card stopped executing the script')
        if dec.bad_format is not None:
            bits.append('  bad-format: %s' % dec.bad_format)
    else:                                        # compact
        bits.append('%u command(s) executed, last SW=%s data=%s' % (
            dec.number_of_commands, dec.last_status_word, dec.last_response_data or '-'))
    return '\n'.join(bits)


class CatTpAdminSession:
    """One card: hand it the queued commands in order, one secured packet per SDU."""

    def __init__(self, otak: OtaKeyset, spi: dict, tar: bytes, commands: List,
                 remote_format: str = 'compact',
                 on_response: Optional[Callable[[object, object], None]] = None):
        self.otak = otak
        self.spi = spi
        self.tar = tar
        self.pending = list(commands)
        self.remote_format = remote_format
        self.on_response = on_response
        self.dialect = OtaDialectCatTp()
        self.responses = []

    def start(self, conn: CatTpConnection):
        logger.info('link OPEN with identification %s, %u command(s) queued',
                    b2h(conn.peer_identification), len(self.pending))
        self._send_next(conn)

    def _send_next(self, conn: CatTpConnection):
        if not self.pending:
            logger.info('no more commands, closing the link')
            conn.close(RST_NORMAL)
            return
        cmd = self.pending.pop(0)
        secured = self.dialect.encode_cmd(self.otak, self.tar, self.spi, cmd,
                                          remote_format=self.remote_format)
        if self.spi['counter'] != 'no_counter':
            self.otak.cntr += 1
        logger.info('-> command packet (%uB): %s', len(secured), b2h(secured))
        conn.send_sdu(secured)

    def _decode(self, sdu: bytes):
        try:
            return self.dialect.decode_resp(self.otak, self.spi, sdu, remote_format=self.remote_format)
        except (ValueError, OtaCheckError):
            # a card that could not process our packet answers in the clear
            spi = dict(self.spi, por_shall_be_ciphered=False, por_rc_cc_ds='no_rc_cc_ds')
            return self.dialect.decode_resp(self.otak, spi, sdu, remote_format=self.remote_format)

    def on_sdu(self, conn: CatTpConnection, sdu: bytes):
        logger.debug('<- response packet (%uB): %s', len(sdu), b2h(sdu))
        try:
            res, dec = self._decode(sdu)
        except Exception as e:
            logger.error('undecodable response packet %s: %s', b2h(sdu), e)
            conn.close(RST_NORMAL)
            return
        self.responses.append((res, dec))
        logger.info('card response:\n%s', format_decoded_response(res, dec))
        if self.on_response:
            self.on_response(res, dec)
        self._send_next(conn)


class CatTpAdminServer:
    """CatTpServer that runs a CatTpAdminSession for every card that connects."""

    def __init__(self, host: str, port: int, otak: OtaKeyset, spi: dict, tar: bytes,
                 commands: List, remote_format: str = 'compact',
                 on_response: Optional[Callable[[object, object], None]] = None,
                 on_session_end: Optional[Callable[[CatTpAdminSession], None]] = None,
                 **conn_kwargs):
        self.otak = otak
        self.spi = spi
        self.tar = tar
        self.commands = commands
        self.remote_format = remote_format
        self.on_response = on_response
        self.on_session_end = on_session_end
        self.sessions: Dict[int, CatTpAdminSession] = {}
        self.server = CatTpServer(host, port, on_sdu=self._on_sdu, on_state=self._on_state, **conn_kwargs)

    def bind(self) -> int:
        return self.server.bind()

    @property
    def port(self) -> int:
        return self.server.port

    def serve_forever(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()

    def _on_state(self, conn: CatTpConnection, state: str):
        if state == CatTpConnection.OPEN:
            session = CatTpAdminSession(self.otak, self.spi, self.tar, self.commands,
                                        self.remote_format, self.on_response)
            self.sessions[id(conn)] = session
            session.start(conn)
        elif state in (CatTpConnection.CLOSE_WAIT, CatTpConnection.CLOSED):
            session = self.sessions.pop(id(conn), None)
            if session is not None:
                logger.info('session ended: %u response(s) collected', len(session.responses))
                if self.on_session_end:
                    self.on_session_end(session)

    def _on_sdu(self, conn: CatTpConnection, sdu: bytes):
        session = self.sessions.get(id(conn))
        if session is None:
            logger.warning('SDU without a session, ignoring')
            return
        session.on_sdu(conn, sdu)


def build_commands(apdus: List[bytes], batch: bool, remote_format: str) -> List:
    """Group the APDUs per secured packet: one concatenated string for compact, a list for expanded."""
    if not apdus:
        return []
    groups = [apdus] if batch else [[a] for a in apdus]
    if remote_format == 'expanded':
        return groups
    return [b''.join(g) for g in groups]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host', default='0.0.0.0', help='IP to bind to')
    parser.add_argument('--port', type=int, default=6001,
                        help='UDP port, also the CAT_TP port the PUSH points the card to')
    argparse_add_ota_args(parser)
    parser.add_argument('--format', choices=['compact', 'expanded'], default='compact',
                        help='Remote Application data format, TS 102 226 5.1 / 5.2')
    parser.add_argument('--apdu', '-a', action='append', default=[], metavar='HEX',
                        help='C-APDU to send, may be given several times, executed in order')
    parser.add_argument('--apdu-file', help='File with one C-APDU (hex) per line, # comments allowed')
    parser.add_argument('--batch', action='store_true', help='All C-APDUs in one command packet')
    parser.add_argument('--max-pdu', type=int, default=1024,
                        help='largest PDU we accept, the card must not exceed it')
    parser.add_argument('--max-sdu', type=int, default=65535, help='largest SDU we accept')
    parser.add_argument('--window', type=int, default=4, help='receive window in PDUs')
    parser.add_argument('--rto', type=float, default=5.0,
                        help='retransmission timeout in seconds, a card behind BIP is slow')
    parser.add_argument('--retries', type=int, default=3, help='retransmissions before RST')
    parser.add_argument('-v', '--verbose', action='store_true', help='enable debug output')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    apdus = [h2b(a) for a in args.apdu]
    if args.apdu_file:
        for line in Path(args.apdu_file).read_text().splitlines():
            line = line.split('#', 1)[0].strip()
            if line:
                apdus.append(h2b(line))
    commands = build_commands(apdus, args.batch, args.format)
    if not commands:
        logger.warning('no C-APDUs: the link will be closed right after the handshake')

    otak = ota_keyset_from_args(args)
    spi = ota_spi_from_args(args)

    server = CatTpAdminServer(args.host, args.port, otak, spi, h2b(args.tar), commands,
                              remote_format=args.format, max_pdu=args.max_pdu, max_sdu=args.max_sdu,
                              window=args.window, rto=args.rto, max_retries=args.retries)
    server.bind()
    logger.info('trigger: contrib/cattp_trigger.py --ip <our ip> --port %u', server.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info('shutting down')
        server.shutdown()


if __name__ == '__main__':
    main()
