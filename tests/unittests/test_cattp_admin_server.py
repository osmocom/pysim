#!/usr/bin/env python3

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

import os.path
import importlib.util
import socket
import threading
import time
import unittest

from osmocom.utils import h2b, b2h

from pySim.cattp import CatTpConnection, RST_NORMAL
from pySim.ota import OtaKeyset, OtaDialectCatTp, encode_expanded_cmd, ExpandedRemoteResp

_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'contrib', 'cattp_admin_server.py')
_spec = importlib.util.spec_from_file_location('cattp_admin_server', _PATH)
cattp_admin_server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cattp_admin_server)

KEYSET = OtaKeyset(algo_crypt='aes_cbc', kic_idx=2, algo_auth='aes_cmac', kid_idx=2,
                   kic=h2b('200102030405060708090a0b0c0d0e0f'),
                   kid=h2b('201102030405060708090a0b0c0d0e0f'))
SPI = {'counter': 'no_counter', 'ciphering': True, 'rc_cc_ds': 'cc', 'por_in_submit': False,
       'por_shall_be_ciphered': True, 'por_rc_cc_ds': 'cc', 'por': 'por_required'}
TAR = h2b('b00010')


class _FakeCard:
    """CAT_TP client that unpacks each command packet and answers 9000 for every C-APDU"""

    def __init__(self, port, remote_format):
        self.dialect = OtaDialectCatTp()
        self.remote_format = remote_format
        self.received = []
        self.conn = CatTpConnection(4711, on_sdu=self._on_sdu, max_pdu=256)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)
        self.sock.connect(('127.0.0.1', port))

    def _on_sdu(self, conn, sdu):
        tar, spi, apdu = self.dialect.decode_cmd(KEYSET, sdu)
        self.received.append(apdu)
        if self.remote_format == 'expanded':
            n = apdu.count(b'\x22')          # good enough for the C-APDUs used here
            data = ExpandedRemoteResp.build(dict(body=dict(
                num_executed=dict(number_of_commands=n),
                responses=[dict(r_apdu=dict(response_data='', status_word='9000'))] * n)))
        else:
            data = h2b('01' '9000')
        conn.send_sdu(self.dialect.encode_resp(KEYSET, spi, tar, data=data))

    def run(self, deadline=5.0):
        self.conn.connect(self.sock.getpeername()[1], identification=h2b('8949'))
        end = time.monotonic() + deadline
        while time.monotonic() < end and self.conn.state != 'CLOSE-WAIT':
            for raw in self.conn.pop_tx():
                self.sock.send(raw)
            try:
                self.conn.on_pdu(self.sock.recv(65535))
            except socket.timeout:
                self.conn.on_timer()
        for raw in self.conn.pop_tx():
            self.sock.send(raw)
        self.sock.close()


class CatTpAdminServerTest(unittest.TestCase):
    APDUS = [h2b('00a40004023f00'), h2b('00b0000010')]

    def _run(self, batch, remote_format):
        commands = cattp_admin_server.build_commands(self.APDUS, batch, remote_format)
        ended = []
        server = cattp_admin_server.CatTpAdminServer('127.0.0.1', 0, KEYSET, SPI, TAR, commands,
                                                     remote_format=remote_format,
                                                     on_session_end=ended.append, rto=0.5)
        server.bind()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        card = _FakeCard(server.port, remote_format)
        card.run()
        deadline = time.monotonic() + 2.0
        while not ended and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(card.conn.close_reason, RST_NORMAL)
        self.assertEqual(len(ended), 1)
        return card, ended[0]

    def test_compact_one_packet_per_apdu(self):
        card, session = self._run(batch=False, remote_format='compact')
        self.assertEqual(card.received, self.APDUS)
        self.assertEqual([d.last_status_word for _, d in session.responses], ['9000', '9000'])

    def test_compact_batch(self):
        card, session = self._run(batch=True, remote_format='compact')
        self.assertEqual(card.received, [b''.join(self.APDUS)])
        self.assertEqual(len(session.responses), 1)

    def test_expanded_batch(self):
        card, session = self._run(batch=True, remote_format='expanded')
        self.assertEqual(card.received, [encode_expanded_cmd(self.APDUS)])
        res, dec = session.responses[0]
        self.assertEqual(res.response_status, 'por_ok')
        self.assertEqual(dec.number_of_commands, 2)

    def test_build_commands(self):
        self.assertEqual(cattp_admin_server.build_commands([], True, 'compact'), [])
        self.assertEqual(cattp_admin_server.build_commands(self.APDUS, False, 'expanded'),
                         [[self.APDUS[0]], [self.APDUS[1]]])


if __name__ == "__main__":
    unittest.main()
