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

import socket
import threading
import time
import unittest
from unittest import mock

from osmocom.utils import b2h, h2b

from pySim.cattp import (Pdu, PduStruct, FLAG_BITS, CatTpConnection, CatTpServer, CatTpError, checksum,
                         FLAG_SYN, FLAG_ACK, FLAG_EACK, FLAG_RST, FLAG_NUL, FLAG_SEG,
                         RST_NORMAL, RST_MAX_RETRIES, RST_VERSION, RST_UNEXPECTED_PDU)


class PduCodecTest(unittest.TestCase):

    def test_checksum_rfc1071_example(self):
        self.assertEqual(checksum(h2b('0001f203f4f5f6f7')), 0x220d)

    def test_syn_golden(self):
        # TS 102 127 5.7: flags|ver 80, RFU, header length 17 hex (12 + max PDU + max SDU + id length), ports,
        # data length 0, seq 100, ack, window, checksum, max PDU 1024, max SDU 1024, id length 0
        pdu = Pdu(FLAG_SYN, 1024, 6001, seq=100, window=4, max_pdu=1024, max_sdu=1024)
        raw = pdu.to_bytes()
        self.assertEqual(b2h(raw), '80000017' '0400' '1771' '0000' '0064' '0000' '0004' '5c0f'
                                   '0400' '0400' '00')
        back = Pdu.from_bytes(raw)
        self.assertTrue(back.syn)
        self.assertEqual((back.src_port, back.dst_port, back.seq, back.window), (1024, 6001, 100, 4))
        self.assertEqual((back.max_pdu, back.max_sdu, back.identification), (1024, 1024, b''))

    def test_flag_bits(self):
        # TS 102 127 figure 39: b8 SYN, b7 ACK, b6 EACK, b5 RST, b4 NUL, b3 SEG, b2..b1 version
        self.assertEqual((FLAG_SYN, FLAG_ACK, FLAG_EACK, FLAG_RST, FLAG_NUL, FLAG_SEG),
                         (0x80, 0x40, 0x20, 0x10, 0x08, 0x04))
        self.assertEqual(Pdu(FLAG_ACK | FLAG_SEG, 1, 2, data=b'x').to_bytes()[0], 0x44)
        self.assertEqual(Pdu(FLAG_SYN, 1, 2, version=1).to_bytes()[0], 0x81)

    def test_roundtrip_all_types(self):
        cases = [
            Pdu(FLAG_SYN, 5000, 6001, seq=7, window=2, max_pdu=512, max_sdu=2048,
                identification=h2b('89490200001234567890')),
            Pdu(FLAG_SYN | FLAG_ACK, 6001, 5000, seq=9, ack=7, window=4, max_pdu=1024, max_sdu=65535),
            Pdu(FLAG_ACK, 6001, 5000, seq=10, ack=8, window=4),
            Pdu(FLAG_ACK, 6001, 5000, seq=10, ack=8, window=4, data=bytes(range(200))),
            Pdu(FLAG_ACK | FLAG_SEG, 6001, 5000, seq=10, ack=8, window=4, data=b'seg'),
            Pdu(FLAG_ACK | FLAG_EACK, 6001, 5000, seq=10, ack=8, window=4, eack=(10, 12)),
            Pdu(FLAG_ACK | FLAG_EACK, 6001, 5000, seq=10, ack=8, window=4, eack=(11,), data=b'd'),
            Pdu(FLAG_RST, 6001, 5000, seq=10, rst_reason=RST_VERSION),
            Pdu(FLAG_RST | FLAG_ACK, 6001, 5000, seq=10, ack=8, rst_reason=RST_NORMAL),
            Pdu(FLAG_NUL | FLAG_ACK, 6001, 5000, seq=10, ack=8, window=4),
            Pdu(FLAG_NUL | FLAG_ACK | FLAG_EACK, 6001, 5000, seq=10, ack=8, window=4, eack=(10,)),
        ]
        for pdu in cases:
            with self.subTest(pdu=repr(pdu)):
                raw = pdu.to_bytes()
                self.assertEqual(raw[3] + len(pdu.data), len(raw))         # header length
                back = Pdu.from_bytes(raw)
                for f in Pdu.__slots__:
                    self.assertEqual(getattr(back, f), getattr(pdu, f), f)
                self.assertEqual(back.to_bytes(), raw)

    def test_rejects_damaged(self):
        raw = bytearray(Pdu(FLAG_ACK, 1, 2, seq=1, data=b'abc').to_bytes())
        raw[-1] ^= 0x01
        with self.assertRaises(CatTpError):
            Pdu.from_bytes(bytes(raw))
        with self.assertRaises(CatTpError):
            Pdu.from_bytes(bytes(raw[:10]))
        raw = bytearray(Pdu(FLAG_ACK, 1, 2, seq=1, data=b'abc').to_bytes())
        raw[9] += 1                                       # data length lies
        with self.assertRaises(CatTpError):
            Pdu.from_bytes(bytes(raw))


    def test_rejects_malformed_variable_header(self):
        def with_var(flags, var):
            # hand built, the encoder refuses to produce these
            fields = dict(first=dict({n: bool(flags & b) for n, b in FLAG_BITS.items()}, version=0),
                          src_port=1, dst_port=2, seq=1, ack=0, window=1, var=var, data=b'')
            raw = PduStruct.build(dict(fields, checksum=0))
            return PduStruct.build(dict(fields, checksum=checksum(raw)))
        Pdu.from_bytes(with_var(FLAG_SYN, h2b('0400' '0400' '02' 'aabb')))
        for flags, var in ((FLAG_SYN, h2b('0400' '0400')),                 # no identification length
                           (FLAG_SYN, h2b('0400' '0400' '02' 'aa')),       # identification cut short
                           (FLAG_SYN, h2b('0400' '0400' '00' 'aa')),       # trailing octet
                           (FLAG_ACK | FLAG_EACK, h2b('000a' '0b')),       # half a sequence number
                           (FLAG_RST, b''),                                # no reason code
                           (FLAG_RST, h2b('0000')),
                           (FLAG_ACK, h2b('00'))):                         # nothing expected here
            with self.subTest(flags=flags, var=var.hex()):
                with self.assertRaises(CatTpError):
                    Pdu.from_bytes(with_var(flags, var))

    def test_rejects_illegal_combinations(self):
        # TS 102 127 5.6.1, 5.10.0
        for flags, data in ((FLAG_SYN, b'x'), (FLAG_RST, b'x'), (FLAG_NUL | FLAG_ACK, b'x'),
                            (FLAG_ACK | FLAG_SEG, b''), (FLAG_SYN | FLAG_RST, b''),
                            (FLAG_RST | FLAG_ACK | FLAG_EACK, b''), (FLAG_NUL, b'')):
            with self.subTest(flags=flags, data=data):
                with self.assertRaises(CatTpError):
                    Pdu(flags, 1, 2, data=data)
        pdu = Pdu(FLAG_ACK, 1, 2)
        pdu.flags |= FLAG_SEG                               # changed after construction
        with self.assertRaises(CatTpError):
            pdu.to_bytes()
        with self.assertRaises(CatTpError):
            Pdu(FLAG_ACK, 1, 0x10000).to_bytes()            # port does not fit


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class _Pair:
    """client and server connection joined back to back, PDUs move via pump()"""

    def __init__(self, test, client_kwargs=None, server_kwargs=None, isn=(100, 200)):
        self.test = test
        self.clock = _Clock()
        self.log = []               # (direction, Pdu)
        self.client_sdus = []
        self.server_sdus = []
        self.states = []
        self.client = CatTpConnection(1024, clock=self.clock, on_sdu=lambda c, s: self.client_sdus.append(s),
                                      on_state=lambda c, s: self.states.append(('client', s)),
                                      **(client_kwargs or {}))
        self.server = CatTpConnection(6001, clock=self.clock, on_sdu=lambda c, s: self.server_sdus.append(s),
                                      on_state=lambda c, s: self.states.append(('server', s)),
                                      **(server_kwargs or {}))
        self.isn = list(isn)
        self.drop = []

    def _isn(self, *_):
        return self.isn.pop(0)

    def open(self, identification=b''):
        with mock.patch('pySim.cattp.random.randrange', side_effect=self._isn):
            self.server.listen()
            self.client.connect(6001, identification)
            self.pump()

    def pump(self):
        """move PDUs both ways until nothing is left"""
        moved = True
        while moved:
            moved = False
            for src, dst, direction in ((self.client, self.server, '>'), (self.server, self.client, '<')):
                for raw in src.pop_tx():
                    moved = True
                    pdu = Pdu.from_bytes(raw)
                    if any(d(direction, pdu) for d in self.drop):
                        self.log.append((direction + 'x', pdu))
                        continue
                    self.log.append((direction, pdu))
                    dst.on_pdu(raw)

    def trace(self):
        return [(d, p.flags, p.seq, p.ack, len(p.data)) for d, p in self.log]

    def advance(self, seconds):
        self.clock.t += seconds
        self.client.on_timer()
        self.server.on_timer()
        self.pump()


class ConnectionTest(unittest.TestCase):

    def test_handshake_annex_a1(self):
        p = _Pair(self)
        p.open(identification=h2b('8949'))
        self.assertEqual(p.trace(), [
            ('>', FLAG_SYN, 100, 0, 0),                        # 2. <SEQ=100><SYN>
            ('<', FLAG_SYN | FLAG_ACK, 200, 100, 0),           # 3. <SEQ=200><ACK=100><SYN,ACK>
            ('>', FLAG_ACK, 101, 200, 0),                      # 4. <SEQ=101><ACK=200>
        ])
        self.assertEqual((p.client.state, p.server.state), ('OPEN', 'OPEN'))
        self.assertEqual(p.server.peer_identification, h2b('8949'))
        self.assertEqual(p.client.peer_identification, b'')     # TS 102 226 9.2.2
        self.assertEqual((p.client.snd_nxt, p.client.rcv_cur), (101, 200))
        self.assertEqual((p.server.snd_nxt, p.server.rcv_cur), (201, 100))
        self.assertEqual(p.server._rtx, [])                     # SYN/ACK acknowledged
        # 5./6. data goes out with the next sequence number and gets an ACK without data
        p.client.send_sdu(b'hello')
        p.pump()
        self.assertEqual(p.trace()[3:], [('>', FLAG_ACK, 101, 200, 5), ('<', FLAG_ACK, 201, 101, 0)])
        self.assertEqual(p.server_sdus, [b'hello'])
        self.assertEqual(p.client._rtx, [])

    def test_request_response_piggyback(self):
        p = _Pair(self)
        p.open()
        # the server answers from within on_sdu, so the ACK rides on the response data
        p.server.on_sdu = lambda c, s: c.send_sdu(b'resp:' + s)
        p.client.send_sdu(b'cmd')
        p.pump()
        self.assertEqual(p.trace()[3:], [('>', FLAG_ACK, 101, 200, 3),
                                          ('<', FLAG_ACK, 201, 101, 8),
                                          ('>', FLAG_ACK, 102, 201, 0)])
        self.assertEqual(p.client_sdus, [b'resp:cmd'])

    def test_lost_pdu_annex_a2(self):
        p = _Pair(self, client_kwargs={'rto': 1.0})
        p.open()
        p.drop.append(lambda d, pdu: d == '>' and pdu.seq == 102 and len(pdu.data))
        for sdu in (b'a', b'b', b'c', b'd'):
            p.client.send_sdu(sdu)
        p.pump()
        del p.drop[:]
        # 102 was lost: 101 acked, 103 and 104 acknowledged out of sequence with EACK
        self.assertEqual([t for t in p.trace()[3:] if t[0] == '<'], [
            ('<', FLAG_ACK, 201, 101, 0),
            ('<', FLAG_ACK | FLAG_EACK, 201, 101, 0),
            ('<', FLAG_ACK | FLAG_EACK, 201, 101, 0)])
        self.assertEqual(p.log[-1][1].eack, (103, 104))
        self.assertEqual(p.server_sdus, [b'a'])
        self.assertEqual([e[0].seq for e in p.client._rtx], [102])
        # retransmission timer fires, only 102 goes again and the cumulative ACK jumps to 104
        p.advance(1.5)
        self.assertEqual(p.trace()[-2:], [('>', FLAG_ACK, 102, 200, 1), ('<', FLAG_ACK, 201, 104, 0)])
        self.assertEqual(p.server_sdus, [b'a', b'b', b'c', b'd'])
        self.assertEqual(p.client._rtx, [])

    def test_segmentation(self):
        p = _Pair(self, server_kwargs={'max_pdu': 18 + 8})     # SYN is 18 + 5 already
        p.open()
        p.client.send_sdu(b'0123456789abcdefgh')
        p.pump()
        self.assertEqual([t for t in p.trace()[3:] if t[0] == '>'], [
            ('>', FLAG_ACK | FLAG_SEG, 101, 200, 8),
            ('>', FLAG_ACK | FLAG_SEG, 102, 200, 8),
            ('>', FLAG_ACK, 103, 200, 2)])
        self.assertEqual(p.server_sdus, [b'0123456789abcdefgh'])
        with self.assertRaises(CatTpError):
            p.client.send_sdu(bytes(65536))

    def test_window_limits_outstanding_pdus(self):
        p = _Pair(self, server_kwargs={'window': 1})
        p.open()
        p.drop.append(lambda d, pdu: d == '<')            # server goes quiet
        p.client.send_sdu(b'a')
        p.client.send_sdu(b'b')
        p.pump()
        self.assertEqual([t for t in p.trace() if t[0] == '>' and t[4]], [('>', FLAG_ACK, 101, 200, 1)])
        del p.drop[:]
        p.client.send_nul()                               # nothing more until the window opens
        p.advance(3.5)                                    # 101 retransmitted, acked, then 102 flows
        self.assertEqual(p.server_sdus, [b'a', b'b'])

    def test_retransmit_gives_up_with_rst(self):
        p = _Pair(self, server_kwargs={'rto': 1.0, 'max_retries': 2, 'close_wait': 5.0})
        p.open()
        p.drop.append(lambda d, pdu: d == '>')            # client vanished
        p.server.send_sdu(b'x')
        p.pump()
        p.advance(1.0)
        p.advance(1.0)
        self.assertEqual(p.server.state, 'OPEN')
        p.advance(1.0)
        self.assertEqual(p.server.state, 'CLOSE-WAIT')
        self.assertEqual(p.server.close_reason, RST_MAX_RETRIES)
        rst = p.log[-1][1]
        self.assertTrue(rst.rst and rst.has_ack)
        self.assertEqual(rst.rst_reason, RST_MAX_RETRIES)
        self.assertEqual([t for t in p.trace() if t[4] == 1],
                         [('<', FLAG_ACK, 201, 100, 1)] * 3)   # original + 2 retries
        p.advance(4.0)
        self.assertEqual(p.server.state, 'CLOSE-WAIT')
        p.advance(1.5)
        self.assertEqual(p.server.state, 'CLOSED')

    def test_close_with_rst(self):
        p = _Pair(self, server_kwargs={'close_wait': 1.0})
        p.open()
        p.client.close()
        p.pump()
        self.assertEqual(p.trace()[-1], ('>', FLAG_RST | FLAG_ACK, 101, 200, 0))
        self.assertEqual((p.client.state, p.server.state), ('CLOSE-WAIT', 'CLOSE-WAIT'))
        self.assertEqual(p.server.close_reason, RST_NORMAL)
        with self.assertRaises(CatTpError):
            p.server.send_sdu(b'late')
        p.advance(1.5)
        self.assertEqual(p.server.state, 'CLOSED')

    def test_close_from_on_sdu_sends_only_the_rst(self):
        p = _Pair(self)
        p.open()
        p.server.on_sdu = lambda c, s: c.close()
        p.client.send_sdu(b'last')
        p.pump()
        self.assertEqual([t for t in p.trace()[3:] if t[0] == '<'],
                         [('<', FLAG_RST | FLAG_ACK, 201, 101, 0)])     # no ACK after the RST
        self.assertEqual(p.server.state, 'CLOSE-WAIT')

    def test_duplicate_data_is_acked_not_delivered(self):
        p = _Pair(self)
        p.open()
        p.client.send_sdu(b'once')
        p.pump()
        dup = Pdu(FLAG_ACK, 1024, 6001, seq=101, ack=200, window=4, data=b'once').to_bytes()
        p.server.on_pdu(dup)
        self.assertEqual(len(p.server.pop_tx()), 1)
        self.assertEqual(p.server_sdus, [b'once'])

    def test_nul_keepalive(self):
        p = _Pair(self)
        p.open()
        p.server.send_nul()
        p.pump()
        self.assertEqual(p.trace()[3:], [('<', FLAG_NUL | FLAG_ACK, 201, 100, 0),
                                          ('>', FLAG_ACK, 101, 201, 0)])
        self.assertEqual(p.server.snd_nxt, 202)

    def test_syn_ack_with_other_version_is_refused(self):
        p = _Pair(self)
        with mock.patch('pySim.cattp.random.randrange', return_value=100):
            p.client.connect(6001)
        p.client.pop_tx()
        p.client.on_pdu(Pdu(FLAG_SYN | FLAG_ACK, 6001, 1024, seq=200, ack=100, window=4, max_pdu=1024,
                            max_sdu=1024, version=1).to_bytes())
        rst = Pdu.from_bytes(p.client.pop_tx()[0])
        self.assertTrue(rst.rst)
        self.assertEqual(rst.rst_reason, RST_VERSION)
        self.assertEqual(p.client.state, 'CLOSE-WAIT')

    def test_syn_in_open_is_unexpected(self):
        p = _Pair(self)
        p.open()
        p.server.on_pdu(Pdu(FLAG_SYN, 1024, 6001, seq=300, max_pdu=1024, max_sdu=1024).to_bytes())
        rst = Pdu.from_bytes(p.server.pop_tx()[0])
        self.assertEqual((rst.rst, rst.rst_reason, rst.ack), (True, RST_UNEXPECTED_PDU, 300))

    def test_lost_syn_ack_is_retransmitted(self):
        p = _Pair(self, server_kwargs={'rto': 1.0})
        p.drop.append(lambda d, pdu: d == '<')
        p.open()
        del p.drop[:]
        self.assertEqual((p.client.state, p.server.state), ('SYN-SENT', 'SYN-RCVD'))
        p.advance(1.0)
        self.assertEqual((p.client.state, p.server.state), ('OPEN', 'OPEN'))


class UdpServerTest(unittest.TestCase):
    """CatTpServer on a real loopback socket, driven by a hand pumped client connection"""

    def setUp(self):
        self.got = []
        self.opened = threading.Event()
        self.server = CatTpServer('127.0.0.1', 0, on_sdu=self._on_sdu, on_state=self._on_state, rto=0.5)
        self.server.bind()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2.0)
        self.sock.connect(('127.0.0.1', self.server.port))
        self.addCleanup(self.sock.close)
        self.client = CatTpConnection(2048)

    def _on_state(self, conn, state):
        if state == 'OPEN':
            conn.send_sdu(b'GET STATUS')            # the admin server talks first
            self.opened.set()

    def _on_sdu(self, conn, sdu):
        self.got.append(sdu)
        if sdu == b'bye':
            conn.close()
        else:
            conn.send_sdu(b'next after ' + sdu)

    def _exchange(self, deadline=3.0):
        """push out what the client has, feed back what the socket returns"""
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            for raw in self.client.pop_tx():
                self.sock.send(raw)
            try:
                raw = self.sock.recv(65535)
            except socket.timeout:
                return
            self.client.on_pdu(raw)
            if not self.client._tx and not self.client._rtx:
                return

    def test_session(self):
        rx = []
        self.client.on_sdu = lambda c, s: rx.append(s)
        self.client.connect(self.server.port, identification=h2b('8949020000000001'))
        self._exchange()
        self.assertTrue(self.opened.wait(2.0))
        self.assertEqual(self.client.state, 'OPEN')
        self.assertEqual(rx, [b'GET STATUS'])
        conn = next(iter(self.server.conns.values()))
        self.assertEqual(conn.peer_identification, h2b('8949020000000001'))
        self.client.send_sdu(b'9000')
        self._exchange()
        self.assertEqual(rx, [b'GET STATUS', b'next after 9000'])
        self.client.send_sdu(b'bye')
        self._exchange()
        self.assertEqual(self.got, [b'9000', b'bye'])
        self.assertEqual(self.client.state, 'CLOSE-WAIT')
        self.assertEqual(self.client.close_reason, RST_NORMAL)


if __name__ == "__main__":
    unittest.main()
