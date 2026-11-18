# -*- coding: utf-8 -*-
"""CAT_TP, the Card Application Toolkit Transport Protocol of ETSI TS 102 127"""

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

# A reliable, sequenced datagram transport that a card runs over a BIP UDP channel to carry
# TS 102 225 secured packets, one per SDU. It is the Reliable Data Protocol of RFC 908/1151
# (handshake, sequence numbers, cumulative and extended ACKs, retransmission, per datagram
# rather than per byte stream) plus a SEG bit to spread one SDU over several PDUs.
# Server side, the card connects here after a TS 102 226 PUSH. The client side exists for
# the tests.
#
# CatTpConnection is the protocol state machine without a socket, driven by tests or by the
# UDP socket of CatTpServer: received PDUs go to on_pdu(), the clock to on_timer(), pop_tx()
# returns the PDUs to send.

import collections
import logging
import random
import socket
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from construct import Struct, BitStruct, BitsInteger, Flag, Int8ub, Int16ub, Padding, Bytes, GreedyBytes
from construct import GreedyRange, Prefixed, Rebuild, Terminated, ConstructError, this, len_
from osmocom.utils import b2h

logger = logging.getLogger(__name__)

# TS 102 127 5.6.1 figure 39, flags in the first octet
FLAG_SYN = 0x80         # establish the connection, synchronise sequence numbers
FLAG_ACK = 0x40         # acknowledgement number and window are significant
FLAG_EACK = 0x20        # extended acknowledgement of PDUs received out of sequence
FLAG_RST = 0x10         # reset (close) the connection, as in TCP
FLAG_NUL = 0x08         # keep alive, carries no data
FLAG_SEG = 0x04         # more segments of this SDU follow
VERSION = 0

# TS 102 127 5.6.2: header length without a variable header area
HDR_LEN = 0x12

# TS 102 127 5.6.5: sequence numbers are 16 bit and wrap around
SEQ_MOD = 0x10000

# TS 102 127 5.10.1.4, reason codes of the RST PDU
RST_NORMAL = 0x00
RST_ILLEGAL_PARAMS = 0x01
RST_TEMP_UNABLE = 0x02
RST_PORT_NOT_AVAILABLE = 0x03
RST_UNEXPECTED_PDU = 0x04
RST_MAX_RETRIES = 0x05
RST_VERSION = 0x06
RST_REASONS = {RST_NORMAL: 'normal ending', RST_ILLEGAL_PARAMS: 'illegal parameters',
               RST_TEMP_UNABLE: 'temporarily unable', RST_PORT_NOT_AVAILABLE: 'port not available',
               RST_UNEXPECTED_PDU: 'unexpected PDU', RST_MAX_RETRIES: 'maximum retries exceeded',
               RST_VERSION: 'version not supported'}

# TS 102 127 5.6 figure 38. The variable header area depends on the PDU type and has its own
# constructs below.
PduStruct = Struct('first'/BitStruct('syn'/Flag, 'ack'/Flag, 'eack'/Flag, 'rst'/Flag, 'nul'/Flag,
                                     'seg'/Flag, 'version'/BitsInteger(2)),
                   Padding(2),                                         # RFU
                   'hdr_len'/Rebuild(Int8ub, len_(this.var) + HDR_LEN),
                   'src_port'/Int16ub,
                   'dst_port'/Int16ub,
                   'data_len'/Rebuild(Int16ub, len_(this.data)),
                   'seq'/Int16ub,
                   'ack'/Int16ub,
                   'window'/Int16ub,
                   'checksum'/Int16ub,
                   'var'/Bytes(this.hdr_len - HDR_LEN),
                   'data'/Bytes(this.data_len),
                   Terminated)

# TS 102 127 5.7 SYN PDU. The identification is a LV (5.5), figure 40 draws it like a fixed field.
SynVar = Struct('max_pdu'/Int16ub, 'max_sdu'/Int16ub,
                'identification'/Prefixed(Int8ub, GreedyBytes), Terminated)
# TS 102 127 5.9.1.4 EACK PDU: sequence numbers of the PDUs received out of sequence
EackVar = Struct('eack'/GreedyRange(Int16ub), Terminated)
# TS 102 127 5.10.1.4 RST PDU
RstVar = Struct('rst_reason'/Int8ub, Terminated)
NoVar = Struct(Terminated)

FLAG_BITS = {'syn': FLAG_SYN, 'ack': FLAG_ACK, 'eack': FLAG_EACK, 'rst': FLAG_RST,
             'nul': FLAG_NUL, 'seg': FLAG_SEG}


def var_struct(flags: int) -> Struct:
    """construct of the variable header area of a PDU with these flags, TS 102 127 5.6.9"""
    if flags & FLAG_SYN:
        return SynVar
    if flags & FLAG_RST:
        return RstVar
    if flags & FLAG_EACK:
        return EackVar
    return NoVar


def checksum(data: bytes) -> int:
    """TS 102 127 5.3.2.2: the RFC 793 checksum without the pseudo header"""
    if len(data) & 1:
        data += b'\x00'
    total = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _seq_add(seq: int, n: int = 1) -> int:
    return (seq + n) % SEQ_MOD


def _seq_diff(a: int, b: int) -> int:
    """a - b on the sequence number circle"""
    return (a - b) % SEQ_MOD


def _seq_ge(a: int, b: int) -> bool:
    """a is at or after b, less than half the circle ahead"""
    return _seq_diff(a, b) < SEQ_MOD // 2


class CatTpError(Exception):
    pass


class Pdu:
    """One CAT_TP PDU, TS 102 127 5.6 to 5.11"""
    __slots__ = ('flags', 'version', 'src_port', 'dst_port', 'seq', 'ack', 'window', 'data',
                 'eack', 'max_pdu', 'max_sdu', 'identification', 'rst_reason')

    def __init__(self, flags: int, src_port: int, dst_port: int, seq: int = 0, ack: int = 0,
                 window: int = 0, data: bytes = b'', eack: Tuple[int, ...] = (),
                 max_pdu: int = 0, max_sdu: int = 0, identification: bytes = b'',
                 rst_reason: int = RST_NORMAL, version: int = VERSION):
        self.flags = flags
        self.version = version
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.window = window
        self.data = bytes(data)
        self.eack = tuple(eack)
        self.max_pdu = max_pdu
        self.max_sdu = max_sdu
        self.identification = bytes(identification)
        self.rst_reason = rst_reason
        self.check()

    syn = property(lambda self: bool(self.flags & FLAG_SYN))
    has_ack = property(lambda self: bool(self.flags & FLAG_ACK))
    has_eack = property(lambda self: bool(self.flags & FLAG_EACK))
    rst = property(lambda self: bool(self.flags & FLAG_RST))
    nul = property(lambda self: bool(self.flags & FLAG_NUL))
    seg = property(lambda self: bool(self.flags & FLAG_SEG))

    @property
    def needs_ack(self) -> bool:
        """TS 102 127 5.3.2.1: SYN, NUL and data PDUs consume a sequence number and get acknowledged"""
        return self.syn or self.nul or len(self.data) > 0

    def check(self):
        """Raise CatTpError for what TS 102 127 5.6.1 and 5.10.0 rule out."""
        if self.data and (self.syn or self.rst or self.nul):
            raise CatTpError('SYN, RST and NUL PDUs carry no data')
        if self.seg and not self.data:
            raise CatTpError('SEG is only allowed with data')
        if self.syn and self.rst:
            raise CatTpError('SYN and RST are separate PDUs')
        if self.rst and self.has_eack:
            raise CatTpError('RST cannot be combined with EACK')
        if self.nul and not self.has_ack:
            raise CatTpError('NUL comes with ACK')

    def to_bytes(self) -> bytes:
        self.check()
        fields = {name: getattr(self, name) for name in self.__slots__}
        fields['first'] = dict({name: bool(self.flags & bit) for name, bit in FLAG_BITS.items()},
                               version=self.version)
        try:
            fields['var'] = var_struct(self.flags).build(fields)
            # TS 102 127 5.3.2.2: computed while the checksum field itself is zero
            raw = PduStruct.build(dict(fields, checksum=0))
            return PduStruct.build(dict(fields, checksum=checksum(raw)))
        except ConstructError as e:
            raise CatTpError('cannot encode %r: %s' % (self, e)) from e

    @classmethod
    def from_bytes(cls, raw: bytes) -> 'Pdu':
        try:
            hdr = PduStruct.parse(raw)
            flags = sum(bit for name, bit in FLAG_BITS.items() if hdr.first[name])
            var = var_struct(flags).parse(hdr.var)
        except ConstructError as e:
            raise CatTpError('malformed PDU: %s' % e) from e
        # RFC 1071: summed up including a correct checksum field the result is zero
        if checksum(raw) != 0:
            raise CatTpError('checksum mismatch')
        return cls(flags, hdr.src_port, hdr.dst_port, seq=hdr.seq, ack=hdr.ack, window=hdr.window,
                   data=hdr.data, version=hdr.first.version,
                   **{name: value for name, value in var.items() if not name.startswith('_')})

    def __repr__(self):
        names = [name.upper() for name, bit in FLAG_BITS.items() if self.flags & bit]
        s = '<%s %u->%u seq=%u ack=%u win=%u len=%u' % ('/'.join(names) or 'DATA', self.src_port,
                                                       self.dst_port, self.seq, self.ack, self.window,
                                                       len(self.data))
        if self.syn:
            s += ' max_pdu=%u max_sdu=%u id=%s' % (self.max_pdu, self.max_sdu, b2h(self.identification))
        if self.eack:
            s += ' eack=%s' % (self.eack,)
        if self.rst:
            s += ' reason=%s' % RST_REASONS.get(self.rst_reason, self.rst_reason)
        return s + '>'


class CatTpConnection:
    """One connection, TS 102 127 5.3.1.4 connection record and 5.4 event processing.

    Upper layer hooks:
    - on_sdu(conn, sdu) for every reassembled SDU
    - on_state(conn, state) on every state change, 'OPEN' is when to start sending
    Calling send_sdu() from inside on_sdu() puts the ACK into the data PDU instead of a separate one.
    clock is only there for tests to fake time.
    """
    CLOSED, LISTEN, SYN_SENT, SYN_RCVD, OPEN, CLOSE_WAIT = ('CLOSED', 'LISTEN', 'SYN-SENT',
                                                            'SYN-RCVD', 'OPEN', 'CLOSE-WAIT')

    def __init__(self, local_port: int, *, max_pdu: int = 1024, max_sdu: int = 65535,
                 window: int = 4, rto: float = 3.0, max_retries: int = 3, close_wait: float = 2.0,
                 on_sdu: Optional[Callable[['CatTpConnection', bytes], None]] = None,
                 on_state: Optional[Callable[['CatTpConnection', str], None]] = None,
                 clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.local_port = local_port
        self.remote_port = 0
        self.state = self.CLOSED
        self.rto = rto
        self.max_retries = max_retries
        self.close_wait = close_wait
        self.on_sdu = on_sdu
        self.on_state = on_state
        self.peer_identification = b''
        self.close_reason: Optional[int] = None
        # sending activity, 5.3.1.4.2
        self.snd_ini = 0
        self.snd_nxt = 0
        self.snd_una = 0
        self.snd_pdu_max = 0
        self.snd_sdu_max = 0
        self.snd_right = 0          # last sequence number the peer window allows
        # receiving activity, 5.3.1.4.3
        self.rcv_ini = 0
        self.rcv_cur = 0
        self.rcv_out_of_seq: Dict[int, Pdu] = {}
        self.rcv_pdu_max = max_pdu
        self.rcv_sdu_max = max_sdu
        self.rcv_win = window
        self._rx_sdu = bytearray()
        # [pdu, sent_at, retries] awaiting acknowledgement, in sequence order
        self._rtx: List[list] = []
        self._tx_wait: collections.deque = collections.deque()  # data PDUs beyond the window
        self._tx: List[bytes] = []
        self._close_deadline: Optional[float] = None
        self._ack_pending = False
        self._data_sent = False

    def __repr__(self):
        return '<CatTpConnection %s %u<->%u snd_nxt=%u snd_una=%u rcv_cur=%u>' % (
            self.state, self.local_port, self.remote_port, self.snd_nxt, self.snd_una, self.rcv_cur)

    def listen(self):
        """TS 102 127 5.4.1.1 passive open"""
        self._set_state(self.LISTEN)

    def connect(self, remote_port: int, identification: bytes = b''):
        """TS 102 127 5.4.1.1 active open, what the card does after the PUSH"""
        self.remote_port = remote_port
        self._init_send()
        self._queue(Pdu(FLAG_SYN, self.local_port, remote_port, seq=self.snd_ini, window=self.rcv_win,
                        max_pdu=self.rcv_pdu_max, max_sdu=self.rcv_sdu_max,
                        identification=identification))
        self._set_state(self.SYN_SENT)

    def send_sdu(self, sdu: bytes):
        """TS 102 127 5.4.1.4: segment into data PDUs (5.2.3), send what the window allows"""
        if self.state != self.OPEN:
            raise CatTpError('cannot send in state %s' % self.state)
        if len(sdu) > self.snd_sdu_max:
            raise CatTpError('SDU of %u octets exceeds peer max SDU size %u' % (len(sdu), self.snd_sdu_max))
        chunk = self.snd_pdu_max - HDR_LEN
        if chunk < 1:
            raise CatTpError('peer max PDU size %u leaves no room for data' % self.snd_pdu_max)
        segments = [sdu[i:i + chunk] for i in range(0, len(sdu), chunk)] or [b'']
        for i, seg in enumerate(segments):
            flags = FLAG_ACK | (FLAG_SEG if i < len(segments) - 1 else 0)
            self._tx_wait.append(Pdu(flags, self.local_port, self.remote_port, seq=self.snd_nxt, data=seg))
            self.snd_nxt = _seq_add(self.snd_nxt)
        self._flush_window()

    def send_nul(self):
        """TS 102 127 5.3.1.6 probe for a half open connection"""
        if self.state != self.OPEN:
            raise CatTpError('cannot send in state %s' % self.state)
        self._tx_wait.append(Pdu(FLAG_NUL | FLAG_ACK, self.local_port, self.remote_port, seq=self.snd_nxt))
        self.snd_nxt = _seq_add(self.snd_nxt)
        self._flush_window()

    def close(self, reason: int = RST_NORMAL):
        """TS 102 127 5.4.1.2: RST, then CLOSE-WAIT until the timer expires"""
        if self.state in (self.CLOSED, self.CLOSE_WAIT):
            return
        if self.state == self.LISTEN:
            self._set_state(self.CLOSED)
            return
        flags = FLAG_RST | (FLAG_ACK if self.state in (self.OPEN, self.SYN_RCVD) else 0)
        self._queue(Pdu(flags, self.local_port, self.remote_port, seq=self.snd_nxt, ack=self.rcv_cur,
                        window=self.rcv_win, rst_reason=reason))
        self._enter_close_wait(reason)

    def pop_tx(self) -> List[bytes]:
        """serialised PDUs to hand to the socket, in order"""
        out, self._tx = self._tx, []
        return out

    def on_timer(self) -> Optional[float]:
        """TS 102 127 5.4.3: retransmit what is overdue, returns the next deadline or None"""
        now = self.clock()
        if self.state == self.CLOSE_WAIT:
            if now >= self._close_deadline:
                self._rtx.clear()
                self._set_state(self.CLOSED)
                return None
            return self._close_deadline
        for entry in self._rtx:
            pdu, sent_at, retries = entry
            if now - sent_at < self.rto:
                continue
            if retries >= self.max_retries:
                logger.warning('%r: %r not acknowledged after %u retries', self, pdu, retries)
                self.close(RST_MAX_RETRIES)
                return self._close_deadline
            logger.debug('%r: retransmit %r', self, pdu)
            entry[1], entry[2] = now, retries + 1
            self._emit(pdu)
        deadlines = [sent_at + self.rto for _, sent_at, _ in self._rtx]
        return min(deadlines) if deadlines else None

    def on_pdu(self, raw: bytes):
        """TS 102 127 5.4.2 PDU arrival"""
        try:
            pdu = Pdu.from_bytes(raw)
        except CatTpError as e:
            logger.warning('%r: discarding PDU: %s', self, e)
            return
        if len(raw) > self.rcv_pdu_max:
            logger.warning('%r: discarding %u octet PDU above max PDU size', self, len(raw))
            return
        logger.debug('%r: rx %r', self, pdu)
        self._ack_pending = False
        self._data_sent = False
        handler = {self.CLOSED: self._rx_closed, self.LISTEN: self._rx_listen,
                   self.SYN_SENT: self._rx_syn_sent, self.SYN_RCVD: self._rx_syn_rcvd,
                   self.OPEN: self._rx_open, self.CLOSE_WAIT: self._rx_close_wait}[self.state]
        handler(pdu)
        # the upper layer may have closed the connection from its callback, TS 102 127 5.3.1.5:
        # nothing is sent in CLOSE-WAIT
        if self._ack_pending and not self._data_sent and self.state == self.OPEN:
            self._queue(self._ack_pdu())

    def _rx_closed(self, pdu: Pdu):
        # TS 102 127 5.4.2.1: tell the peer nobody is home, RST is never answered
        if not pdu.rst:
            self._queue(Pdu(FLAG_RST | FLAG_ACK, self.local_port, pdu.src_port, ack=pdu.seq,
                            rst_reason=RST_PORT_NOT_AVAILABLE))

    def _rx_close_wait(self, pdu: Pdu):
        pass                                        # TS 102 127 5.3.1.5: discarded

    def _rx_listen(self, pdu: Pdu):
        # TS 102 127 5.4.2.3: only a SYN gets us anywhere
        if pdu.rst:
            return
        if not pdu.syn or pdu.has_ack:
            self._queue(Pdu(FLAG_RST | FLAG_ACK, self.local_port, pdu.src_port, ack=pdu.seq,
                            rst_reason=RST_UNEXPECTED_PDU))
            return
        if pdu.max_pdu < HDR_LEN + 1:
            self._queue(Pdu(FLAG_RST | FLAG_ACK, self.local_port, pdu.src_port, ack=pdu.seq,
                            rst_reason=RST_ILLEGAL_PARAMS))
            return
        self.remote_port = pdu.src_port
        self.rcv_ini = self.rcv_cur = pdu.seq
        self.peer_identification = pdu.identification
        self._init_send(pdu)
        # TS 102 127 5.3.1.7: answer with our version, TS 102 226 9.2.2: empty identification
        self._queue(Pdu(FLAG_SYN | FLAG_ACK, self.local_port, self.remote_port, seq=self.snd_ini,
                        ack=self.rcv_cur, window=self.rcv_win, max_pdu=self.rcv_pdu_max,
                        max_sdu=self.rcv_sdu_max))
        self._set_state(self.SYN_RCVD)

    def _rx_syn_sent(self, pdu: Pdu):
        # TS 102 127 5.4.2.4
        if pdu.rst:
            self._enter_close_wait(pdu.rst_reason)
            return
        if not (pdu.syn and pdu.has_ack) or pdu.ack != self.snd_ini:
            self._queue(Pdu(FLAG_RST, self.local_port, self.remote_port, seq=self.snd_nxt,
                            rst_reason=RST_UNEXPECTED_PDU))
            self._enter_close_wait(RST_UNEXPECTED_PDU)
            return
        if pdu.version != VERSION:
            self.close(RST_VERSION)
            return
        self.rcv_ini = self.rcv_cur = pdu.seq
        self.peer_identification = pdu.identification
        self.snd_pdu_max, self.snd_sdu_max = pdu.max_pdu, pdu.max_sdu
        self._process_ack(pdu)
        self._set_state(self.OPEN)
        self._ack_pending = True

    def _rx_syn_rcvd(self, pdu: Pdu):
        # TS 102 127 5.4.2.5
        if pdu.rst:
            self._rtx.clear()
            self._set_state(self.LISTEN)
            return
        if pdu.syn:
            if pdu.seq == self.rcv_ini and not pdu.has_ack:
                self._retransmit_syn_ack()          # our SYN/ACK got lost
                return
            self._queue(Pdu(FLAG_RST | FLAG_ACK, self.local_port, self.remote_port, ack=pdu.seq,
                            rst_reason=RST_UNEXPECTED_PDU))
            self._enter_close_wait(RST_UNEXPECTED_PDU)
            return
        if not pdu.has_ack or pdu.ack != self.snd_ini:
            return
        self._set_state(self.OPEN)
        self._rx_open(pdu)

    def _rx_open(self, pdu: Pdu):
        # TS 102 127 5.4.2.2, figures 25 to 28
        if pdu.rst:
            logger.info('%r: peer reset, %s', self, RST_REASONS.get(pdu.rst_reason, pdu.rst_reason))
            self._enter_close_wait(pdu.rst_reason)
            return
        if pdu.syn:
            self._queue(Pdu(FLAG_RST | FLAG_ACK, self.local_port, self.remote_port, ack=pdu.seq,
                            rst_reason=RST_UNEXPECTED_PDU))
            self._enter_close_wait(RST_UNEXPECTED_PDU)
            return
        if pdu.has_ack:
            self._process_ack(pdu)
        if not pdu.needs_ack:
            return
        self._ack_pending = True
        d = _seq_diff(pdu.seq, self.rcv_cur)
        if d == 0 or d > self.rcv_win:
            logger.debug('%r: seq %u outside window, duplicate ACK', self, pdu.seq)
            return
        if d != 1:
            self.rcv_out_of_seq[pdu.seq] = pdu       # TS 102 127 5.3.3: in the window but out of sequence
            return
        self._accept(pdu)
        while _seq_add(self.rcv_cur) in self.rcv_out_of_seq:
            self._accept(self.rcv_out_of_seq.pop(_seq_add(self.rcv_cur)))

    def _accept(self, pdu: Pdu):
        self.rcv_cur = pdu.seq
        if pdu.nul:
            return
        self._rx_sdu += pdu.data
        if len(self._rx_sdu) > self.rcv_sdu_max:
            logger.warning('%r: SDU exceeds %u octets', self, self.rcv_sdu_max)
            self.close(RST_ILLEGAL_PARAMS)
            return
        if pdu.seg:
            return
        sdu, self._rx_sdu = bytes(self._rx_sdu), bytearray()
        if self.on_sdu:
            self.on_sdu(self, sdu)

    def _set_state(self, state: str):
        logger.info('%r: %s -> %s', self, self.state, state)
        self.state = state
        if self.on_state:
            self.on_state(self, state)

    def _enter_close_wait(self, reason: int):
        self.close_reason = reason
        self._rtx.clear()
        self._tx_wait.clear()
        self._close_deadline = self.clock() + self.close_wait
        self._set_state(self.CLOSE_WAIT)

    def _init_send(self, syn: Optional[Pdu] = None):
        self.snd_ini = random.randrange(SEQ_MOD)
        self.snd_nxt = _seq_add(self.snd_ini)
        self.snd_una = self.snd_ini
        self.snd_right = self.snd_ini
        if syn is not None:
            self.snd_pdu_max, self.snd_sdu_max = syn.max_pdu, syn.max_sdu

    def _retransmit_syn_ack(self):
        for entry in self._rtx:
            if entry[0].syn:
                entry[1] = self.clock()
                self._emit(entry[0])

    def _ack_pdu(self) -> Pdu:
        """(E)ACK without data, seq is SND_NXT and is not consumed, TS 102 127 figure 45"""
        pdu = Pdu(FLAG_ACK, self.local_port, self.remote_port, seq=self.snd_nxt)
        if self.rcv_out_of_seq:
            pdu.flags |= FLAG_EACK
            pdu.eack = tuple(sorted(self.rcv_out_of_seq))
        return pdu

    def _process_ack(self, pdu: Pdu):
        # only acknowledgements within SND_UNA-1 .. SND_NXT-1 are meaningful
        base = _seq_add(self.snd_una, -1)
        if _seq_diff(pdu.ack, base) > _seq_diff(_seq_add(self.snd_nxt, -1), base):
            logger.debug('%r: ignoring ack %u outside %u..%u', self, pdu.ack, base, self.snd_nxt - 1)
            return
        acked = set(pdu.eack)
        self._rtx = [e for e in self._rtx
                     if not _seq_ge(pdu.ack, e[0].seq) and e[0].seq not in acked]
        if _seq_ge(pdu.ack, self.snd_una):
            self.snd_una = _seq_add(pdu.ack)
        # TS 102 127 5.3.3: the right window border never moves left
        right = _seq_add(pdu.ack, pdu.window)
        if _seq_ge(right, self.snd_right):
            self.snd_right = right
        self._flush_window()

    def _flush_window(self):
        while self._tx_wait and _seq_ge(self.snd_right, self._tx_wait[0].seq):
            pdu = self._tx_wait.popleft()
            self._queue(pdu)
            self._data_sent = True

    def _queue(self, pdu: Pdu):
        """TS 102 127 5.3.2.4 serialization/retransmission"""
        if pdu.needs_ack:
            self._rtx.append([pdu, self.clock(), 0])
        self._emit(pdu)

    def _emit(self, pdu: Pdu):
        if pdu.has_ack and not (pdu.syn or pdu.rst):
            pdu.ack, pdu.window = self.rcv_cur, self.rcv_win
        logger.debug('%r: tx %r', self, pdu)
        self._tx.append(pdu.to_bytes())


class CatTpServer:
    """One UDP socket, a listening CatTpConnection per peer address, single threaded.

    Args:
        host: local address to bind to
        port: local UDP port, also the CAT_TP port of the connections. 0 picks a free one,
            bind() returns it.
        on_sdu: callback(conn: CatTpConnection, sdu: bytes) for every SDU received
        on_state: callback(conn: CatTpConnection, state: str) on every state change of a
            connection, 'OPEN' is when to start sending with conn.send_sdu()
        conn_kwargs: passed on to every CatTpConnection (max_pdu, max_sdu, window, rto,
            max_retries, close_wait)

    The callbacks run on the server thread, sending from them puts the response and the ACK
    into the same PDU. Other threads use send_sdu() of the server.
    """
    POLL = 0.05                 # seconds between timer runs while no datagram arrives
    MAX_DATAGRAM = 65535        # largest UDP datagram

    def __init__(self, host: str, port: int, on_sdu=None, on_state=None, **conn_kwargs):
        self.host = host
        self.port = port
        self.on_sdu = on_sdu
        self.on_state = on_state
        self.conn_kwargs = conn_kwargs
        self.conns: Dict[tuple, CatTpConnection] = {}
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

    def bind(self) -> int:
        """Bind the socket, returns the port. Optional, serve_forever() does it if needed."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(self.POLL)
        self.port = self._sock.getsockname()[1]
        return self.port

    def serve_forever(self):
        """Receive datagrams and run the connection timers until shutdown() is called."""
        if self._sock is None:
            self.bind()
        logger.info('CAT_TP server listening on %s:%u/udp', self.host, self.port)
        while not self._stop.is_set():
            try:
                raw, addr = self._sock.recvfrom(self.MAX_DATAGRAM)
            except socket.timeout:
                raw, addr = None, None
            except OSError:
                break
            with self._lock:
                if raw is not None:
                    conn = self.conns.get(addr)
                    if conn is None:
                        conn = CatTpConnection(self.port, on_sdu=self.on_sdu, on_state=self.on_state,
                                               **self.conn_kwargs)
                        conn.listen()
                        self.conns[addr] = conn
                    conn.on_pdu(raw)
                    self._flush(conn, addr)
                self._tick()

    def _tick(self):
        for addr, conn in list(self.conns.items()):
            conn.on_timer()
            self._flush(conn, addr)
            if conn.state == CatTpConnection.CLOSED:
                del self.conns[addr]

    def _flush(self, conn: CatTpConnection, addr):
        for raw in conn.pop_tx():
            try:
                self._sock.sendto(raw, addr)
            except OSError as e:
                logger.warning('sendto %s failed: %s', addr, e)

    def send_sdu(self, conn: CatTpConnection, sdu: bytes):
        """thread safe entry for callers outside the server thread"""
        with self._lock:
            conn.send_sdu(sdu)
            addr = next(a for a, c in self.conns.items() if c is conn)
            self._flush(conn, addr)

    def shutdown(self):
        """Stop serve_forever() and close the socket."""
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
