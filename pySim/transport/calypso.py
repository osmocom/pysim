# -*- coding: utf-8 -*-

# Copyright (C) 2018 Vadim Yanitskiy <axilirator@gmail.com>
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

import select
import struct
import socket
import os
import argparse
from typing import Optional
from osmocom.utils import h2b, b2h, Hexstr

from pySim.transport import LinkBase
from pySim.exceptions import ReaderError, ProtocolError
from pySim.utils import ResTuple


class L1CTLMessage:

    # Every (encoded) L1CTL message has the following structure:
    #  - msg_length (2 bytes, net order)
    #  - l1ctl_hdr (packed structure)
    #    - msg_type
    #    - flags
    #    - padding (2 spare bytes)
    #  - ... payload ...

    def __init__(self, msg_type, flags=0x00):
        # Init L1CTL message header
        self.data = struct.pack("BBxx", msg_type, flags)

    def gen_msg(self):
        return struct.pack("!H", len(self.data)) + self.data


class L1CTLMessageReset(L1CTLMessage):

    # L1CTL message types
    L1CTL_RESET_REQ = 0x0d
    L1CTL_RESET_IND = 0x07
    L1CTL_RESET_CONF = 0x0e

    # Reset types
    L1CTL_RES_T_BOOT = 0x00
    L1CTL_RES_T_FULL = 0x01
    L1CTL_RES_T_SCHED = 0x02

    def __init__(self, ttype=L1CTL_RES_T_FULL):
        super().__init__(self.L1CTL_RESET_REQ)
        self.data += struct.pack("Bxxx", ttype)


class L1CTLMessageSIM(L1CTLMessage):

    # SIM related message types
    L1CTL_SIM_REQ = 0x16
    L1CTL_SIM_CONF = 0x17

    def __init__(self, pdu):
        super().__init__(self.L1CTL_SIM_REQ)
        self.data += pdu


class CalypsoSimLink(LinkBase):
    """Transport Link for Calypso based phones."""
    name = 'Calypso-based (OsmocomBB) reader'

    def __init__(self, opts: argparse.Namespace = argparse.Namespace(osmocon_sock="/tmp/osmocom_l2"), **kwargs):
        sock_path = opts.osmocon_sock
        super().__init__(**kwargs)
        # Make sure that a given socket path exists
        if not os.path.exists(sock_path):
            raise ReaderError(
                "There is no such ('%s') UNIX socket" % sock_path)

        print("Connecting to osmocon at '%s'..." % sock_path)

        # Establish a client connection
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(sock_path)

        # Remember socket path
        self._sock_path = sock_path

    def __del__(self):
        self.sock.close()

    def wait_for_rsp(self, exp_len: int = 128):
        # Wait for incoming data (timeout is 3 seconds)
        s, _, _ = select.select([self.sock], [], [], 3.0)
        if not s:
            raise ReaderError("Timeout waiting for card response")

        # Receive expected amount of bytes from osmocon
        rsp = self.sock.recv(exp_len)
        return rsp

    def _reset_card(self):
        # Request FULL reset
        req_msg = L1CTLMessageReset()
        self.sock.send(req_msg.gen_msg())

        # Wait for confirmation
        rsp = self.wait_for_rsp()
        rsp_msg = struct.unpack_from("!HB", rsp)
        if rsp_msg[1] != L1CTLMessageReset.L1CTL_RESET_CONF:
            raise ReaderError("Failed to reset Calypso PHY")

    def connect(self):
        self.reset_card()

    def disconnect(self):
        pass  # Nothing to do really ...

    def wait_for_card(self, timeout: Optional[int] = None, newcardonly: bool = False):
        pass  # Nothing to do really ...

    def _send_apdu_raw(self, pdu: Hexstr) -> ResTuple:

        # Request FULL reset
        req_msg = L1CTLMessageSIM(h2b(pdu))
        self.sock.send(req_msg.gen_msg())

        # Read message length first
        rsp = self.wait_for_rsp(struct.calcsize("!H"))
        msg_len = struct.unpack_from("!H", rsp)[0]
        if msg_len < struct.calcsize("BBxx"):
            raise ReaderError("Missing L1CTL header for L1CTL_SIM_CONF")

        # Read the whole message then
        rsp = self.sock.recv(msg_len)

        # Verify L1CTL header
        hdr = struct.unpack_from("BBxx", rsp)
        if hdr[0] != L1CTLMessageSIM.L1CTL_SIM_CONF:
            raise ReaderError("Unexpected L1CTL message received")

        # Verify the payload length
        offset = struct.calcsize("BBxx")
        if len(rsp) <= offset:
            raise ProtocolError("Empty response from SIM?!?")

        # Omit L1CTL header
        rsp = rsp[offset:]

        # Unpack data and SW
        data = rsp[:-2]
        sw = rsp[-2:]

        return b2h(data), b2h(sw)

    def __str__(self) -> str:
        return "osmocon:%s" % (self._sock_path)

    @staticmethod
    def argparse_add_reader_args(arg_parser: argparse.ArgumentParser):
        osmobb_group = arg_parser.add_argument_group('OsmocomBB Reader', """Use an OsmocomBB compatible phone
to access the SIM inserted to the phone SIM slot.  This will require you to run the OsmocomBB firmware inside
the phone (can be ram-loaded).  It also requires that you run the ``osmocon`` program, which provides a unix
domain socket to which this reader driver can attach.""")
        osmobb_group.add_argument('--osmocon', dest='osmocon_sock', metavar='PATH', default=None,
                                  help='Socket path for Calypso (e.g. Motorola C1XX) based reader (via OsmocomBB)')
