# -*- coding: utf-8 -*-

# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
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
import os
import argparse
from typing import Optional
import serial
from osmocom.utils import h2b, b2h, Hexstr

from pySim.exceptions import NoCardError, ProtocolError
from pySim.transport import LinkBase
from pySim.utils import ResTuple


class SerialSimLink(LinkBase):
    """ pySim: Transport Link for serial (RS232) based readers included with simcard"""
    name = 'Serial'

    def __init__(self, opts = argparse.Namespace(device='/dev/ttyUSB0', baudrate=9600), rst: str = '-rts',
                 debug: bool = False, **kwargs):
        super().__init__(**kwargs)
        if not os.path.exists(opts.device):
            raise ValueError("device file %s does not exist -- abort" % opts.device)
        self._sl = serial.Serial(
            port=opts.device,
            parity=serial.PARITY_EVEN,
            bytesize=serial.EIGHTBITS,
            stopbits=serial.STOPBITS_TWO,
            timeout=1,
            xonxoff=0,
            rtscts=0,
            baudrate=opts.baudrate,
        )
        self._rst_pin = rst
        self._debug = debug
        self._atr = None

    def __del__(self):
        if hasattr(self, "_sl"):
            self._sl.close()

    def wait_for_card(self, timeout: Optional[int] = None, newcardonly: bool = False):
        # Direct try
        existing = False

        try:
            self.reset_card()
            if not newcardonly:
                return
            existing = True
        except NoCardError:
            pass

        # Poll ...
        mt = time.time() + timeout if timeout is not None else None
        pe = 0

        while (mt is None) or (time.time() < mt):
            try:
                time.sleep(0.5)
                self.reset_card()
                if not existing:
                    return
            except NoCardError:
                existing = False
            except ProtocolError:
                if existing:
                    existing = False
                else:
                    # Tolerate a couple of protocol error ... can happen if
                    # we try when the card is 'half' inserted
                    pe += 1
                    if pe > 2:
                        raise

        # Timed out ...
        raise NoCardError()

    def connect(self):
        self.reset_card()

    def get_atr(self) -> Hexstr:
        return self._atr

    def disconnect(self):
        pass  # Nothing to do really ...

    def _reset_card(self):
        rv = self.__reset_card()
        if rv == 0:
            raise NoCardError()
        if rv < 0:
            raise ProtocolError()
        return rv

    def __reset_card(self):
        self._atr = None
        rst_meth_map = {
            'rts': self._sl.setRTS,
            'dtr': self._sl.setDTR,
        }
        rst_val_map = {'+': 0, '-': 1}

        try:
            rst_meth = rst_meth_map[self._rst_pin[1:]]
            rst_val = rst_val_map[self._rst_pin[0]]
        except Exception as exc:
            raise ValueError('Invalid reset pin %s' % self._rst_pin) from exc

        rst_meth(rst_val)
        time.sleep(0.1)  # 100 ms
        self._sl.flushInput()
        rst_meth(rst_val ^ 1)

        b = self._rx_byte()
        if not b:
            return 0
        if ord(b) != 0x3b:
            return -1
        self._dbg_print("TS: 0x%x Direct convention" % ord(b))

        while ord(b) == 0x3b:
            b = self._rx_byte()

        if not b:
            return -1
        t0 = ord(b)
        self._dbg_print("T0: 0x%x" % t0)
        self._atr = [0x3b, ord(b)]

        for i in range(4):
            if t0 & (0x10 << i):
                b = self._rx_byte()
                self._atr.append(ord(b))
                self._dbg_print("T%si = %x" % (chr(ord('A')+i), ord(b)))

        for i in range(0, t0 & 0xf):
            b = self._rx_byte()
            self._atr.append(ord(b))
            self._dbg_print("Historical = %x" % ord(b))

        while True:
            x = self._rx_byte()
            if not x:
                break
            self._atr.append(ord(x))
            self._dbg_print("Extra: %x" % ord(x))

        return 1

    def _dbg_print(self, s):
        if self._debug:
            print(s)

    def _tx_byte(self, b):
        self._sl.write(b)
        r = self._sl.read()
        if r != b:  # TX and RX are tied, so we must clear the echo
            raise ProtocolError("Bad echo value. Expected %02x, got %s)" % (
                ord(b), '%02x' % ord(r) if r else '(nil)'))

    def _tx_string(self, s):
        """This is only safe if it's guaranteed the card won't send any data
        during the time of tx of the string !!!"""
        self._sl.write(s)
        r = self._sl.read(len(s))
        if r != s:  # TX and RX are tied, so we must clear the echo
            raise ProtocolError(
                "Bad echo value (Expected: %s, got %s)" % (b2h(s), b2h(r)))

    def _rx_byte(self):
        return self._sl.read()

    def _send_apdu_raw(self, pdu: Hexstr) -> ResTuple:

        pdu = h2b(pdu)
        data_len = pdu[4]  # P3

        # Send first CLASS,INS,P1,P2,P3
        self._tx_string(pdu[0:5])

        # Wait ack which can be
        #  - INS: Command acked -> go ahead
        #  - 0x60: NULL, just wait some more
        #  - SW1: The card can apparently proceed ...
        while True:
            b = self._rx_byte()
            if ord(b) == pdu[1]:
                break
            if b != '\x60':
                # Ok, it 'could' be SW1
                sw1 = b
                sw2 = self._rx_byte()
                nil = self._rx_byte()
                if (sw2 and not nil):
                    return '', b2h(sw1+sw2)

                raise ProtocolError()

        # Send data (if any)
        if len(pdu) > 5:
            self._tx_string(pdu[5:])

        # Receive data (including SW !)
        #  length = [P3 - tx_data (=len(pdu)-len(hdr)) + 2 (SW1//2) ]
        to_recv = data_len - len(pdu) + 5 + 2

        data = bytes(0)
        while len(data) < to_recv:
            b = self._rx_byte()
            if (to_recv == 2) and (b == '\x60'):  # Ignore NIL if we have no RX data (hack ?)
                continue
            if not b:
                break
            data += b

        # Split datafield from SW
        if len(data) < 2:
            return None, None
        sw = data[-2:]
        data = data[0:-2]

        # Return value
        return b2h(data), b2h(sw)

    def __str__(self) -> str:
        return "serial:%s" % (self._sl.name)

    @staticmethod
    def argparse_add_reader_args(arg_parser: argparse.ArgumentParser):
        serial_group = arg_parser.add_argument_group('Serial Reader', """Use a simple/ultra-low-cost serial reader
attached to a (physical or USB/virtual) RS232 port.  This doesn't work with all RS232-attached smart card
readers, only with the very primitive readers following the ancient `Phoenix` or `Smart Mouse` design.""")
        serial_group.add_argument('-d', '--device', metavar='DEV', default='/dev/ttyUSB0',
                                  help='Serial Device for SIM access')
        serial_group.add_argument('-b', '--baud', dest='baudrate', type=int, metavar='BAUD', default=9600,
                                  help='Baud rate used for SIM access')
