# -*- coding: utf-8 -*-

# Copyright (C) 2020 Vadim Yanitskiy <axilirator@gmail.com>
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

import logging as log
import time
import re
import argparse
from typing import Optional
import serial
from osmocom.utils import Hexstr

from pySim.utils import ResTuple
from pySim.transport import LinkBase
from pySim.exceptions import ReaderError, ProtocolError

# HACK: if somebody needs to debug this thing
# log.root.setLevel(log.DEBUG)


class ModemATCommandLink(LinkBase):
    """Transport Link for 3GPP TS 27.007 compliant modems."""
    name = "modem for Generic SIM Access (3GPP TS 27.007)"

    def __init__(self, opts: argparse.Namespace = argparse.Namespace(modem_dev='/dev/ttyUSB0',
                                                                     modem_baud=115200), **kwargs):
        device = opts.modem_dev
        baudrate = opts.modem_baud
        super().__init__(**kwargs)
        self._sl = serial.Serial(device, baudrate, timeout=5)
        self._echo = False		# this will be auto-detected by _check_echo()
        self._device = device
        self._atr = None

        # Check the AT interface
        self._check_echo()

        # Trigger initial reset
        self.reset_card()

    def __del__(self):
        if hasattr(self, '_sl'):
            self._sl.close()

    def send_at_cmd(self, cmd, timeout=0.2, patience=0.002):
        # Convert from string to bytes, if needed
        bcmd = cmd if isinstance(cmd, bytes) else cmd.encode()
        bcmd += b'\r'

        # Clean input buffer from previous/unexpected data
        self._sl.reset_input_buffer()

        # Send command to the modem
        log.debug('Sending AT command: %s', cmd)
        try:
            wlen = self._sl.write(bcmd)
            assert wlen == len(bcmd)
        except Exception as exc:
            raise ReaderError('Failed to send AT command: %s' % cmd) from exc

        rsp = b''
        its = 1
        t_start = time.time()
        while True:
            rsp = rsp + self._sl.read(self._sl.in_waiting)
            lines = rsp.split(b'\r\n')
            if len(lines) >= 2:
                res = lines[-2]
                if res == b'OK':
                    log.debug('Command finished with result: %s', res)
                    break
                if res == b'ERROR' or res.startswith(b'+CME ERROR:'):
                    log.error('Command failed with result: %s', res)
                    break

            if time.time() - t_start >= timeout:
                log.info('Command finished with timeout >= %ss', timeout)
                break
            time.sleep(patience)
            its += 1
        log.debug('Command took %0.6fs (%d cycles a %fs)', time.time() - t_start, its, patience)

        if self._echo:
            # Skip echo chars
            rsp = rsp[wlen:]
        rsp = rsp.strip()
        rsp = rsp.split(b'\r\n\r\n')

        log.debug('Got response from modem: %s', rsp)
        return rsp

    def _check_echo(self):
        """Verify the correct response to 'AT' command
        and detect if inputs are echoed by the device

        Although echo of inputs can be enabled/disabled via
        ATE1/ATE0, respectively, we rather detect the current
        configuration of the modem without any change.
        """
        # Next command shall not strip the echo from the response
        self._echo = False
        result = self.send_at_cmd('AT')

        # Verify the response
        if len(result) > 0:
            if result[-1] == b'OK':
                self._echo = False
                return
            if result[-1] == b'AT\r\r\nOK':
                self._echo = True
                return
        raise ReaderError('Interface \'%s\' does not respond to \'AT\' command' % self._device)

    def _reset_card(self):
        # Reset the modem, just to be sure
        if self.send_at_cmd('ATZ') != [b'OK']:
            raise ReaderError('Failed to reset the modem')

        # Make sure that generic SIM access is supported
        if self.send_at_cmd('AT+CSIM=?') != [b'OK']:
            raise ReaderError('The modem does not seem to support SIM access')

        log.info('Modem at \'%s\' is ready!', self._device)

    def connect(self):
        pass  # Nothing to do really ...

    def disconnect(self):
        pass  # Nothing to do really ...

    def wait_for_card(self, timeout: Optional[int] = None, newcardonly: bool = False):
        pass  # Nothing to do really ...

    def _send_apdu_raw(self, pdu: Hexstr) -> ResTuple:
        # Make sure pdu has upper case hex digits [A-F]
        pdu = pdu.upper()

        # Prepare the command as described in 8.17
        cmd = 'AT+CSIM=%d,\"%s\"' % (len(pdu), pdu)
        log.debug('Sending command: %s',  cmd)

        # Send AT+CSIM command to the modem
        rsp = self.send_at_cmd(cmd)
        if rsp[-1].startswith(b'+CME ERROR:'):
            raise ProtocolError('AT+CSIM failed with: %s' % str(rsp))
        if len(rsp) != 2 or rsp[-1] != b'OK':
            raise ReaderError('APDU transfer failed: %s' % str(rsp))
        rsp = rsp[0]  # Get rid of b'OK'

        # Make sure that the response has format: b'+CSIM: %d,\"%s\"'
        try:
            result = re.match(b'\+CSIM: (\d+),\"([0-9A-F]+)\"', rsp)
            (_rsp_pdu_len, rsp_pdu) = result.groups()
        except Exception as exc:
            raise ReaderError('Failed to parse response from modem: %s' % rsp) from exc

        # TODO: make sure we have at least SW
        data = rsp_pdu[:-4].decode().lower()
        sw = rsp_pdu[-4:].decode().lower()
        log.debug('Command response: %s, %s',  data, sw)
        return data, sw

    def __str__(self) -> str:
        return "modem:%s" % self._device

    @staticmethod
    def argparse_add_reader_args(arg_parser: argparse.ArgumentParser):
        modem_group = arg_parser.add_argument_group('AT Command Modem Reader', """Talk to a SIM Card inside a
mobile phone or cellular modem which is attached to this computer and offers an AT command interface including
the AT+CSIM interface for Generic SIM access as specified in 3GPP TS 27.007.""")
        modem_group.add_argument('--modem-device', dest='modem_dev', metavar='DEV', default=None,
                                 help='Serial port of modem for Generic SIM Access (3GPP TS 27.007)')
        modem_group.add_argument('--modem-baud', type=int, metavar='BAUD', default=115200,
                                 help='Baud rate used for modem port')
