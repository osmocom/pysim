# -*- coding: utf-8 -*-

""" pySim: PCSC reader transport link base
"""

import abc
import argparse
from typing import Optional, Tuple
from construct import Construct

from pySim.exceptions import *
from pySim.construct import filter_dict
from pySim.utils import sw_match, b2h, h2b, i2h, Hexstr, SwHexstr, SwMatchstr, ResTuple
from pySim.cat import ProactiveCommand, CommandDetails, DeviceIdentities, Result

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2021-2023 Harald Welte <laforge@osmocom.org>
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


class ApduTracer:
    def trace_command(self, cmd):
        pass

    def trace_response(self, cmd, sw, resp):
        pass

class ProactiveHandler(abc.ABC):
    """Abstract base class representing the interface of some code that handles
    the proactive commands, as returned by the card in responses to the FETCH
    command."""
    def receive_fetch_raw(self, pcmd: ProactiveCommand, parsed: Hexstr):
        # try to find a generic handler like handle_SendShortMessage
        handle_name = 'handle_%s' % type(parsed).__name__
        if hasattr(self, handle_name):
            handler = getattr(self, handle_name)
            return handler(pcmd.decoded)
        # fall back to common handler
        return self.receive_fetch(pcmd)

    def receive_fetch(self, pcmd: ProactiveCommand):
        """Default handler for not otherwise handled proactive commands."""
        raise NotImplementedError('No handler method for %s' % pcmd.decoded)



class LinkBase(abc.ABC):
    """Base class for link/transport to card."""

    def __init__(self, sw_interpreter=None, apdu_tracer: Optional[ApduTracer]=None,
                 proactive_handler: Optional[ProactiveHandler]=None):
        self.sw_interpreter = sw_interpreter
        self.apdu_tracer = apdu_tracer
        self.proactive_handler = proactive_handler

    @abc.abstractmethod
    def __str__(self) -> str:
        """Implementation specific method for printing an information to identify the device."""

    @abc.abstractmethod
    def _send_apdu_raw(self, pdu: Hexstr) -> ResTuple:
        """Implementation specific method for sending the PDU."""

    def set_sw_interpreter(self, interp):
        """Set an (optional) status word interpreter."""
        self.sw_interpreter = interp

    @abc.abstractmethod
    def wait_for_card(self, timeout: Optional[int] = None, newcardonly: bool = False):
        """Wait for a card and connect to it

        Args:
           timeout : Maximum wait time in seconds (None=no timeout)
           newcardonly : Should we wait for a new card, or an already inserted one ?
        """

    @abc.abstractmethod
    def connect(self):
        """Connect to a card immediately
        """

    @abc.abstractmethod
    def disconnect(self):
        """Disconnect from card
        """

    @abc.abstractmethod
    def reset_card(self):
        """Resets the card (power down/up)
        """

    def send_apdu_raw(self, pdu: Hexstr) -> ResTuple:
        """Sends an APDU with minimal processing

        Args:
           pdu : string of hexadecimal characters (ex. "A0A40000023F00")
        Returns:
           tuple(data, sw), where
                        data : string (in hex) of returned data (ex. "074F4EFFFF")
                        sw   : string (in hex) of status word (ex. "9000")
        """
        if self.apdu_tracer:
            self.apdu_tracer.trace_command(pdu)
        (data, sw) = self._send_apdu_raw(pdu)
        if self.apdu_tracer:
            self.apdu_tracer.trace_response(pdu, sw, data)
        return (data, sw)

    def send_apdu(self, pdu: Hexstr) -> ResTuple:
        """Sends an APDU and auto fetch response data

        Args:
           pdu : string of hexadecimal characters (ex. "A0A40000023F00")
        Returns:
           tuple(data, sw), where
                        data : string (in hex) of returned data (ex. "074F4EFFFF")
                        sw   : string (in hex) of status word (ex. "9000")
        """
        data, sw = self.send_apdu_raw(pdu)

        # When we have sent the first APDU, the SW may indicate that there are response bytes
        # available. There are two SWs commonly used for this 9fxx (sim) and 61xx (usim), where
        # xx is the number of response bytes available.
        # See also:
        if (sw is not None):
            if ((sw[0:2] == '9f') or (sw[0:2] == '61')):
                # SW1=9F: 3GPP TS 51.011 9.4.1, Responses to commands which are correctly executed
                # SW1=61: ISO/IEC 7816-4, Table 5 — General meaning of the interindustry values of SW1-SW2
                pdu_gr = pdu[0:2] + 'c00000' + sw[2:4]
                data, sw = self.send_apdu_raw(pdu_gr)
            if sw[0:2] == '6c':
                # SW1=6C: ETSI TS 102 221 Table 7.1: Procedure byte coding
                pdu_gr = pdu[0:8] + sw[2:4]
                data, sw = self.send_apdu_raw(pdu_gr)

        return data, sw

    def send_apdu_checksw(self, pdu: Hexstr, sw: SwMatchstr = "9000") -> ResTuple:
        """Sends an APDU and check returned SW

        Args:
           pdu : string of hexadecimal characters (ex. "A0A40000023F00")
           sw : string of 4 hexadecimal characters (ex. "9000"). The user may mask out certain
                        digits using a '?' to add some ambiguity if needed.
        Returns:
                tuple(data, sw), where
                        data : string (in hex) of returned data (ex. "074F4EFFFF")
                        sw   : string (in hex) of status word (ex. "9000")
        """
        rv = self.send_apdu(pdu)
        last_sw = rv[1]

        while sw == '9000' and sw_match(last_sw, '91xx'):
            # It *was* successful after all -- the extra pieces FETCH handled
            # need not concern the caller.
            rv = (rv[0], '9000')
            # proactive sim as per TS 102 221 Setion 7.4.2
            # TODO: Check SW manually to avoid recursing on the stack (provided this piece of code stays in this place)
            fetch_rv = self.send_apdu_checksw('80120000' + last_sw[2:], sw)
            # Setting this in case we later decide not to send a terminal
            # response immediately unconditionally -- the card may still have
            # something pending even though the last command was not processed
            # yet.
            last_sw = fetch_rv[1]
            # parse the proactive command
            pcmd = ProactiveCommand()
            parsed = pcmd.from_tlv(h2b(fetch_rv[0]))
            print("FETCH: %s (%s)" % (fetch_rv[0], type(parsed).__name__))
            result = Result()
            if self.proactive_handler:
                # Extension point: If this does return a list of TLV objects,
                # they could be appended after the Result; if the first is a
                # Result, that cuold replace the one built here.
                self.proactive_handler.receive_fetch_raw(pcmd, parsed)
                result.from_dict({'general_result': 'performed_successfully', 'additional_information': ''})
            else:
                result.from_dict({'general_result': 'command_beyond_terminal_capability', 'additional_information': ''})

            # Send response immediately, thus also flushing out any further
            # proactive commands that the card already wants to send
            #
            # Structure as per TS 102 223 V4.4.0 Section 6.8

            # The Command Details are echoed from the command that has been processed.
            (command_details,) = [c for c in pcmd.decoded.children if isinstance(c, CommandDetails)]
            # The Device Identities are fixed. (TS 102 223 V4.0.0 Section 6.8.2)
            device_identities = DeviceIdentities()
            device_identities.from_dict({'source_dev_id': 'terminal', 'dest_dev_id': 'uicc'})

            # Testing hint: The value of tail does not influence the behavior
            # of an SJA2 that sent ans SMS, so this is implemented only
            # following TS 102 223, and not fully tested.
            tail = command_details.to_tlv() + device_identities.to_tlv() + result.to_tlv()
            # Testing hint: In contrast to the above, this part is positively
            # essential to get the SJA2 to provide the later parts of a
            # multipart SMS in response to an OTA RFM command.
            terminal_response = '80140000' + b2h(len(tail).to_bytes(1, 'big') + tail)

            terminal_response_rv = self.send_apdu(terminal_response)
            last_sw = terminal_response_rv[1]

        if not sw_match(rv[1], sw):
            raise SwMatchError(rv[1], sw.lower(), self.sw_interpreter)
        return rv

    def send_apdu_constr(self, cla: Hexstr, ins: Hexstr, p1: Hexstr, p2: Hexstr, cmd_constr: Construct,
                         cmd_data: Hexstr, resp_constr: Construct) -> Tuple[dict, SwHexstr]:
        """Build and sends an APDU using a 'construct' definition; parses response.

        Args:
                cla : string (in hex) ISO 7816 class byte
                ins : string (in hex) ISO 7816 instruction byte
                p1 : string (in hex) ISO 7116 Parameter 1 byte
                p2 : string (in hex) ISO 7116 Parameter 2 byte
                cmd_cosntr : defining how to generate binary APDU command data
                cmd_data : command data passed to cmd_constr
                resp_cosntr : defining how to decode  binary APDU response data
        Returns:
                Tuple of (decoded_data, sw)
        """
        cmd = cmd_constr.build(cmd_data) if cmd_data else ''
        p3 = i2h([len(cmd)])
        pdu = ''.join([cla, ins, p1, p2, p3, b2h(cmd)])
        (data, sw) = self.send_apdu(pdu)
        if data:
            # filter the resulting dict to avoid '_io' members inside
            rsp = filter_dict(resp_constr.parse(h2b(data)))
        else:
            rsp = None
        return (rsp, sw)

    def send_apdu_constr_checksw(self, cla: Hexstr, ins: Hexstr, p1: Hexstr, p2: Hexstr,
                                 cmd_constr: Construct, cmd_data: Hexstr, resp_constr: Construct,
                                 sw_exp: SwMatchstr="9000") -> Tuple[dict, SwHexstr]:
        """Build and sends an APDU using a 'construct' definition; parses response.

        Args:
                cla : string (in hex) ISO 7816 class byte
                ins : string (in hex) ISO 7816 instruction byte
                p1 : string (in hex) ISO 7116 Parameter 1 byte
                p2 : string (in hex) ISO 7116 Parameter 2 byte
                cmd_cosntr : defining how to generate binary APDU command data
                cmd_data : command data passed to cmd_constr
                resp_cosntr : defining how to decode  binary APDU response data
                exp_sw : string (in hex) of status word (ex. "9000")
        Returns:
                Tuple of (decoded_data, sw)
        """
        (rsp, sw) = self.send_apdu_constr(cla, ins,
                                          p1, p2, cmd_constr, cmd_data, resp_constr)
        if not sw_match(sw, sw_exp):
            raise SwMatchError(sw, sw_exp.lower(), self.sw_interpreter)
        return (rsp, sw)


def argparse_add_reader_args(arg_parser: argparse.ArgumentParser):
    """Add all reader related arguments to the given argparse.Argumentparser instance."""
    from pySim.transport.serial import SerialSimLink
    from pySim.transport.pcsc import PcscSimLink
    from pySim.transport.modem_atcmd import ModemATCommandLink
    from pySim.transport.calypso import CalypsoSimLink

    SerialSimLink.argparse_add_reader_args(arg_parser)
    PcscSimLink.argparse_add_reader_args(arg_parser)
    ModemATCommandLink.argparse_add_reader_args(arg_parser)
    CalypsoSimLink.argparse_add_reader_args(arg_parser)

    return arg_parser


def init_reader(opts, **kwargs) -> LinkBase:
    """
    Init card reader driver
    """
    if opts.pcsc_dev is not None:
        from pySim.transport.pcsc import PcscSimLink
        sl = PcscSimLink(opts.pcsc_dev, **kwargs)
    elif opts.osmocon_sock is not None:
        from pySim.transport.calypso import CalypsoSimLink
        sl = CalypsoSimLink(sock_path=opts.osmocon_sock, **kwargs)
    elif opts.modem_dev is not None:
        from pySim.transport.modem_atcmd import ModemATCommandLink
        sl = ModemATCommandLink(
             device=opts.modem_dev, baudrate=opts.modem_baud, **kwargs)
    else:  # Serial reader is default
        from pySim.transport.serial import SerialSimLink
        sl = SerialSimLink(device=opts.device,
                           baudrate=opts.baudrate, **kwargs)
    return sl
