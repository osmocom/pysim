#!/usr/bin/env python3

# (C) 2026 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
#
# Author: Eric Wild
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

from osmocom.utils import b2h, h2b

from pySim.sms import SMS_SUBMIT, AddressField
from pySim.cat import (ProactiveCommand, CommandDetails, DeviceIdentities,
                       BearerDescription, BufferSize, UiccTransportLevel,
                       OtherAddress, ChannelData, ChannelDataLength, ChannelStatus,
                       Result, LocationInformation)

from pySim.bip import Proact, ProactChannels, terminal_profile


class _EchoServer:
    """behold, my tiny threaded TCP echo server listening on 127.0.0.1:<port>"""
    def __init__(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(('127.0.0.1', 0))
        self._srv.listen(1)
        self.port = self._srv.getsockname()[1]
        self.accepted = threading.Event()
        self._conns = []
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        self._conns.append(conn)
        self.accepted.set()
        while not self._stop:
            try:
                data = conn.recv(4096)
            except OSError:
                break
            if not data:
                break
            conn.sendall(data)

    def close(self):
        self._stop = True
        for s in [self._srv] + self._conns:
            try:
                s.close()
            except OSError:
                pass


def _pcmd(children_tlvs):
    """Assemble D0 proactive-command TLV from child IE bytes,
    decode it like transport does after a FETCH"""
    body = b''.join(children_tlvs)
    pdu = h2b('D0') + bytes([len(body)]) + body
    return ProactiveCommand().from_tlv(pdu)


def _open_channel(port, ip='127.0.0.1', cmd_nr=1):
    a, b, c, d = (int(x) for x in ip.split('.'))
    return _pcmd([
        CommandDetails(decoded={'command_number': cmd_nr, 'type_of_command': 'open_channel',
                                'command_qualifier': 3}).to_tlv(),
        DeviceIdentities(decoded={'source_dev_id': 'uicc', 'dest_dev_id': 'terminal'}).to_tlv(),
        BearerDescription(decoded={'bearer_type': 'default', 'bearer_parameters': b''}).to_tlv(),
        BufferSize(decoded=1024).to_tlv(),
        UiccTransportLevel(decoded={'protocol_type': 'tcp_uicc_client_remote',
                                    'port_number': port}).to_tlv(),
        OtherAddress(decoded={'type_of_address': 'ipv4',
                              'address': bytes([a, b, c, d])}).to_tlv(),
    ])


def _open_channel_raw(extra_ies, cmd_nr=1):
    """OPEN CHANNEL with only the head data"""
    return _pcmd([
        CommandDetails(decoded={'command_number': cmd_nr, 'type_of_command': 'open_channel',
                                'command_qualifier': 3}).to_tlv(),
        DeviceIdentities(decoded={'source_dev_id': 'uicc', 'dest_dev_id': 'terminal'}).to_tlv(),
        BearerDescription(decoded={'bearer_type': 'default', 'bearer_parameters': b''}).to_tlv(),
        BufferSize(decoded=1024).to_tlv(),
    ] + extra_ies)


def _send_data(payload, chan='channel_1', cmd_nr=1):
    return _pcmd([
        CommandDetails(decoded={'command_number': cmd_nr, 'type_of_command': 'send_data',
                                'command_qualifier': 1}).to_tlv(),
        DeviceIdentities(decoded={'source_dev_id': 'uicc', 'dest_dev_id': chan}).to_tlv(),
        ChannelData(decoded=b2h(payload)).to_tlv(),
    ])


def _receive_data(length, chan='channel_1', cmd_nr=1):
    return _pcmd([
        CommandDetails(decoded={'command_number': cmd_nr, 'type_of_command': 'receive_data',
                                'command_qualifier': 0}).to_tlv(),
        DeviceIdentities(decoded={'source_dev_id': 'uicc', 'dest_dev_id': chan}).to_tlv(),
        ChannelDataLength(decoded=length).to_tlv(),
    ])


def _close_channel(chan='channel_1', cmd_nr=1):
    return _pcmd([
        CommandDetails(decoded={'command_number': cmd_nr, 'type_of_command': 'close_channel',
                                'command_qualifier': 0}).to_tlv(),
        DeviceIdentities(decoded={'source_dev_id': 'uicc', 'dest_dev_id': chan}).to_tlv(),
    ])


def _first(til, cls):
    return next((x for x in til if isinstance(x, cls)), None)


class BipRelayRoundTripTest(unittest.TestCase):
    """Drive the fixed Proact handlers (blocking sockets) with synthetic
    proactive commands against a local echo server and assert a byte round-trip
    plus the channel bookkeeping / error handling."""

    def setUp(self):
        self.echo = _EchoServer()
        self.addCleanup(self.echo.close)
        self.events = []
        self.proact = Proact(data_available_sink=self.events.append)
        self.addCleanup(self._close_all_channels)

    def _close_all_channels(self):
        for chan in list(self.proact.channels.channels.values()):
            try:
                chan.close()
            except Exception:
                pass

    def _open(self, cmd_nr=1):
        til = self.proact.handle_OpenChannel(_open_channel(self.echo.port, cmd_nr=cmd_nr))
        # every TLV in the response must serialise (the transport does exactly
        # this to post the TERMINAL RESPONSE)
        b''.join(x.to_tlv() for x in til)
        return til

    def test_open_send_receive_roundtrip(self):
        # OPEN CHANNEL -> socket connected, channel 1 opened, link established
        til = self._open()
        self.assertTrue(self.echo.accepted.wait(timeout=2.0))
        self.assertIn(1, self.proact.channels.channels)
        cd = _first(til, CommandDetails)
        self.assertEqual(cd.decoded['type_of_command'], 'open_channel')
        # TS 102 223 6.8.2 TERMINAL RESPONSE device id: terminal -> UICC
        self.assertEqual(b2h(_first(til, DeviceIdentities).to_tlv()), '82028281')
        # channel status: channel 1, link established
        self.assertEqual(_first(til, ChannelStatus).decoded, '8100')
        self.assertEqual(_first(til, Result).decoded['general_result'], 'performed_successfully')

        # SEND DATA -> bytes written to the socket, echo server sends them back
        payload = b'Hello SCP81 relay - opaque TLS record bytes'
        til = self.proact.handle_SendData(_send_data(payload))
        b''.join(x.to_tlv() for x in til)
        # channel data length in the response = free Tx space, FF = ">255"
        self.assertEqual(_first(til, ChannelDataLength).decoded, 255)
        self.assertEqual(_first(til, Result).decoded['general_result'], 'performed_successfully')

        # RECEIVE DATA -> drain the bytes back to the "card". real card
        # uses data-available event, we poll the buffer
        # and may need several RECEIVE DATA commands, as the spec allows.
        got = bytearray()
        deadline = time.monotonic() + 3.0
        while len(got) < len(payload) and time.monotonic() < deadline:
            chan = self.proact.channels.channels[1]
            chan.wait_rx(1.0)
            til = self.proact.handle_ReceiveData(_receive_data(len(payload) - len(got)))
            b''.join(x.to_tlv() for x in til)
            self.assertEqual(b2h(_first(til, DeviceIdentities).to_tlv()), '82028281')
            got += h2b(_first(til, ChannelData).decoded)
        self.assertEqual(bytes(got), payload, "byte round-trip through the BIP relay")

        # CLOSE CHANNEL -> socket closed, bookkeeping cleared
        til = self.proact.handle_CloseChannel(_close_channel())
        b''.join(x.to_tlv() for x in til)
        self.assertEqual(_first(til, Result).decoded['general_result'], 'performed_successfully')
        self.assertNotIn(1, self.proact.channels.channels)

    def test_data_available_event_envelope(self):
        # The empty->non-empty Rx transition raises ENVELOPE EVENT DOWNLOAD
        self._open()
        self.assertTrue(self.echo.accepted.wait(timeout=2.0))
        payload = b'PONG'
        self.proact.handle_SendData(_send_data(payload))
        chan = self.proact.channels.channels[1]
        self.assertGreater(chan.wait_rx(2.0), 0)
        # give the reader thread a beat to invoke the sink
        deadline = time.monotonic() + 2.0
        while not self.events and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(self.events), 1, "one data-available event on the empty->non-empty edge")
        env = h2b(self.events[0])
        # d6 0e | 99 01 09 (event: data available) | 82 02 82 81 terminal->UICC
        #       | b8 02 81 00 (channel 1 established) | b7 01 XX bytes available
        self.assertEqual(b2h(env[:15]), 'd60e99010982028281b8028100b701')
        self.assertGreaterEqual(env[15], 1)
        self.assertLessEqual(env[15], len(payload))

    def test_channel_number_from_device_identities(self):
        # Two channels, not the old hardcoded 1
        e2 = _EchoServer()
        self.addCleanup(e2.close)
        self.proact.handle_OpenChannel(_open_channel(self.echo.port))
        # open a second channel with a second echo server
        til2 = self.proact.handle_OpenChannel(_open_channel(e2.port))
        self.assertEqual(sorted(self.proact.channels.channels), [1, 2])
        self.assertEqual(_first(til2, ChannelStatus).decoded, '8200')  # channel 2, established

        # SEND DATA addressed to channel_2 must reach the second socket
        self.assertTrue(e2.accepted.wait(timeout=2.0))
        self.proact.handle_SendData(_send_data(b'two', chan='channel_2'))
        chan2 = self.proact.channels.channels[2]
        self.assertGreater(chan2.wait_rx(2.0), 0)
        til = self.proact.handle_ReceiveData(_receive_data(3, chan='channel_2'))
        self.assertEqual(h2b(_first(til, ChannelData).decoded), b'two')
        # ..and nothing on chan 1
        self.assertEqual(self.proact.channels.channels[1].available_rx(), 0)

    def test_commands_on_closed_channel_report_bip_error(self):
        # SEND/RECEIVE/CLOSE on a channel that was never opened must be rejected
        # with a BIP error
        for til in (self.proact.handle_SendData(_send_data(b'x', chan='channel_4')),
                    self.proact.handle_ReceiveData(_receive_data(1, chan='channel_4')),
                    self.proact.handle_CloseChannel(_close_channel(chan='channel_4'))):
            b''.join(x.to_tlv() for x in til)
            res = _first(til, Result).decoded
            self.assertEqual(res['general_result'], 'bearer_independent_protocol_error')
            self.assertEqual(res['additional_information'], 'channel_id_not_valid')

    def test_receive_more_than_available_is_missing_info(self):
        # terminal must NOT wait if fewer than the requested bytes are buffered,
        # eturns what it has with "performed with missing information".
        self._open()
        self.assertTrue(self.echo.accepted.wait(timeout=2.0))
        til = self.proact.handle_ReceiveData(_receive_data(10))
        b''.join(x.to_tlv() for x in til)
        self.assertEqual(_first(til, Result).decoded['general_result'],
                         'performed_with_missing_information')
        self.assertEqual(h2b(_first(til, ChannelData).decoded), b'')
        self.assertEqual(_first(til, ChannelDataLength).decoded, 0)


class OpenChannelRefusalTest(unittest.TestCase):
    """Refusal is a TERMINAL RESPONSE, not an exception, raising takes the whole
    proactive session down and leaves the card wondering why"""

    ADDR = OtherAddress(decoded={'type_of_address': 'ipv4', 'address': bytes([127, 0, 0, 1])})
    TCP = UiccTransportLevel(decoded={'protocol_type': 'tcp_uicc_client_remote', 'port_number': 1234})

    def setUp(self):
        self.proact = Proact()
        self.addCleanup(self._close_all_channels)

    def _close_all_channels(self):
        for chan in list(self.proact.channels.channels.values()):
            try:
                chan.close()
            except Exception:
                pass

    def _assert_refused(self, til, additional_information, chan_nr=0):
        b''.join(x.to_tlv() for x in til)               # must serialise, the transport posts it
        res = _first(til, Result).decoded
        self.assertEqual(res['general_result'], 'bearer_independent_protocol_error')
        self.assertEqual(res['additional_information'], additional_information)
        self.assertEqual(_first(til, ChannelStatus).decoded, '%02x00' % chan_nr)   # 8.56
        self.assertIsNotNone(_first(til, BearerDescription))                       # 6.8.20
        self.assertIsNotNone(_first(til, BufferSize))                              # 6.8.21
        self.assertEqual(b2h(_first(til, DeviceIdentities).to_tlv()), '82028281')  # 6.8.2

    def test_transport_level(self):
        cases = [[self.ADDR.to_tlv()]]                             # absent, 6.6.27.x Optional
        for proto in ('udp_uicc_client_remote', 'tcp_uicc_server', 'udp_uicc_client_local',
                      'tcp_uicc_client_local', 'direct_channel'):   # not TCP client remote
            tl = UiccTransportLevel(decoded={'protocol_type': proto, 'port_number': 1234})
            cases.append([tl.to_tlv(), self.ADDR.to_tlv()])
        for extra in cases:
            with self.subTest(extra=b2h(extra[0])):
                self._assert_refused(self.proact.handle_OpenChannel(_open_channel_raw(extra)),
                                     'requested_uicc_if_transp_level_not_available')

    def test_destination_address(self):
        v6 = OtherAddress(decoded={'type_of_address': 'ipv6', 'address': bytes(16)})
        for extra in ([self.TCP.to_tlv()],                         # absent
                      [self.TCP.to_tlv(), v6.to_tlv()]):           # not IPv4
            with self.subTest(extra=len(extra)):
                self._assert_refused(self.proact.handle_OpenChannel(_open_channel_raw(extra)),
                                     'no_specific_cause')

    def test_no_channel_left(self):
        for _ in range(7):                                         # 6.4.27.2, 6.4.27.3
            self.proact.channels.channel_create()
        cmd = _open_channel_raw([self.TCP.to_tlv(), self.ADDR.to_tlv()])
        self._assert_refused(self.proact.handle_OpenChannel(cmd), 'no_channel_availabile')

    def test_connect_failure(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      # port nothing listens on
        s.bind(('127.0.0.1', 0))
        dead_port = s.getsockname()[1]
        s.close()
        til = self.proact.handle_OpenChannel(_open_channel(dead_port))
        self._assert_refused(til, 'channel_closed', chan_nr=1)      # 6.4.30
        self.assertEqual(self.proact.channels.channels, {})        # channel given back


class ProvideLocalInformationTest(unittest.TestCase):
    """TS 102 223 6.8.7: only 00 gets a data object; the rest keeps the empty result."""

    def _cmd(self, qualifier):
        return _pcmd([
            CommandDetails(decoded={'command_number': 1, 'type_of_command': 'provide_local_info',
                                    'command_qualifier': qualifier}).to_tlv(),
            DeviceIdentities(decoded={'source_dev_id': 'uicc', 'dest_dev_id': 'terminal'}).to_tlv()])

    def test_location(self):
        til = Proact().handle_ProvideLocalInformation(self._cmd(0x00))
        b''.join(x.to_tlv() for x in til)
        self.assertEqual(_first(til, Result).decoded['general_result'], 'performed_successfully')
        self.assertEqual(b2h(_first(til, LocationInformation).to_tlv()), '930762f21000010001')
        self.assertEqual(b2h(_first(til, DeviceIdentities).to_tlv()), '82028281')   # 6.8.2

    def test_other_qualifiers_get_no_data_object(self):
        for qualifier in (0x01, 0x03, 0x04, 0x1a):
            with self.subTest(command_qualifier=qualifier):
                til = Proact().handle_ProvideLocalInformation(self._cmd(qualifier))
                b''.join(x.to_tlv() for x in til)
                self.assertIsNone(_first(til, LocationInformation))

    def test_location_is_configurable(self):
        til = Proact(location=h2b('26f8100539')).handle_ProvideLocalInformation(self._cmd(0x00))
        self.assertEqual(b2h(_first(til, LocationInformation).to_tlv()), '930526f8100539')


class TerminalProfileTest(unittest.TestCase):
    """TS 102 223 5.2, one bit per CAT facility"""

    def setUp(self):
        self.profile = terminal_profile()

    def byte(self, n):
        return self.profile[n - 1]                      # 1-based, as 5.2 numbers them

    def test_announced(self):
        self.assertEqual(len(self.profile), 32)
        self.assertEqual(self.byte(1), 0x13)            # profile download, SMS-PP download b2+b5
        self.assertEqual(self.byte(4), 0x02)            # SEND SHORT MESSAGE
        self.assertEqual(self.byte(5) & 0x01, 0x01)     # SET UP EVENT LIST
        self.assertEqual(self.byte(6), 0x0c)            # events: data available, channel status
        self.assertEqual(self.byte(12), 0x1f)           # OPEN/CLOSE CHANNEL, RECEIVE/SEND DATA, STATUS
        self.assertEqual(self.byte(13) >> 5, ProactChannels.MAX_CHANNELS)
        self.assertEqual(self.byte(14), 0x60)           # class ND, class NK
        self.assertEqual(self.byte(17), 0x01)           # TCP, UICC client mode, remote

    def test_not_announced(self):
        self.assertEqual(self.byte(3) & 0x60, 0)        # POLL INTERVAL, POLLING OFF
        self.assertEqual(self.byte(4) & 0xc0, 0)        # PROVIDE LOCAL INFORMATION, NMR
        self.assertEqual(self.byte(12) & 0xe0, 0)       # SERVICE SEARCH/INFORMATION, DECLARE SERVICE
        self.assertEqual(self.byte(14) & 0x1f, 0)       # no characters down the display
        for n in (7, 9, 10, 11, 15, 16, 18):            # class "a", class "d", display, ESN/IMEISV
            self.assertEqual(self.byte(n), 0)

    def test_channel_count(self):
        self.assertEqual(terminal_profile(3)[12] >> 5, 3)
        with self.assertRaises(ValueError):             # 8.56: 1 to 7
            terminal_profile(8)


if __name__ == "__main__":
    unittest.main()


class BipSinkTest(unittest.TestCase):
    """Both sinks are optional, a driver with no SMS path at all must not crash and burn
    with a card that sends one, and one that has one must get the PDU."""

    def _submit(self):
        return SMS_SUBMIT(tp_da=AddressField('12345', 'unknown', 'unknown'),
                          tp_ud=b'\x01\x02', tp_udl=2, tp_dcs=0xf6)

    def test_sinks_default_to_none(self):
        p = Proact()
        self.assertIsNone(p.sms_sink)

    def test_mo_sms_goes_to_the_sink(self):
        seen = []
        Proact(sms_sink=seen.append).send_sms_via_smpp(self._submit())
        self.assertEqual(len(seen), 1)

    def test_no_sms_sink_drops_instead_of_raising(self):
        with self.assertLogs('pySim.bip', level='INFO'):
            Proact().send_sms_via_smpp(self._submit())
