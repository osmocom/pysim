# -*- coding: utf-8 -*-
"""Bearer Independent Protocol relay"""

#
# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
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

# A ProactiveHandler with TCP sockets that backs the BIP channels,
# so a card can run its own IP session (SCP81/HTTPS, CAT_TP, ...)
#
# Currently used by pySim-smpp2sim.py which connects the SMS path to its SMPP server.
# Other drivers can pass their own sinks:
#
#     handler = Proact(data_available_sink=..., sms_sink=...)
#     tp = init_reader(opts, proactive_handler=handler)


import logging
import socket
import threading
import time

from osmocom.utils import b2h, h2b

from pySim.transport import ProactiveHandler
from pySim.sms import SMS_DELIVER, SMS_SUBMIT, AddressField
from pySim.cat import (ProactiveCommand, SendShortMessage, SMS_TPDU, SMSPPDownload,
                       BearerDescription, DeviceIdentities, Address, OtherAddress,
                       UiccTransportLevel, BufferSize, ChannelStatus, ChannelData,
                       ChannelDataLength, EventList, EventDownload, Result)

logger = logging.getLogger(__name__)


def terminal_profile(num_channels: int = 7) -> bytes:
    """TERMINAL PROFILE for what we implement, TS 102 223 5.2 and annex T.

    Annex T table T.1 lists what a Connected Entity, a CAT client that is not the modem
    which is pretty much what we are, may announce, and its inverse is what only a modem may announce.
    """
    if not 0 <= num_channels <= ProactChannels.MAX_CHANNELS:
        raise ValueError('num_channels must be 0..%u' % ProactChannels.MAX_CHANNELS)
    profile = bytearray(32)
    # 1 (Download): b1 profile download, b2+b5 SMS-PP data download. Both of the latter, per the
    # note in TS 31.111 5.2: "several bits may need to be set to 1 for the support of the same
    # facility ... because of backward compatibility with SAT". The relay is OTA over SMS-PP.
    profile[0] = 0x01 | 0x02 | 0x10
    profile[1] = 0x01                    # 2 (Other): b1 command result
    profile[2] = 0x80                    # 3: b8 REFRESH (empty result is a valid answer, 6.4.7)
    profile[3] = 0x02                    # 4: b2 SEND SHORT MESSAGE (the OTA response path)
    profile[4] = 0x01                    # 5: b1 SET UP EVENT LIST
    profile[5] = 0x04 | 0x08             # 6: b3 Event Data available, b4 Event Channel status
    # 12 (class "e"): b1..b5 OPEN CHANNEL, CLOSE CHANNEL, RECEIVE DATA, SEND DATA, GET CHANNEL
    # STATUS.
    profile[11] = 0x1f
    # 13 (class "e" supported bearers): b2 GPRS, and b6..b8 the number of channels.
    profile[12] = 0x02 | (num_channels << 5)
    profile[13] = 0x40 | 0x20            # 14: b6 no display capability, b7 no keypad available
    profile[16] = 0x01                   # 15: b1 TCP, UICC in client mode, remote connection
    return bytes(profile)


class ProactChannel:
    """One BIP channel, TS 102 223 class "e", backed by a blocking TCP socket.

    Created by ProactChannels.channel_create(). A reader thread fills the Rx buffer from the
    socket, the Proact handlers drain it (RECEIVE DATA) and write to it (SEND DATA). Payload
    is opaque, TLS or CAT_TP run on the card.

    Args:
        channels: the owning ProactChannels, notified of data arrival and of close()
        chan_nr: channel number 1..7 as used in the Device identities
    """
    # Why blocking sockets and not Twisted endpoints, considering we have twisted?
    # The proactive-command loop lives in a blocking while-loop,
    # "pySim.transport.LinkBase.send_apdu_checksw" that runs on the Twisted reactor thread.
    # A Twisted async TCP client only makes any progress when the reactor uhh... reacts, but
    # the reactor is stuck in that loop for the whole proactive session -> the
    # connectProtocol() Deferred never fires while we are handling OPEN/SEND/RECEIVE CHANNEL.
    # Plain blocking sockets just work: connect() in handle_OpenChannel, send() in
    # handle_SendData, recv() feeding a buffer for handle_ReceiveData. No need to make it
    # harder than it has to be to handle the "massive" T0 bandwidth..
    # how much we try to read off the socket per recv()
    RECV_CHUNK = 4096

    def __init__(self, channels: 'ProactChannels', chan_nr: int):
        self.channels = channels
        self.chan_nr = chan_nr
        self.sock = None
        # TS 102 223 says the terminal keeps an Rx buffer per channel; RECEIVE
        # DATA drains it, and it is filled asynchronously as the peer sends.
        self.rx_buf = bytearray()
        self._rx_lock = threading.Lock()
        self._reader = None
        self._closing = False
        self.peer_closed = False

    def connect(self, host: str, port: int, timeout: float = 10.0):
        """Open the blocking TCP socket and start the background Rx reader."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(timeout)
            s.connect((host, port))
            # Back to blocking mode for the reader thread.
            # CLOSE CHANNEL unblocks the pending recv() via shutdown().
            s.settimeout(None)
        except OSError:
            s.close()
            raise
        self.sock = s
        self._reader = threading.Thread(target=self._rx_loop,
                                        name='bip-rx-%d' % self.chan_nr, daemon=True)
        self._reader.start()

    def _rx_loop(self):
        """Continuously read from the socket into rx_buf, like a real ME.

        TS 102 223 7.5.10.1 says the event is raised 'only if the targeted channel buffer is
        empty when new data arrives in it', so the data available hook fires on the
        empty->non-empty transition only. That is enough: every RECEIVE DATA response tells
        the card how many bytes remain, so it keeps fetching until the buffer is empty, and
        the next event restarts it when more data arrives."""
        while not self._closing:
            try:
                data = self.sock.recv(self.RECV_CHUNK)
            except (OSError, ValueError):
                break
            if not data:
                self.peer_closed = True
                break
            with self._rx_lock:
                was_empty = len(self.rx_buf) == 0
                self.rx_buf.extend(data)
            if was_empty and not self._closing:
                self.channels.notify_data_available(self)

    def send(self, data: bytes):
        """Tx, write bytes to the socket == SEND DATA"""
        self.sock.sendall(data)

    def available_rx(self) -> int:
        """Number of bytes waiting in the Rx buffer, what RECEIVE DATA can return right now."""
        with self._rx_lock:
            return len(self.rx_buf)

    def take_rx(self, n: int):
        """Take up to n bytes out of the Rx buffer. Returns (bytes, bytes still remaining)."""
        with self._rx_lock:
            chunk = bytes(self.rx_buf[:n])
            del self.rx_buf[:n]
            remaining = len(self.rx_buf)
        return chunk, remaining

    def wait_rx(self, timeout: float) -> int:
        """wait up to timeout seconds until the rxbuf has data
        returns the number of bytes available
        Cards have a "data available" event, card free callers use
        this to wait for the echoed bytes."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            avail = self.available_rx()
            if avail or self.peer_closed:
                return avail
            time.sleep(0.005)
        return self.available_rx()

    def close(self):
        """Close channel: stop reader, close socket, drop bookkeeping."""
        self._closing = True
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
        # CLOSE CHANNEL synchronously handled inside the rx reader thread
        # (data-available -> ENVELOPE -> FETCH -> handle_CloseChannel -> close),
        # so close() can be called on the reader thread.
        # Joining self raises "cannot join current thread" so better skip i..
        # setting _closing + shutting down the socket already makes _rx_loop
        # return on the next iteration anyway.
        if self._reader is not None and self._reader is not threading.current_thread():
            self._reader.join(timeout=1.0)
        self.channels.channel_delete(self.chan_nr)

class ProactChannels:
    """The open BIP channels of one terminal, keyed by channel number.

    Args:
        on_data_available: callback(chan: ProactChannel), invoked from the channel's reader
            thread when data arrives in an empty Rx buffer. Proact turns it into an
            ENVELOPE EVENT DOWNLOAD (data available).
    """

    # TS 102 223 8.56 channel identifier in 3 bits as "1 to 7", 0 == no channel available
    # TERMINAL PROFILE has to agree with byte 13 , "number of channels supported by terminal"
    MAX_CHANNELS = 7

    def __init__(self, on_data_available=None):
        self.channels = {}
        self._on_data_available = on_data_available

    def channel_create(self) -> ProactChannel:
        """Create a new proactive channel, allocating its integer number."""
        for i in range(1, self.MAX_CHANNELS + 1):
            if not i in self.channels:
                self.channels[i] = ProactChannel(self, i)
                return self.channels[i]
        raise ValueError('Cannot allocate another channel: All channels active')

    def channel_delete(self, chan_nr: int):
        """Forget a channel, called by ProactChannel.close()."""
        self.channels.pop(chan_nr, None)

    def notify_data_available(self, chan: ProactChannel):
        """Run the on_data_available callback for chan, if one was given."""
        if self._on_data_available:
            self._on_data_available(chan)

class Proact(ProactiveHandler):
    """ProactiveHandler that answers the BIP proactive commands with TCP sockets.

    The transport calls the handle_* methods with the decoded proactive command and posts
    the returned IE list as TERMINAL RESPONSE.

    Args:
        data_available_sink: callback(envelope_hex: str), called from a channel reader thread
            with an encoded ENVELOPE EVENT DOWNLOAD (data available). The caller forwards it
            to the card with the ENVELOPE command, the card then FETCHes RECEIVE DATA.
            None: the event is only logged (card free / test mode).
        sms_sink: callback(pdu), called with the SMPP deliver_sm of a SEND SHORT MESSAGE
            the card issued; pySim-smpp2sim.py hands it to its SMPP server.
            None: the SMS is logged and dropped.
    """
    def __init__(self, data_available_sink=None, sms_sink=None):
        self.data_available_sink = data_available_sink
        self.sms_sink = sms_sink
        self.channels = ProactChannels(on_data_available=self._on_channel_data_available)

    def receive_fetch(self, pcmd: ProactiveCommand):
        """Answer anything this handler has no specific handler for.

        A card coming up will usually issue PROVIDE LOCAL INFORMATION,
        POLL INTERVAL or TIMER MANAGEMENT before it gets anywhere near a BIP channel,
        whatever the TERMINAL PROFILE announces.

        Note that this is not the spec-correct answer. TS 102 223 6.8.7
        says a successful TERMINAL RESPONSE to PROVIDE LOCAL INFORMATION "shall" carry the
        requested Local information data object, and 6.8.13/6.8.14 says the same for TIMER
        MANAGEMENT, this returns empty results for all of them, which works with real cards.

        Always "performed_successfully", never "command_beyond_terminal_capability" because
        answering that to PROVIDE LOCAL INFORMATION makes a card refuse to open the session.
        """
        logger.info("no handler for %s, answering performed_successfully",
                    type(pcmd.decoded).__name__)
        return self.prepare_response(pcmd, 'performed_successfully')

    @staticmethod
    def _find_first_element_of_type(instlist, cls):
        for i in instlist:
            if isinstance(i, cls):
                return i
        return None

    @staticmethod
    def _channel_nr_from_dev_ids(dev_id_ie: DeviceIdentities) -> int:
        """Maps id like channel_1 -> channel number.
        TS 102 223 Section 8.7 says low nibble is channel number,
        channel-N = 0x21..0x27"""
        dest = dev_id_ie.decoded['dest_dev_id']
        return DeviceIdentities.DEV_IDS.inverse[dest] & 0x0f

    def _channel_for(self, dev_id_ie: DeviceIdentities):
        """Resolve the ProactChannel addressed by a command dev id, or None"""
        return self.channels.channels.get(self._channel_nr_from_dev_ids(dev_id_ie), None)

    @staticmethod
    def _channel_status(chan_nr: int, established: bool = True) -> str:
        """TS 102 223 Section 8.56 channel status value for the
        default/network bearer:
        - byte 3 low 3 bits = channel id
        - bit 8 = link established
        - byte 4 = 00 no further info"""
        b3 = (0x80 if established else 0x00) | (chan_nr & 0x07)
        return '%02x00' % b3

    def _bip_response_head(self, pcmd: ProactiveCommand,
                           general_result: str = 'performed_successfully',
                           additional_information: str = ''):
        """CommandDetails / DeviceIdentities / Result head part of a BIP TERMINAL
        RESPONSE. Built on prepare_response() but with two changes:

        - Device identities forced source=terminal, dest=UICC.
          TS 102 223 6.8.2 mandates for every TERMINAL RESPONSE
          prepare_response() inverts the commands device id, which is
          right for a uicc->terminal command but would yield a wrong
          channel_N->UICC for the channel addressed BIP commands.

        - Result is recreated for non success cases. prepare_response()
          hard codes empty "additional information", but for enum results
          like BIP error -> AddlInfoBip the empty value cannot be encoded at
          all, so we always ask prepare_response() for a success Result
          and swap for a properly encoded one here."""
        head = self.prepare_response(pcmd, 'performed_successfully')
        for i, ie in enumerate(head):
            if isinstance(ie, DeviceIdentities):
                head[i] = DeviceIdentities(decoded={'source_dev_id': 'terminal',
                                                    'dest_dev_id': 'uicc'})
            elif isinstance(ie, Result) and general_result != 'performed_successfully':
                res = Result()
                res.from_dict({'result': {'general_result': general_result,
                                          'additional_information': additional_information}})
                head[i] = res
        return head

    def _build_data_available_envelope(self, chan: ProactChannel) -> bytes:
        """TS 102 223 7.5.10.2 ENVELOPE EVENT DOWNLOAD
        Event list, Device id terminal->UICC, Channel status,
        Channel data length (bytes available or FF for > 255)."""
        avail = min(chan.available_rx(), 0xff)
        ed = EventDownload(children=[
            EventList(decoded=['data_available']),
            DeviceIdentities(decoded={'source_dev_id': 'terminal', 'dest_dev_id': 'uicc'}),
            ChannelStatus(decoded=self._channel_status(chan.chan_nr)),
            ChannelDataLength(decoded=avail),
        ])
        return ed.to_tlv()

    def _on_channel_data_available(self, chan: ProactChannel):
        """rx reader thread hook: socket data arrived while the channel buffer
        was empty. card uses ENVELOPE EVENT DOWNLOAD + responds by FETCHing RECEIVE DATA
        proactive command. Card free only builds and logs"""
        envelope_hex = b2h(self._build_data_available_envelope(chan))
        logger.info("channel %u: %u byte(s) available -> ENVELOPE(Data available) %s",
                    chan.chan_nr, chan.available_rx(), envelope_hex)
        if self.data_available_sink:
            self.data_available_sink(envelope_hex)

    # handle_*: called by the transport with the decoded proactive command, the returned IE
    # list becomes the TERMINAL RESPONSE.
    def handle_SendShortMessage(self, pcmd: ProactiveCommand):
        # {'smspp_download': [{'device_identities': {'source_dev_id': 'network',
        #                                            'dest_dev_id': 'uicc'}},
        #                     {'address': {'ton_npi': {'ext': True,
        #                                              'type_of_number': 'international',
        #                                              'numbering_plan_id': 'isdn_e164'},
        #                                  'call_number': '79'}},
        #                     {'sms_tpdu': {'tpdu': '40048111227ff6407070611535004d02700000481516011212000001fe4c0943aea42e45021c078ae06c66afc09303608874b72f58bacadb0dcf665c29349c799fbb522e61709c9baf1890015e8e8e196e36153106c8b92f95153774'}}
        #                    ]}
        """SEND SHORT MESSAGE: hand the MO-SMS to sms_sink, answer with success so the card
        continues with the next part of a multi part response."""
        logger.info("SendShortMessage")
        logger.info(pcmd)
        # Relevant parts in pcmd: Address, SMS_TPDU
        addr_ie = Proact._find_first_element_of_type(pcmd.children, Address)
        sms_tpdu_ie = Proact._find_first_element_of_type(pcmd.children, SMS_TPDU)
        raw_tpdu = sms_tpdu_ie.decoded['tpdu']
        submit = SMS_SUBMIT.from_bytes(raw_tpdu)
        submit.tp_da = AddressField(addr_ie.decoded['call_number'], addr_ie.decoded['ton_npi']['type_of_number'],
                                    addr_ie.decoded['ton_npi']['numbering_plan_id'])
        logger.info(submit)
        self.send_sms_via_smpp(submit)
        # Return a successful TERMINAL RESPONSE.
        # This is important:
        # - without it the transport cannot complete the proactive command
        # - for a multi part OTA response, the card would never be asked to give us
        # the remaining SMS chunks.
        # 'pcmd' is a decoded SendShortMessage IE, which contains CommandDetails and
        # DeviceIdentities that prepare_response() echoes/inverts.
        return self.prepare_response(pcmd)

    def handle_OpenChannel(self, pcmd: ProactiveCommand):
        """OPEN CHANNEL: connect a TCP socket to the given address and port, allocate a
        channel number and report it in the Channel status of the response."""
        # {'open_channel': [{'command_details': {'command_number': 1,
        #                                        'type_of_command': 'open_channel',
        #                                        'command_qualifier': 3}},
        #                   {'device_identities': {'source_dev_id': 'uicc',
        #                                          'dest_dev_id': 'terminal'}},
        #                   {'bearer_description': {'bearer_type': 'default',
        #                                           'bearer_parameters': ''}},
        #                   {'buffer_size': 1024},
        #                   {'uicc_transport_level': {'protocol_type': 'tcp_uicc_client_remote',
        #                                             'port_number': 32768}},
        #                   {'other_address': {'type_of_address': 'ipv4',
        #                                      'address': '01020304'}}
        #                  ]}
        logger.info("OpenChannel")
        logger.info(pcmd)
        transp_lvl_ie = Proact._find_first_element_of_type(pcmd.children, UiccTransportLevel)
        other_addr_ie = Proact._find_first_element_of_type(pcmd.children, OtherAddress)
        bearer_desc_ie = Proact._find_first_element_of_type(pcmd.children, BearerDescription)
        buffer_size_ie = Proact._find_first_element_of_type(pcmd.children, BufferSize)

        def refuse(additional_information: str, chan_nr: int = 0):
            """TERMINAL RESPONSE refusing the OPEN CHANNEL

            - always a BIP error, only the cause byte of TS 102 223 8.12.11 differs
            - chan_nr 0 -> "no channel available" in the Channel status, 8.56
            - 6.8.18, 6.8.20, 6.8.21 want chan status, Bearer desc and buf size
              in a successful or unsuccessful response
            """
            ies = [ChannelStatus(decoded=self._channel_status(chan_nr, established=False))]
            ies += [ie for ie in (bearer_desc_ie, buffer_size_ie) if ie is not None]
            return self._bip_response_head(pcmd, 'bearer_independent_protocol_error',
                                           additional_information) + ies

        # UICC/terminal interface transport level is Optional, TS 102 223 6.6.27.x. Absent means
        # the CAT application runs its own network and transport layer, which we do not do.
        if transp_lvl_ie is None or transp_lvl_ie.decoded['protocol_type'] != 'tcp_uicc_client_remote':
            logger.warning("OpenChannel: unsupported UICC/terminal interface transport level (%s) "
                           "-> refusing", transp_lvl_ie.decoded if transp_lvl_ie else '(absent)')
            return refuse('requested_uicc_if_transp_level_not_available')
        if other_addr_ie is None or other_addr_ie.decoded.get('type_of_address', None) != 'ipv4':
            # No cause byte fits a wrong address family. '06' is about the transport level data
            # object, and 8.12.11 leaves '14' ("IPv4 only allowed") reserved by 3GPP, so '00'.
            logger.warning("OpenChannel: unsupported data destination address (%s) -> refusing",
                           other_addr_ie.decoded if other_addr_ie else '(absent)')
            return refuse('no_specific_cause')
        addr_bytes = h2b(other_addr_ie.decoded['address']) if isinstance(
                other_addr_ie.decoded['address'], str) else other_addr_ie.decoded['address']
        ipv4_str = '%u.%u.%u.%u' % (addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3])
        port_nr = transp_lvl_ie.decoded['port_number']
        logger.info("OpenChannel: connecting to %s:%u", ipv4_str, port_nr)
        try:
            channel = self.channels.channel_create()
        except ValueError:
            # TS 102 223 6.4.27.2 and 6.4.27.3: no channel left -> BIP error
            logger.warning("OpenChannel: all %u channels are in use -> refusing",
                           len(self.channels.channels))
            return refuse('no_channel_availabile')
        # yes, blocking connect()
        try:
            channel.connect(ipv4_str, port_nr)
        except OSError as e:
            logger.warning("OpenChannel: connect to %s:%u failed: %s", ipv4_str, port_nr, e)
            self.channels.channel_delete(channel.chan_nr)
            # TS 102 223 6.4.30 is the only clause naming a cause for a link that could not be
            # established: BIP error, channel closed. 6.4.27.4 lists no error cases at all.
            return refuse('channel_closed', channel.chan_nr)

        # Terminal Response example: [
        #  {'command_details': {'command_number': 1,
        #                       'type_of_command': 'open_channel',
        #                       'command_qualifier': 3}},
        #  {'device_identities': {'source_dev_id': 'terminal', 'dest_dev_id': 'uicc'}},
        #  {'result': {'general_result': 'performed_successfully', 'additional_information': ''}},
        #  {'channel_status': '8100'},
        #  {'bearer_description': {'bearer_type': 'default', 'bearer_parameters': ''}},
        #  {'buffer_size': 1024}
        # ]
        return self._bip_response_head(pcmd) + [
                ChannelStatus(decoded=self._channel_status(channel.chan_nr)),
                bearer_desc_ie, buffer_size_ie]

    def handle_CloseChannel(self, pcmd: ProactiveCommand):
        """CLOSE CHANNEL: close the socket of the addressed channel and free its number."""
        logger.info("CloseChannel")
        logger.info(pcmd)
        dev_id_ie = Proact._find_first_element_of_type(pcmd.children, DeviceIdentities)
        chan = self._channel_for(dev_id_ie)
        if chan is None:
            # channel closed / invalid
            return self._bip_response_head(pcmd, 'bearer_independent_protocol_error',
                                           'channel_id_not_valid')
        chan.close()
        return self._bip_response_head(pcmd)

    def handle_ReceiveData(self, pcmd: ProactiveCommand):
        """RECEIVE DATA: the card fetches up to Channel data length bytes from the Rx buffer
        of the addressed channel, the response also carries how many bytes remain."""
        # {'receive_data': [{'command_details': {'command_number': 1,
        #                                        'type_of_command': 'receive_data',
        #                                        'command_qualifier': 0}},
        #                   {'device_identities': {'source_dev_id': 'uicc',
        #                                          'dest_dev_id': 'channel_1'}},
        #                   {'channel_data_length': 9}
        #                  ]}
        logger.info("ReceiveData")
        logger.info(pcmd)
        dev_id_ie = Proact._find_first_element_of_type(pcmd.children, DeviceIdentities)
        req_len_ie = Proact._find_first_element_of_type(pcmd.children, ChannelDataLength)
        chan = self._channel_for(dev_id_ie)
        if chan is None:
            return self._bip_response_head(pcmd, 'bearer_independent_protocol_error',
                                           'channel_id_not_valid')
        # TS 102 223 8.54: RECEIVE DATA contains the requested count the card wants
        requested = req_len_ie.decoded if req_len_ie is not None else chan.available_rx()
        data, remaining = chan.take_rx(requested)
        # TS 102 223 6.4.29:
        # - return data available in the Rx buffer + num bytes still remaining (FF if > 255)
        # - if fewer than requested available terminal must NOT wait, report and returns what we have
        general_result = 'performed_successfully'
        if len(data) < requested:
            general_result = 'performed_with_missing_information'
        # Terminal Response example: [
        #  {'command_details': {'command_number': 1,
        #                       'type_of_command': 'receive_data',
        #                       'command_qualifier': 0}},
        #  {'device_identities': {'source_dev_id': 'terminal', 'dest_dev_id': 'uicc'}},
        #  {'result': {'general_result': 'performed_successfully', 'additional_information': ''}},
        #  {'channel_data': '16030100040e000000'},
        #  {'channel_data_length': 0}
        # ]
        return self._bip_response_head(pcmd, general_result) + [
                ChannelData(decoded=b2h(data)),
                ChannelDataLength(decoded=min(remaining, 0xff))]

    def handle_SendData(self, pcmd: ProactiveCommand):
        """SEND DATA: write the Channel data of the command to the socket of the addressed
        channel."""
        # {'send_data': [{'command_details': {'command_number': 1,
        #                                     'type_of_command': 'send_data',
        #                                     'command_qualifier': 1}},
        #                {'device_identities': {'source_dev_id': 'uicc',
        #                                       'dest_dev_id': 'channel_1'}},
        #                {'channel_data': '160301003c010000380303d0f45e12b52ce5bb522750dd037738195334c87a46a847fe2b6886cada9ea6bf00000a00ae008c008b00b0002c010000050001000101'}
        #               ]}
        logger.info("SendData")
        logger.info(pcmd)
        dev_id_ie = Proact._find_first_element_of_type(pcmd.children, DeviceIdentities)
        chan_data_ie = Proact._find_first_element_of_type(pcmd.children, ChannelData)
        chan = self._channel_for(dev_id_ie)
        if chan is None:
            return self._bip_response_head(pcmd, 'bearer_independent_protocol_error',
                                           'channel_id_not_valid')
        # lets accept hexstrings as well
        payload = chan_data_ie.decoded
        if isinstance(payload, str):
            payload = h2b(payload)
        # command_qualifier bit 1 selects 'send immediately' / Tx-buffer store and forward
        # For TCP stream all we have is a socket and TCP takes care of segmentation,
        # so just send.
        chan.send(payload)
        # Terminal Response example: [
        #  {'command_details': {'command_number': 1,
        #                       'type_of_command': 'send_data',
        #                       'command_qualifier': 1}},
        #  {'device_identities': {'source_dev_id': 'terminal', 'dest_dev_id': 'uicc'}},
        #  {'result': {'general_result': 'performed_successfully', 'additional_information': ''}},
        #  {'channel_data_length': 255}
        # ]
        # TS 102 223 6.4.30 / 8.54 Channel data length = free space tx buf; FF == > 255 available
        return self._bip_response_head(pcmd) + [ChannelDataLength(decoded=255)]

    def handle_SetUpEventList(self, pcmd: ProactiveCommand):
        """SET UP EVENT LIST: acknowledged, data available and channel status are always on."""
        # {'set_up_event_list': [{'command_details': {'command_number': 1,
        #                                             'type_of_command': 'set_up_event_list',
        #                                             'command_qualifier': 0}},
        #                        {'device_identities': {'source_dev_id': 'uicc',
        #                                               'dest_dev_id': 'terminal'}},
        #                        {'event_list': ['data_available', 'channel_status']}
        #                       ]}
        logger.info("SetUpEventList")
        logger.info(pcmd)
        # Terminal Response example: [
        #  {'command_details': {'command_number': 1,
        #                       'type_of_command': 'set_up_event_list',
        #                       'command_qualifier': 0}},
        #  {'device_identities': {'source_dev_id': 'terminal', 'dest_dev_id': 'uicc'}},
        #  {'result': {'general_result': 'performed_successfully', 'additional_information': ''}}
        # ]
        return self.prepare_response(pcmd)

    def getChannelStatus(self, pcmd: ProactiveCommand):
        logger.info("GetChannelStatus")
        logger.info(pcmd)
        return self.prepare_response(pcmd) + []

    def send_sms_via_smpp(self, submit: SMS_SUBMIT):
        # while in a normal network the phone/ME would *submit* a message to the SMSC,
        # we are actually emulating the SMSC itself, so we must *deliver* the message
        # to the ESME
        deliver = SMS_DELIVER.from_submit(submit)
        deliver_smpp = deliver.to_smpp()

        if self.sms_sink is None:
            logger.info('no sms_sink: dropping MO-SMS %s', deliver_smpp)
            return
        self.sms_sink(deliver_smpp)
#       # obtain the connection/binding of system_id to be used for delivering MO-SMS to the ESME
#       connection = smpp_server.getBoundConnections[system_id].getNextBindingForDelivery()
#       connection.sendDataRequest(deliver_smpp)



