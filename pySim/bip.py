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

import logging
import socket
import threading
import time

from twisted.internet import endpoints, protocol, reactor

from osmocom.utils import b2h, h2b

from pySim.transport import ProactiveHandler
from pySim.sms import SMS_DELIVER, SMS_SUBMIT, AddressField
from pySim.cat import (ProactiveCommand, SendShortMessage, SMS_TPDU, SMSPPDownload,
                       BearerDescription, DeviceIdentities, Address, OtherAddress,
                       UiccTransportLevel, BufferSize, ChannelStatus, ChannelData,
                       ChannelDataLength, EventList, EventDownload, Result)

logger = logging.getLogger(__name__)

class TcpProtocol(protocol.Protocol):
    def dataReceived(self, data):
        pass

    def connectionLost(self, reason):
        pass


def tcp_connected_callback(p: protocol.Protocol):
    """called by twisted TCP client."""
    logger.error("%s: connected!" % p)

class ProactChannel:
    """Representation of a single protective channel."""
    def __init__(self, channels: 'ProactChannels', chan_nr: int):
        self.channels = channels
        self.chan_nr = chan_nr
        self.ep = None

    def close(self):
        """Close the channel."""
        if self.ep:
            self.ep.disconnect()
        self.channels.channel_delete(self.chan_nr)

class ProactChannels:
    """Wrapper class for maintaining state of proactive channels."""
    def __init__(self):
        self.channels = {}

    def channel_create(self) -> ProactChannel:
        """Create a new proactive channel, allocating its integer number."""
        for i in range(1, 9):
            if not i in self.channels:
                self.channels[i] = ProactChannel(self, i)
                return self.channels[i]
        raise ValueError('Cannot allocate another channel: All channels active')

    def channel_delete(self, chan_nr: int):
        del self.channels[chan_nr]

class Proact(ProactiveHandler):
    #def __init__(self, smpp_factory):
    #    self.smpp_factory = smpp_factory
    def __init__(self, sms_sink=None):
        # sms_sink(pdu) delivers an MO-SMS the card sent (SEND SHORT MESSAGE)
        # onwards; pySim-smpp2sim.py hands it to its SMPP server.  None -> log
        # and drop.
        self.sms_sink = sms_sink
        self.channels = ProactChannels()

    @staticmethod
    def _find_first_element_of_type(instlist, cls):
        for i in instlist:
            if isinstance(i, cls):
                return i
        return None

    """Call-back which the pySim transport core calls whenever it receives a
    proactive command from the SIM."""
    def handle_SendShortMessage(self, pcmd: ProactiveCommand):
        # {'smspp_download': [{'device_identities': {'source_dev_id': 'network',
        #                                            'dest_dev_id': 'uicc'}},
        #                     {'address': {'ton_npi': {'ext': True,
        #                                              'type_of_number': 'international',
        #                                              'numbering_plan_id': 'isdn_e164'},
        #                                  'call_number': '79'}},
        #                     {'sms_tpdu': {'tpdu': '40048111227ff6407070611535004d02700000481516011212000001fe4c0943aea42e45021c078ae06c66afc09303608874b72f58bacadb0dcf665c29349c799fbb522e61709c9baf1890015e8e8e196e36153106c8b92f95153774'}}
        #                    ]}
        """Card requests sending a SMS. We need to pass it on to the ESME via SMPP."""
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

    def handle_OpenChannel(self, pcmd: ProactiveCommand):
        """Card requests opening a new channel via a UDP/TCP socket."""
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
        if transp_lvl_ie.decoded['protocol_type'] != 'tcp_uicc_client_remote':
            raise ValueError('Unsupported protocol_type')
        if other_addr_ie.decoded.get('type_of_address', None) != 'ipv4':
            raise ValueError('Unsupported type_of_address')
        ipv4_bytes = h2b(other_addr_ie.decoded['address'])
        ipv4_str = '%u.%u.%u.%u' % (ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3])
        port_nr = transp_lvl_ie.decoded['port_number']
        print("%s:%u" % (ipv4_str, port_nr))
        channel = self.channels.channel_create()
        channel.ep = endpoints.TCP4ClientEndpoint(reactor, ipv4_str, port_nr)
        channel.prot = TcpProtocol()
        d = endpoints.connectProtocol(channel.ep, channel.prot)
        # FIXME: why is this never called despite the client showing the inbound connection?
        d.addCallback(tcp_connected_callback)

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
        return self.prepare_response(pcmd) + [ChannelStatus(decoded='8100'), bearer_desc_ie, buffer_size_ie]

    def handle_CloseChannel(self, pcmd: ProactiveCommand):
        """Close a channel."""
        logger.info("CloseChannel")
        logger.info(pcmd)

    def handle_ReceiveData(self, pcmd: ProactiveCommand):
        """Receive/read data from the socket."""
        # {'receive_data': [{'command_details': {'command_number': 1,
        #                                        'type_of_command': 'receive_data',
        #                                        'command_qualifier': 0}},
        #                   {'device_identities': {'source_dev_id': 'uicc',
        #                                          'dest_dev_id': 'channel_1'}},
        #                   {'channel_data_length': 9}
        #                  ]}
        logger.info("ReceiveData")
        logger.info(pcmd)
        # Terminal Response example: [
        #  {'command_details': {'command_number': 1,
        #                       'type_of_command': 'receive_data',
        #                       'command_qualifier': 0}},
        #  {'device_identities': {'source_dev_id': 'terminal', 'dest_dev_id': 'uicc'}},
        #  {'result': {'general_result': 'performed_successfully', 'additional_information': ''}},
        #  {'channel_data': '16030100040e000000'},
        #  {'channel_data_length': 0}
        # ]
        return self.prepare_response(pcmd) + []

    def handle_SendData(self, pcmd: ProactiveCommand):
        """Send/write data received from the SIM to the socket."""
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
        chan_str = dev_id_ie.decoded['dest_dev_id']
        chan_nr = 1 # FIXME
        chan = self.channels.channels.get(chan_nr, None)
        # FIXME chan.prot.transport.write(h2b(chan_data_ie.decoded))
        # Terminal Response example: [
        #  {'command_details': {'command_number': 1,
        #                       'type_of_command': 'send_data',
        #                       'command_qualifier': 1}},
        #  {'device_identities': {'source_dev_id': 'terminal', 'dest_dev_id': 'uicc'}},
        #  {'result': {'general_result': 'performed_successfully', 'additional_information': ''}},
        #  {'channel_data_length': 255}
        # ]
        return self.prepare_response(pcmd) + [ChannelDataLength(decoded=255)]

    def handle_SetUpEventList(self, pcmd: ProactiveCommand):
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



