#!/usr/bin/env python3
#
# Program to emulate the entire communication path SMSC-MSC-BSC-BTS-ME
# that is usually between an OTA backend and the SIM card.  This allows
# to play with SIM OTA technology without using a mobile network or even
# a mobile phone.
#
# An external application must encode (and encrypt/sign) the OTA SMS
# and submit them via SMPP to this program, just like it would submit
# it normally to a SMSC (SMS Service Centre).  The program then re-formats
# the SMPP-SUBMIT into a SMS DELIVER TPDU and passes it via an ENVELOPE
# APDU to the SIM card that is locally inserted into a smart card reader.
#
# The path from SIM to external OTA application works the opposite way.

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

import argparse
import logging
import colorlog

from twisted.protocols import basic
from twisted.internet import defer, endpoints, protocol, reactor, task
from twisted.cred.portal import IRealm
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.portal import Portal
from zope.interface import implementer

from smpp.twisted.config import SMPPServerConfig
from smpp.twisted.server import SMPPServerFactory, SMPPBindManager
from smpp.twisted.protocol import SMPPSessionStates, DataHandlerResponse

from smpp.pdu import pdu_types, operations, pdu_encoding

from pySim.sms import SMS_DELIVER, SMS_SUBMIT, AddressField

from pySim.transport import LinkBase, ProactiveHandler, argparse_add_reader_args, init_reader, ApduTracer
from pySim.commands import SimCardCommands
from pySim.cards import UiccCardBase
from pySim.exceptions import *
from pySim.cat import ProactiveCommand, SendShortMessage, SMS_TPDU, SMSPPDownload, BearerDescription
from pySim.cat import DeviceIdentities, Address, OtherAddress, UiccTransportLevel, BufferSize
from pySim.cat import ChannelStatus, ChannelData, ChannelDataLength
from pySim.utils import b2h, h2b

logger = logging.getLogger(__name__)

# MSISDNs to use when generating proactive SMS messages
SIM_MSISDN='23'
ESME_MSISDN='12'

# HACK: we need some kind of mapping table between system_id and card-reader
# or actually route based on MSISDNs
hackish_global_smpp = None

class MyApduTracer(ApduTracer):
    def trace_response(self, cmd, sw, resp):
        print("-> %s %s" % (cmd[:10], cmd[10:]))
        print("<- %s: %s" % (sw, resp))

class TcpProtocol(protocol.Protocol):
    def dataReceived(self, data):
        pass

    def connectionLost(self, reason):
        pass


def tcp_connected_callback(p: protocol.Protocol):
    """called by twisted TCP client."""
    logger.error("%s: connected!" % p)

class ProactChannel:
    """Representation of a single proective channel."""
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
    def __init__(self):
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

        hackish_global_smpp.sendDataRequest(deliver_smpp)
#       # obtain the connection/binding of system_id to be used for delivering MO-SMS to the ESME
#       connection = smpp_server.getBoundConnections[system_id].getNextBindingForDelivery()
#       connection.sendDataRequest(deliver_smpp)



def dcs_is_8bit(dcs):
    if dcs == pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED):
        return True
    if dcs == pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED_COMMON):
        return True
    # pySim-smpp2sim.py:150:21: E1101: Instance of 'DataCodingScheme' has no 'GSM_MESSAGE_CLASS' member (no-member)
    # pylint: disable=no-member
    if dcs.scheme == pdu_types.DataCodingScheme.GSM_MESSAGE_CLASS and dcs.schemeData['msgCoding'] == pdu_types.DataCodingGsmMsgCoding.DATA_8BIT:
        return True
    else:
        return False


class MyServer:

    @implementer(IRealm)
    class SmppRealm:
        def requestAvatar(self, avatarId, mind, *interfaces):
            return ('SMPP', avatarId, lambda: None)

    def __init__(self, tcp_port:int = 2775, bind_ip = '::', system_id:str = 'test', password:str = 'test'):
        smpp_config = SMPPServerConfig(msgHandler=self._msgHandler,
                                       systems={system_id: {'max_bindings': 2}})
        portal = Portal(self.SmppRealm())
        credential_checker = InMemoryUsernamePasswordDatabaseDontUse()
        credential_checker.addUser(system_id, password)
        portal.registerChecker(credential_checker)
        self.factory = SMPPServerFactory(smpp_config, auth_portal=portal)
        logger.info('Binding Virtual SMSC to TCP Port %u at %s' % (tcp_port, bind_ip))
        smppEndpoint = endpoints.TCP6ServerEndpoint(reactor, tcp_port, interface=bind_ip)
        smppEndpoint.listen(self.factory)
        self.tp = self.scc = self.card = None

    def connect_to_card(self, tp: LinkBase):
        self.tp = tp
        self.scc = SimCardCommands(self.tp)
        self.card = UiccCardBase(self.scc)
        # this should be part of UiccCardBase, but FairewavesSIM breaks with that :/
        self.scc.cla_byte = "00"
        self.scc.sel_ctrl = "0004"
        self.card.read_aids()
        self.card.select_adf_by_aid(adf='usim')
        # FIXME: create a more realistic profile than ffffff
        self.scc.terminal_profile('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

    def _msgHandler(self, system_id, smpp, pdu):
        """Handler for incoming messages received via SMPP from ESME."""
        # HACK: we need some kind of mapping table between system_id and card-reader
        # or actually route based on MSISDNs
        global hackish_global_smpp
        hackish_global_smpp = smpp
        if pdu.id == pdu_types.CommandId.submit_sm:
            return self.handle_submit_sm(system_id, smpp, pdu)
        else:
            logger.warning('Rejecting non-SUBMIT commandID')
            return pdu_types.CommandStatus.ESME_RINVCMDID

    def handle_submit_sm(self, system_id, smpp, pdu):
        """SUBMIT-SM was received via SMPP from ESME. We need to deliver it to the SIM."""
        # check for valid data coding scheme + PID
        if not dcs_is_8bit(pdu.params['data_coding']):
            logger.warning('Rejecting non-8bit DCS')
            return pdu_types.CommandStatus.ESME_RINVDCS
        if pdu.params['protocol_id'] != 0x7f:
            logger.warning('Rejecting non-SIM PID')
            return pdu_types.CommandStatus.ESME_RINVDCS

        # 1) build a SMS-DELIVER (!) from the SMPP-SUBMIT
        tpdu = SMS_DELIVER.from_smpp_submit(pdu)
        logger.info(tpdu)
        # 2) wrap into the CAT ENVELOPE for SMS-PP-Download
        tpdu_ie = SMS_TPDU(decoded={'tpdu': b2h(tpdu.to_bytes())})
        addr_ie = Address(decoded={'ton_npi': {'ext':False, 'type_of_number':'unknown', 'numbering_plan_id':'unknown'}, 'call_number': '0123456'})
        dev_ids = DeviceIdentities(decoded={'source_dev_id': 'network', 'dest_dev_id': 'uicc'})
        sms_dl = SMSPPDownload(children=[dev_ids, addr_ie, tpdu_ie])
        # 3) send to the card
        envelope_hex = b2h(sms_dl.to_tlv())
        logger.info("ENVELOPE: %s" % envelope_hex)
        (data, sw) = self.scc.envelope(envelope_hex)
        logger.info("SW %s: %s" % (sw, data))
        if sw in ['9200', '9300']:
            # TODO send back RP-ERROR message with TP-FCS == 'SIM Application Toolkit Busy'
            return pdu_types.CommandStatus.ESME_RSUBMITFAIL
        elif sw == '9000' or sw[0:2] in ['6f', '62', '63'] and len(data):
            # data something like 027100000e0ab000110000000000000001612f or
            # 027100001c12b000119660ebdb81be189b5e4389e9e7ab2bc0954f963ad869ed7c
            # which is the user-data portion of the SMS starting with the UDH (027100)
            # TODO: return the response back to the sender in an RP-ACK; PID/DCS like in CMD
            deliver = operations.DeliverSM(service_type=pdu.params['service_type'],
                                           source_addr_ton=pdu.params['dest_addr_ton'],
                                           source_addr_npi=pdu.params['dest_addr_npi'],
                                           source_addr=pdu.params['destination_addr'],
                                           dest_addr_ton=pdu.params['source_addr_ton'],
                                           dest_addr_npi=pdu.params['source_addr_npi'],
                                           destination_addr=pdu.params['source_addr'],
                                           esm_class=pdu.params['esm_class'],
                                           protocol_id=pdu.params['protocol_id'],
                                           priority_flag=pdu.params['priority_flag'],
                                           data_coding=pdu.params['data_coding'],
                                           short_message=h2b(data))
            smpp.sendDataRequest(deliver)
            return pdu_types.CommandStatus.ESME_ROK
        else:
            return pdu_types.CommandStatus.ESME_RSUBMITFAIL


option_parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
argparse_add_reader_args(option_parser)
smpp_group = option_parser.add_argument_group('SMPP Options')
smpp_group.add_argument('--smpp-bind-port', type=int, default=2775,
                        help='TCP Port to bind the SMPP socket to')
smpp_group.add_argument('--smpp-bind-ip', default='::',
                        help='IPv4/IPv6 address to bind the SMPP socket to')
smpp_group.add_argument('--smpp-system-id', default='test',
                        help='SMPP System-ID used by ESME to bind')
smpp_group.add_argument('--smpp-password', default='test',
                        help='SMPP Password used by ESME to bind')

if __name__ == '__main__':
    log_format='%(log_color)s%(levelname)-8s%(reset)s %(name)s: %(message)s'
    colorlog.basicConfig(level=logging.INFO, format = log_format)
    logger = colorlog.getLogger()

    opts = option_parser.parse_args()

    tp = init_reader(opts, proactive_handler = Proact())
    if tp is None:
        exit(1)
    tp.connect()

    global g_ms
    g_ms = MyServer(opts.smpp_bind_port, opts.smpp_bind_ip, opts.smpp_system_id, opts.smpp_password)
    g_ms.connect_to_card(tp)
    reactor.run()

