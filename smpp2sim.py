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

import argparse
import logging
import colorlog
from pprint import pprint as pp

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

from pySim.sms import SMS_DELIVER, AddressField

from pySim.transport import LinkBase, ProactiveHandler, argparse_add_reader_args, init_reader
from pySim.commands import SimCardCommands
from pySim.cards import UsimCard
from pySim.exceptions import *
from pySim.cat import ProactiveCommand, SendShortMessage, SMS_TPDU, SMSPPDownload
from pySim.cat import DeviceIdentities, Address
from pySim.utils import b2h, h2b

logger = logging.getLogger(__name__)

# MSISDNs to use when generating proactive SMS messages
SIM_MSISDN='23'
ESME_MSISDN='12'

# HACK: we need some kind of mapping table between system_id and card-reader
# or actually route based on MSISDNs
hackish_global_smpp = None

class Proact(ProactiveHandler):
    def __init__(self, smpp_factory):
        self.smpp_factory = smpp_factory

    @staticmethod
    def _find_first_element_of_type(instlist, cls):
        for i in instlist:
            if isinstance(i, cls):
                return i
        return None

    """Call-back which the pySim transport core calls whenever it receives a
    proactive command from the SIM."""
    def handle_SendShortMessage(self, data):
        """Card requests sending a SMS."""
        pp(data)
        # Relevant parts in data: Address, SMS_TPDU
        addr_ie = _find_first_element_of_type(data.children, Address)
        sms_tpdu_ie = _find_first_element_of_type(data.children, SMS_TPDU)
        raw_tpdu = sms_tpdu_ie.decoded['tpdu']
        submit = SMS_SUBMIT.fromBytes(raw_tpdu)
        self.send_sms_via_smpp(data)
    def handle_OpenChannel(self, data):
        """Card requests opening a new channel via a UDP/TCP socket."""
        pp(data)
        pass
    def handle_CloseChannel(self, data):
        """Close a channel."""
        pp(data)
        pass
    def handleReceiveData(self, data):
        """Receive/read data from the socket."""
        pp(data)
        pass
    def handleSendData(self, data):
        """Send/write data to the socket."""
        pp(data)
        pass
    def getChannelStatus(self, data):
        pp(data)
        pass

    def send_sms_via_smpp(self, data):
        # while in a normal network the phone/ME would *submit* a message to the SMSC,
        # we are actually emulating the SMSC itself, so we must *deliver* the message
        # to the ESME
        dcs = pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED)
        esm_class = pdu_types.EsmClass(pdu_types.EsmClassMode.DEFAULT, pdu_types.EsmClassType.DEFAULT,
                                       gsmFeatures=[pdu_types.EsmClassGsmFeatures.UDHI_INDICATOR_SET])
        deliver = operations.DeliverSM(source_addr=SIM_MSISDN,
                                       destination_addr=ESME_MSISDN,
                                       esm_class=esm_class,
                                       protocol_id=0x7F,
                                       data_coding=dcs,
                                       short_message=h2b(data))
        hackish_global_smpp.sendDataRequest(deliver)
#       # obtain the connection/binding of system_id to be used for delivering MO-SMS to the ESME
#       connection = smpp_server.getBoundConnections[system_id].getNextBindingForDelivery()
#       connection.sendDataRequest(deliver)



def dcs_is_8bit(dcs):
    if dcs == pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED):
        return True
    if dcs == pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED_COMMON):
        return True
    if dcs.scheme == pdu_types.DataCodingScheme.GSM_MESSAGE_CLASS and dcs.schemeData['msgCoding'] == pdu_types.DataCodingGsmMsgCoding.DATA_8BIT:
        return True
    else:
        return False


class MyServer:

    @implementer(IRealm)
    class SmppRealm:
        def requestAvatar(self, avatarId, mind, *interfaces):
            return ('SMPP', avatarId, lambda: None)

    def __init__(self, tcp_port:int = 2775, bind_ip = '::'):
        smpp_config = SMPPServerConfig(msgHandler=self._msgHandler,
                                       systems={'test': {'max_bindings': 2}})
        portal = Portal(self.SmppRealm())
        credential_checker = InMemoryUsernamePasswordDatabaseDontUse()
        credential_checker.addUser('test', 'test')
        portal.registerChecker(credential_checker)
        self.factory = SMPPServerFactory(smpp_config, auth_portal=portal)
        logger.info('Binding Virtual SMSC to TCP Port %u at %s' % (tcp_port, bind_ip))
        smppEndpoint = endpoints.TCP6ServerEndpoint(reactor, tcp_port, interface=bind_ip)
        smppEndpoint.listen(self.factory)
        self.tp = self.scc = self.card = None

    def connect_to_card(self, tp: LinkBase):
        self.tp = tp
        self.scc = SimCardCommands(self.tp)
        self.card = UsimCard(self.scc)
        # this should be part of UsimCard, but FairewavesSIM breaks with that :/
        self.scc.cla_byte = "00"
        self.scc.sel_ctrl = "0004"
        self.card.read_aids()
        self.card.select_adf_by_aid(adf='usim')
        # FIXME: create a more realistic profile than ffffff
        self.scc.terminal_profile('ffffff')

    def _msgHandler(self, system_id, smpp, pdu):
        # HACK: we need some kind of mapping table between system_id and card-reader
        # or actually route based on MSISDNs
        global hackish_global_smpp
        hackish_global_smpp = smpp
        #pp(pdu)
        if pdu.id == pdu_types.CommandId.submit_sm:
            return self.handle_submit_sm(system_id, smpp, pdu)
        else:
            logging.warning('Rejecting non-SUBMIT commandID')
            return pdu_types.CommandStatus.ESME_RINVCMDID

    def handle_submit_sm(self, system_id, smpp, pdu):
        # check for valid data coding scheme + PID
        if not dcs_is_8bit(pdu.params['data_coding']):
            logging.warning('Rejecting non-8bit DCS')
            return pdu_types.CommandStatus.ESME_RINVDCS
        if pdu.params['protocol_id'] != 0x7f:
            logging.warning('Rejecting non-SIM PID')
            return pdu_types.CommandStatus.ESME_RINVDCS

        # 1) build a SMS-DELIVER (!) from the SMPP-SUBMIT
        tpdu = SMS_DELIVER.fromSmppSubmit(pdu)
        print(tpdu)
        # 2) wrap into the CAT ENVELOPE for SMS-PP-Download
        tpdu_ie = SMS_TPDU(decoded={'tpdu': b2h(tpdu.toBytes())})
        dev_ids = DeviceIdentities(decoded={'source_dev_id': 'network', 'dest_dev_id': 'uicc'})
        sms_dl = SMSPPDownload(children=[dev_ids, tpdu_ie])
        # 3) send to the card
        envelope_hex = b2h(sms_dl.to_tlv())
        print("ENVELOPE: %s" % envelope_hex)
        (data, sw) = self.scc.envelope(envelope_hex)
        print("SW %s: %s" % (sw, data))
        if sw == '9300':
            # TODO send back RP-ERROR message with TP-FCS == 'SIM Application Toolkit Busy'
            return pdu_types.CommandStatus.ESME_RSUBMITFAIL
        elif sw == '9000' or sw[0:2] in ['6f', '62', '63']:
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

if __name__ == '__main__':
    log_format='%(log_color)s%(levelname)-8s%(reset)s %(name)s: %(message)s'
    colorlog.basicConfig(level=logging.INFO, format = log_format)
    logger = colorlog.getLogger()

    opts = option_parser.parse_args()

    #tp = init_reader(opts, proactive_handler = Proact())
    tp = init_reader(opts)
    if tp is None:
        exit(1)
    tp.connect()

    ms = MyServer(opts.smpp_bind_port, opts.smpp_bind_ip)
    ms.connect_to_card(tp)
    reactor.run()

