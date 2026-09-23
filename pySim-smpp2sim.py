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
import socket
import threading
import time
import colorlog

from twisted.protocols import basic
from twisted.internet import defer, endpoints, reactor, task
from twisted.cred.portal import IRealm
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.portal import Portal
from zope.interface import implementer

from smpp.twisted.config import SMPPServerConfig
from smpp.twisted.server import SMPPServerFactory, SMPPBindManager
from smpp.twisted.protocol import SMPPSessionStates, DataHandlerResponse

from smpp.pdu import pdu_types, operations, pdu_encoding

from pySim.sms import SMS_DELIVER, SMS_SUBMIT, AddressField

from pySim.bip import Proact, terminal_profile
from pySim.transport import LinkBase, ProactiveHandler, argparse_add_reader_args, init_reader, ApduTracer
from pySim.commands import SimCardCommands
from pySim.cards import UiccCardBase
from pySim.exceptions import *
from pySim.cat import sms_pp_download_envelope
from pySim.cat import ProactiveCommand, SendShortMessage, SMS_TPDU, SMSPPDownload, BearerDescription
from pySim.cat import DeviceIdentities, Address, OtherAddress, UiccTransportLevel, BufferSize
from pySim.cat import ChannelStatus, ChannelData, ChannelDataLength
from pySim.cat import EventList, EventDownload, Result
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
        # Serialise card/APDU access.
        # - SMPP handler drives the card from reactor thread
        # - BIP relay data-available path drives it from socket reader thread.
        # The transport is not re-entrant, both must take this lock.
        self._card_lock = threading.Lock()

    def connect_to_card(self, tp: LinkBase):
        self.tp = tp
        self.scc = SimCardCommands(self.tp)
        self.card = UiccCardBase(self.scc)
        # this should be part of UiccCardBase, but FairewavesSIM breaks with that :/
        self.scc.cla_byte = "00"
        self.scc.sel_ctrl = "0004"
        self.card.read_aids()
        self.card.select_adf_by_aid(adf='usim')
        self.scc.terminal_profile(b2h(terminal_profile()))
        # Connect the BIP relay inbound path to the card.
        # relay socket receives data -> ME initiated ENVELOPE EVENT DOWNLOA
        # -> triggers RECEIVE DATA proactive session.
        # FIXME this cross-thread push to the card is exercised only with real hardware
        # the card free tests cover socket relay + envelope construction, not delivery.
        handler = getattr(tp, 'proactive_handler', None)
        if isinstance(handler, Proact):
            handler.data_available_sink = self._deliver_data_available

    def _deliver_data_available(self, envelope_hex: str):
        """push ME initiated ENVELOPE EVENT DOWNLOAD to the card"""
        with self._card_lock:
            logger.info("ENVELOPE(Data available): %s" % envelope_hex)
            (data, sw) = self.scc.envelope(envelope_hex)
            logger.info("SW %s: %s" % (sw, data))

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
        sms_dl = sms_pp_download_envelope(tpdu)
        # 3) send to the card
        envelope_hex = b2h(sms_dl.to_tlv())
        logger.info("ENVELOPE: %s" % envelope_hex)
        with self._card_lock:
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

    tp = init_reader(opts, proactive_handler = Proact(
        sms_sink=lambda pdu: hackish_global_smpp.sendDataRequest(pdu)))
    if tp is None:
        exit(1)
    tp.connect()

    global g_ms
    g_ms = MyServer(opts.smpp_bind_port, opts.smpp_bind_ip, opts.smpp_system_id, opts.smpp_password)
    g_ms.connect_to_card(tp)
    reactor.run()

