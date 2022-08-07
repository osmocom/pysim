#!/usr/bin/env python3
#
# This program receive APDUs via the VPCD protocol of Frank Morgner's
# virtualsmartcard, encrypts them with OTA (over the air) keys and
# forwards them via SMPP to a SMSC (SMS service centre).
#
# In other words, you can use it as a poor man's OTA server, to enable
# you to use unmodified application software with PC/SC support to talk
# securely via OTA with a remote SMS card.
#
# This is very much a work in progress at this point.

#######################################################################
# twisted VPCD Library
#######################################################################

import logging
import struct
import abc
from typing import Union, Optional
from construct import Struct, Int8ub, Int16ub, If, Enum, Bytes, this, len_, Rebuild
from twisted.internet.protocol import Protocol, ReconnectingClientFactory
from pySim.utils import b2h, h2b

logger = logging.getLogger(__name__)

class VirtualCard(abc.ABC):
    """Abstract base class for a virtual smart card."""
    def __init__(self, atr: Union[str, bytes]):
        if isinstance(atr, str):
            atr = h2b(atr)
        self.atr = atr

    @abc.abstractmethod
    def power_change(self, new_state: bool):
        """Power the card on or off."""
        pass

    @abc.abstractmethod
    def reset(self):
        """Reset the card."""
        pass

    @abc.abstractmethod
    def rx_c_apdu(self, apdu: bytes):
        """Receive a C-APDU from the reader/application."""
        pass

    def tx_r_apdu(self, apdu: Union[str, bytes]):
        if isinstance(apdu, str):
            apdu = h2b(apdu)
        logger.info("R-APDU: %s" % b2h(apdu))
        self.protocol.send_data(apdu)

class VpcdProtocolBase(Protocol):
    # Prefixed couldn't be used as the this.length wouldn't be available in this case
    construct = Struct('length'/Rebuild(Int16ub, len_(this.data) + len_(this.ctrl)),
                       'data'/If(this.length > 1, Bytes(this.length)),
                       'ctrl'/If(this.length == 1, Enum(Int8ub, off=0, on=1, reset=2, atr=4)))
    def __init__(self, vcard: VirtualCard):
        self.recvBuffer = b''
        self.connectionCorrupted = False
        self.pduReadTimer = None
        self.pduReadTimerSecs = 10
        self.callLater = reactor.callLater
        self.on = False
        self.vcard = vcard
        self.vcard.protocol = self

    def dataReceived(self, data: bytes):
        """entry point where twisted tells us data was received."""
        #logger.debug('Data received: %s' % b2h(data))
        self.recvBuffer = self.recvBuffer + data
        while True:
            if self.connectionCorrupted:
                return
            msg = self.readMessage()
            if msg is None:
                break
            self.endPDURead()
            self.rawMessageReceived(msg)

        if len(self.recvBuffer) > 0:
            self.incompletePDURead()

    def incompletePDURead(self):
        """We have an incomplete PDU in readBuffer, schedule pduReadTimer"""
        if self.pduReadTimer and self.pduReadTimer.active():
            return
        self.pduReadTimer = self.callLater(self.pduReadTimerSecs, self.onPDUReadTimeout)

    def endPDURead(self):
        """We completed reading a PDU, cancel the pduReadTimer."""
        if self.pduReadTimer and self.pduReadTimer.active():
            self.pduReadTimer.cancel()

    def readMessage(self) -> Optional[bytes]:
        """read an entire [raw] message."""
        pduLen = self._getMessageLength()
        if pduLen is None:
            return None
        return self._getMessage(pduLen)

    def _getMessageLength(self) -> Optional[int]:
        if len(self.recvBuffer) < 2:
            return None
        return struct.unpack('!H', self.recvBuffer[:2])[0]

    def _getMessage(self, pduLen: int) -> Optional[bytes]:
        if len(self.recvBuffer) < pduLen+2:
            return None

        message = self.recvBuffer[:pduLen+2]
        self.recvBuffer = self.recvBuffer[pduLen+2:]
        return message

    def onPDUReadTimeout(self):
        logger.error('PDU read timed out. Buffer is now considered corrupt')
        #self.coruptDataReceived

    def rawMessageReceived(self, message: bytes):
        """Called once a complete binary vpcd message has been received."""
        pdu = None
        try:
            pdu = VpcdProtocolBase.construct.parse(message)
        except Exception as e:
            logger.exception(e)
            logger.critical('Received corrupt PDU %s' % b2h(message))
            #self.corupDataRecvd()
        else:
            self.PDUReceived(pdu)

    def PDUReceived(self, pdu):
        logger.debug("Rx PDU: %s" % pdu)
        if pdu['data']:
            return self.on_rx_data(pdu)
        else:
            method = getattr(self, 'on_rx_' + pdu['ctrl'])
            return method(pdu)

    def on_rx_atr(self, pdu):
        self.send_data(self.vcard.atr)

    def on_rx_on(self, pdu):
        if self.on:
            return
        else:
            self.on = True
            self.vcard.power_change(self.on)

    def on_rx_reset(self, pdu):
        self.vcard.reset()

    def on_rx_off(self, pdu):
        if not self.on:
            return
        else:
            self.on = False
            self.vcard.power_change(self.on)

    def on_rx_data(self, pdu):
        self.vcard.rx_c_apdu(pdu['data'])

    def send_pdu(self, pdu):
        logger.debug("Sending PDU: %s" % pdu)
        encoded = VpcdProtocolBase.construct.build(pdu)
        #logger.debug("Sending binary: %s" % b2h(encoded))
        self.transport.write(encoded)

    def send_data(self, data: Union[str, bytes]):
        if isinstance(data, str):
            data = h2b(data)
        return self.send_pdu({'length': 0, 'ctrl': '', 'data': data})

    def send_ctrl(self, ctrl: str):
        return self.send_pdu({'length': 0, 'ctrl': ctrl, 'data': ''})


class VpcdProtocolClient(VpcdProtocolBase):
    pass


class VpcdClientFactory(ReconnectingClientFactory):
    def __init__(self, vcard_class: VirtualCard):
        self.vcard_class = vcard_class

    def startedConnecting(self, connector):
        logger.debug('Started to connect')

    def buildProtocol(self, addr):
        logger.info('Connection established to %s' % addr)
        self.resetDelay()
        return VpcdProtocolClient(vcard = self.vcard_class())

    def clientConnectionLost(self, connector, reason):
        logger.warning('Connection lost (reason: %s)' % reason)
        super().clientConnectionLost(connector, reason)

    def clientConnectionFailed(self, connector, reason):
        logger.warning('Connection failed (reason: %s)' % reason)
        super().clientConnectionFailed(connector, reason)

#######################################################################
# Application
#######################################################################

from pprint import pprint as pp

from twisted.internet.protocol import Protocol, ReconnectingClientFactory, ClientCreator
from twisted.internet import reactor

from smpp.twisted.client import SMPPClientTransceiver, SMPPClientService
from smpp.twisted.protocol import SMPPClientProtocol
from smpp.twisted.config import SMPPClientConfig
from smpp.pdu.operations import SubmitSM, DeliverSM
from smpp.pdu import pdu_types

from pySim.ota import OtaKeyset, OtaDialectSms
from pySim.utils import b2h, h2b


class MyVcard(VirtualCard):
    def __init__(self, **kwargs):
        super().__init__(atr='3B9F96801FC78031A073BE21136743200718000001A5', **kwargs)
        self.smpp_client = None
        # KIC1 + KID1 of 8988211000000467285
        KIC1 = h2b('D0FDA31990D8D64178601317191669B4')
        KID1 = h2b('D24EB461799C5E035C77451FD9404463')
        KIC3 = h2b('C21DD66ACAC13CB3BC8B331B24AFB57B')
        KID3 = h2b('12110C78E678C25408233076AA033615')
        self.ota_keyset = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=3, kic=KIC3,
                                    algo_auth='triple_des_cbc2', kid_idx=3, kid=KID3)
        self.ota_dialect = OtaDialectSms()
        self.tar = h2b('B00011')
        self.spi = {'counter':'no_counter', 'ciphering':True, 'rc_cc_ds': 'cc', 'por_in_submit':False,
                    'por_shall_be_ciphered':True, 'por_rc_cc_ds': 'cc', 'por': 'por_required'}

    def ensure_smpp(self):
        config = SMPPClientConfig(host='localhost', port=2775, username='test', password='test')
        if self.smpp_client:
            return
        self.smpp_client = SMPPClientTransceiver(config, self.handleSmpp)
        smpp = self.smpp_client.connectAndBind()
        #self.smpp = ClientCreator(reactor, SMPPClientProtocol, config, self.handleSmpp)
        #d = self.smpp.connectTCP(config.host, config.port)
        #d = self.smpp.connectAndBind()
        #d.addCallback(self.forwardToClient, self.smpp)

    def power_change(self, new_state: bool):
        if new_state:
            logger.info("POWER ON")
            self.ensure_smpp()
        else:
            logger.info("POWER OFF")

    def reset(self):
        logger.info("RESET")

    def rx_c_apdu(self, apdu: bytes):
        pp(self.smpp_client.smpp)
        logger.info("C-APDU: %s" % b2h(apdu))
        # translate to Secured OTA RFM
        secured = self.ota_dialect.encode_cmd(self.ota_keyset, self.tar, self.spi, apdu=apdu)
        # add user data header
        tpdu = b'\x02\x70\x00' + secured
        # send via SMPP
        self.tx_sms_tpdu(tpdu)
        #self.tx_r_apdu('9000')

    def tx_sms_tpdu(self, tpdu: bytes):
        """Send a SMS TPDU via SMPP SubmitSM."""
        dcs = pdu_types.DataCoding(pdu_types.DataCodingScheme.DEFAULT,
                                   pdu_types.DataCodingDefault.OCTET_UNSPECIFIED)
        esm_class = pdu_types.EsmClass(pdu_types.EsmClassMode.DEFAULT, pdu_types.EsmClassType.DEFAULT,
                                       gsmFeatures=[pdu_types.EsmClassGsmFeatures.UDHI_INDICATOR_SET])
        submit = SubmitSM(source_addr='12',destination_addr='23', data_coding=dcs, esm_class=esm_class,
                          protocol_id=0x7f, short_message=tpdu)
        self.smpp_client.smpp.sendDataRequest(submit)

    def handleSmpp(self, smpp, pdu):
        #logger.info("Received SMPP %s" % pdu)
        data = pdu.params['short_message']
        #logger.info("Received SMS Data %s" % b2h(data))
        r, d = self.ota_dialect.decode_resp(self.ota_keyset, self.spi, data)
        logger.info("Decoded SMPP %s" % r)
        self.tx_r_apdu(r['last_response_data'] + r['last_status_word'])


if __name__ == '__main__':
    import logging
    logger = logging.getLogger(__name__)
    import colorlog
    log_format='%(log_color)s%(levelname)-8s%(reset)s %(name)s: %(message)s'
    colorlog.basicConfig(level=logging.INFO, format = log_format)
    logger = colorlog.getLogger()

    from twisted.internet import reactor
    host = 'localhost'
    port = 35963
    reactor.connectTCP(host, port, VpcdClientFactory(vcard_class=MyVcard))
    reactor.run()
