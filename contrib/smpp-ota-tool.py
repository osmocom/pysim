#!/usr/bin/env python3

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Harald Welte, Philipp Maier
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
import smpplib.gsm
import smpplib.client
import smpplib.consts
import time
from pySim.ota import OtaKeyset, OtaDialectSms, OtaAlgoCrypt, OtaAlgoAuth, CNTR_REQ, RC_CC_DS, POR_REQ
from pySim.utils import b2h, h2b, is_hexstr
from pathlib import Path

logger = logging.getLogger(Path(__file__).stem)

class SmppHandler:
    client = None

    def __init__(self, host: str, port: int,
                 system_id: str, password: str,
                 ota_keyset: OtaKeyset, spi: dict, tar: bytes):
        """
        Initialize connection to SMPP server and set static OTA SMS-TPDU ciphering parameters
        Args:
                host : Hostname or IPv4/IPv6 address of the SMPP server
                port : TCP Port of the SMPP server
                system_id: SMPP System-ID used by ESME (client) to bind
                password: SMPP Password used by ESME (client) to bind
                ota_keyset: OTA keyset to be used for SMS-TPDU ciphering
                spi: Security Parameter Indicator (SPI) to be used for SMS-TPDU ciphering
                tar: Toolkit Application Reference (TAR) of the targeted card application
        """

        # Create and connect SMPP client
        client = smpplib.client.Client(host, port, allow_unknown_opt_params=True)
        client.set_message_sent_handler(self.message_sent_handler)
        client.set_message_received_handler(self.message_received_handler)
        client.connect()
        client.bind_transceiver(system_id=system_id, password=password)
        self.client = client

        # Setup static OTA parameters
        self.ota_dialect = OtaDialectSms()
        self.ota_keyset = ota_keyset
        self.tar = tar
        self.spi = spi

    def __del__(self):
        if self.client:
            self.client.unbind()
            self.client.disconnect()

    def message_received_handler(self, pdu):
        if pdu.short_message:
            logger.info("SMS-TPDU received: %s", b2h(pdu.short_message))
            try:
                dec = self.ota_dialect.decode_resp(self.ota_keyset, self.spi, pdu.short_message)
            except ValueError:
                # Retry to decoding with ciphering disabled (in case the card has problems to decode the SMS-TDPU
                # we have sent, the response will contain an unencrypted error message)
                spi = self.spi.copy()
                spi['por_shall_be_ciphered'] = False
                spi['por_rc_cc_ds'] = 'no_rc_cc_ds'
                dec = self.ota_dialect.decode_resp(self.ota_keyset, spi, pdu.short_message)
            logger.info("SMS-TPDU decoded: %s", dec)
            self.response = dec
        return None

    def message_sent_handler(self, pdu):
            logger.debug("SMS-TPDU sent: pdu_sequence=%s pdu_message_id=%s", pdu.sequence, pdu.message_id)

    def transceive_sms_tpdu(self, tpdu: bytes, src_addr: str, dest_addr: str, timeout: int) -> tuple:
        """
        Transceive SMS-TPDU. This method sends the SMS-TPDU to the SMPP server, and waits for a response. The method
        returns when the response is received.

        Args:
                tpdu : short message content (plaintext)
                src_addr : short message source address
                dest_addr : short message destination address
                timeout : timeout after which this method should give up waiting for a response
        Returns:
                tuple containing the response (plaintext)
        """

        logger.info("SMS-TPDU sending: %s...", b2h(tpdu))

        self.client.send_message(
            # TODO: add parameters to switch source_addr_ton and dest_addr_ton between SMPP_TON_INTL and SMPP_NPI_ISDN
            source_addr_ton=smpplib.consts.SMPP_TON_INTL,
            source_addr=src_addr,
            dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
            destination_addr=dest_addr,
            short_message=tpdu,
            # TODO: add parameters to set data_coding and esm_class
            data_coding=smpplib.consts.SMPP_ENCODING_BINARY,
            esm_class=smpplib.consts.SMPP_GSMFEAT_UDHI,
            protocol_id=0x7f,
            # TODO: add parameter to use registered delivery
            # registered_delivery=True,
        )

        logger.info("SMS-TPDU sent, waiting for response...")
        timestamp_sent=int(time.time())
        self.response = None
        while self.response is None:
            self.client.poll()
            if int(time.time()) - timestamp_sent > timeout:
                raise ValueError("Timeout reached, no response SMS-TPDU received!")
        return self.response

    def transceive_apdu(self, apdu: bytes, src_addr: str, dest_addr: str, timeout: int) -> tuple[bytes, bytes]:
        """
        Transceive APDU. This method wraps the given APDU into an SMS-TPDU, sends it to the SMPP server and waits for
        the response. When the response is received, the last response data and the last status word is extracted from
        the response and returned to the caller.

        Args:
                apdu : one or more concatenated APDUs
                src_addr : short message source address
                dest_addr : short message destination address
                timeout : timeout after which this method should give up waiting for a response
        Returns:
                tuple containing the last response data and the last status word as byte strings
        """

        logger.info("C-APDU sending: %s..." % b2h(apdu))

        # translate to Secured OTA RFM
        secured = self.ota_dialect.encode_cmd(self.ota_keyset, self.tar, self.spi, apdu=apdu)
        # add user data header
        tpdu = b'\x02\x70\x00' + secured
        # send via SMPP
        response =  self.transceive_sms_tpdu(tpdu, src_addr, dest_addr, timeout)

        # Extract last_response_data and last_status_word from the response
        sw = None
        resp = None
        for container in response:
            if container:
                container_dict = dict(container)
                resp = container_dict.get('last_response_data')
                sw = container_dict.get('last_status_word')
        if resp is None:
            raise ValueError("Response does not contain any last_response_data, no R-APDU received!")
        if sw is None:
            raise ValueError("Response does not contain any last_status_word, no R-APDU received!")

        logger.info("R-APDU received: %s %s", resp, sw)
        return h2b(resp), h2b(sw)

if __name__ == '__main__':
    option_parser = argparse.ArgumentParser(description='CSV importer for pySim-shell\'s PostgreSQL Card Key Provider',
                                   formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    option_parser.add_argument("--host", help="Host/IP of the SMPP server", default="localhost")
    option_parser.add_argument("--port", help="TCP port of the SMPP server", default=2775, type=int)
    option_parser.add_argument("--system-id", help="System ID to use to bind to the SMPP server", default="test")
    option_parser.add_argument("--password", help="Password to use to bind to the SMPP server", default="test")
    option_parser.add_argument("--verbose", help="Enable verbose logging", action='store_true', default=False)
    algo_crypt_choices = []
    algo_crypt_classes = OtaAlgoCrypt.__subclasses__()
    for cls in algo_crypt_classes:
        algo_crypt_choices.append(cls.enum_name)
    option_parser.add_argument("--algo-crypt", choices=algo_crypt_choices, default='triple_des_cbc2',
                               help="OTA crypt algorithm")
    algo_auth_choices = []
    algo_auth_classes = OtaAlgoAuth.__subclasses__()
    for cls in algo_auth_classes:
        algo_auth_choices.append(cls.enum_name)
    option_parser.add_argument("--algo-auth", choices=algo_auth_choices, default='triple_des_cbc2',
                               help="OTA auth algorithm")
    option_parser.add_argument('--kic', required=True, type=is_hexstr, help='OTA key (KIC)')
    option_parser.add_argument('--kic_idx', default=1, type=int, help='OTA key index (KIC)')
    option_parser.add_argument('--kid', required=True, type=is_hexstr, help='OTA key (KID)')
    option_parser.add_argument('--kid_idx', default=1, type=int, help='OTA key index (KID)')
    option_parser.add_argument('--cntr', default=0, type=int, help='replay protection counter')
    option_parser.add_argument('--tar', required=True, type=is_hexstr, help='Toolkit Application Reference')
    option_parser.add_argument("--cntr_req", choices=CNTR_REQ.decmapping.values(), default='no_counter',
                               help="Counter requirement")
    option_parser.add_argument('--ciphering', default=True, type=bool, help='Enable ciphering')
    option_parser.add_argument("--rc-cc-ds", choices=RC_CC_DS.decmapping.values(), default='cc',
                               help="message check (rc=redundency check, cc=crypt. checksum, ds=digital signature)")
    option_parser.add_argument('--por-in-submit', default=False, type=bool,
                               help='require PoR to be sent via SMS-SUBMIT')
    option_parser.add_argument('--por-shall-be-ciphered', default=True, type=bool, help='require encrypted PoR')
    option_parser.add_argument("--por-rc-cc-ds", choices=RC_CC_DS.decmapping.values(), default='cc',
                               help="PoR check (rc=redundency check, cc=crypt. checksum, ds=digital signature)")
    option_parser.add_argument("--por_req", choices=POR_REQ.decmapping.values(), default='por_required',
                               help="Proof of Receipt requirements")
    option_parser.add_argument('--src-addr', default='12', type=str, help='TODO')
    option_parser.add_argument('--dest-addr', default='23', type=str, help='TODO')
    option_parser.add_argument('--timeout', default=10, type=int, help='TODO')
    option_parser.add_argument('-a', '--apdu', action='append', required=True, type=is_hexstr, help='C-APDU to send')
    opts = option_parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if opts.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    ota_keyset = OtaKeyset(algo_crypt=opts.algo_crypt,
                           kic_idx=opts.kic_idx,
                           kic=h2b(opts.kic),
                           algo_auth=opts.algo_auth,
                           kid_idx=opts.kic_idx,
                           kid=h2b(opts.kid),
                           cntr=opts.cntr)
    spi = {'counter' : opts.cntr_req,
           'ciphering' : opts.ciphering,
           'rc_cc_ds': opts.rc_cc_ds,
           'por_in_submit':opts.por_in_submit,
           'por_shall_be_ciphered':opts.por_shall_be_ciphered,
           'por_rc_cc_ds': opts.por_rc_cc_ds,
           'por': opts.por_req}
    apdu = h2b("".join(opts.apdu))

    smpp_handler = SmppHandler(opts.host, opts.port, opts.system_id, opts.password, ota_keyset, spi, h2b(opts.tar))
    resp, sw = smpp_handler.transceive_apdu(apdu, opts.src_addr, opts.dest_addr, opts.timeout)
    print("%s %s" % (b2h(resp), b2h(sw)))
