#!/usr/bin/env python3
import logging
import sys
from pprint import pprint as pp

from pySim.ota import OtaKeyset, OtaDialectSms
from pySim.utils import b2h, h2b

import smpplib.gsm
import smpplib.client
import smpplib.consts
import argparse

logger = logging.getLogger(__name__)

# if you want to know what's happening
logging.basicConfig(level='DEBUG')



class Foo:
    def smpp_rx_handler(self, pdu):
        sys.stdout.write('delivered {}\n'.format(pdu.receipted_message_id))
        if pdu.short_message:
            try:
                dec = self.ota_dialect.decode_resp(self.ota_keyset, self.spi, pdu.short_message)
            except ValueError:
                spi = self.spi.copy()
                spi['por_shall_be_ciphered'] = False
                spi['por_rc_cc_ds'] = 'no_rc_cc_ds'
                dec = self.ota_dialect.decode_resp(self.ota_keyset, spi, pdu.short_message)
            pp(dec)
        return None

    def __init__(self, kic, kid, idx, tar):
        # Two parts, UCS2, SMS with UDH
        #parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(u'Привет мир!\n'*10)

        client = smpplib.client.Client('localhost', 2775, allow_unknown_opt_params=True)

        # Print when obtain message_id
        client.set_message_sent_handler(
            lambda pdu: sys.stdout.write('sent {} {}\n'.format(pdu.sequence, pdu.message_id)))
        #client.set_message_received_handler(
        #    lambda pdu: sys.stdout.write('delivered {}\n'.format(pdu.receipted_message_id)))
        client.set_message_received_handler(self.smpp_rx_handler)

        client.connect()
        client.bind_transceiver(system_id='test', password='test')

        self.client = client


        self.ota_keyset = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=idx, kic=h2b(kic),
                                    algo_auth='triple_des_cbc2', kid_idx=idx, kid=h2b(kid))
        self.ota_keyset.cntr = 0xdadb
        self.tar = h2b(tar)

        self.ota_dialect = OtaDialectSms()
        self.spi = {'counter':'no_counter', 'ciphering':True, 'rc_cc_ds': 'cc', 'por_in_submit':False,
                    'por_shall_be_ciphered':True, 'por_rc_cc_ds': 'cc', 'por': 'por_required'}


    def tx_sms_tpdu(self, tpdu: bytes):
        self.client.send_message(
            source_addr_ton=smpplib.consts.SMPP_TON_INTL,
            #source_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
            # Make sure it is a byte string, not unicode:
            source_addr='12',

            dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
            #dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
            # Make sure thease two params are byte strings, not unicode:
            destination_addr='23',
            short_message=tpdu,

            data_coding=smpplib.consts.SMPP_ENCODING_BINARY,
            esm_class=smpplib.consts.SMPP_GSMFEAT_UDHI,
            protocol_id=0x7f,
            #registered_delivery=True,
        )

    def tx_c_apdu(self, apdu: bytes):
        logger.info("C-APDU: %s" % b2h(apdu))
        # translate to Secured OTA RFM
        secured = self.ota_dialect.encode_cmd(self.ota_keyset, self.tar, self.spi, apdu=apdu)
        # add user data header
        tpdu = b'\x02\x70\x00' + secured
        # send via SMPP
        self.tx_sms_tpdu(tpdu)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--kic')
    parser.add_argument('-d', '--kid')
    parser.add_argument('-i', '--idx', type=int, default=1)
    parser.add_argument('-t', '--tar', default='b00011')
    parser.add_argument('apdu', default="", nargs='+')
    args = parser.parse_args()

    f = Foo(args.kic, args.kid, args.idx, args.tar)
    print("initialized, sending APDU")
    f.tx_c_apdu(h2b("".join(args.apdu)))

    f.client.listen()
