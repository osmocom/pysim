#!/usr/bin/env python3
import logging
import sys
from pprint import pprint as pp

from pySim.ota import OtaKeyset, OtaDialectSms
from pySim.utils import b2h, h2b

import smpplib.gsm
import smpplib.client
import smpplib.consts

logger = logging.getLogger(__name__)

# if you want to know what's happening
logging.basicConfig(level='DEBUG')

class Foo:
    def smpp_rx_handler(self, pdu):
        sys.stdout.write('delivered {}\n'.format(pdu.receipted_message_id))
        if pdu.short_message:
            dec = self.ota_dialect.decode_resp(self.ota_keyset, self.spi, pdu.short_message)
            pp(dec)
        return None

    def __init__(self):
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

        if False:
            KIC1 = h2b('000102030405060708090a0b0c0d0e0f')
            KID1 = h2b('101112131415161718191a1b1c1d1e1f')
            self.ota_keyset = OtaKeyset(algo_crypt='aes_cbc', kic_idx=1, kic=KIC1,
                                        algo_auth='aes_cmac', kid_idx=1, kid=KID1)
            self.tar = h2b('000001') # ISD-R according to Annex H of SGP.02
            #self.tar = h2b('000002') # ECASD according to Annex H of SGP.02

        if True:
            KIC1 = h2b('4BE2D58A1FA7233DD723B3C70996E6E6')
            KID1 = h2b('4a664208eba091d32c4ecbc299da1f34')
            self.ota_keyset = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=1, kic=KIC1,
                                        algo_auth='triple_des_cbc2', kid_idx=1, kid=KID1)
            #KIC3 = h2b('A4074D8E1FE69B484A7E62682ED09B51')
            #KID3 = h2b('41FF1033910112DB4EBEBB7807F939CD')
            #self.ota_keyset = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=3, kic=KIC3,
            #                            algo_auth='triple_des_cbc2', kid_idx=3, kid=KID3)
            #self.tar = h2b('B00011') # USIM RFM
            self.tar = h2b('000000') # RAM

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

 
f = Foo()
print("initialized")
#f.tx_c_apdu(h2b('80a40400023f00'))
#f.tx_c_apdu(h2b('80EC010100'))
f.tx_c_apdu(h2b('80EC0101' + '0E' + '350103' + '390203e8' + '3e052101020304'))
f.client.listen()
