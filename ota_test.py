#!/usr/bin/python3

from pySim.ota import *
from pySim.sms import SMS_SUBMIT, SMS_DELIVER, AddressField
from pySim.utils import h2b, h2b

# pre-defined SPI values for use in test cases below
SPI_CC_POR_CIPHERED_CC = {
    'counter':'no_counter',
    'ciphering':True,
    'rc_cc_ds': 'cc',
    'por_in_submit':False,
    'por_shall_be_ciphered':True,
    'por_rc_cc_ds': 'cc',
    'por': 'por_required'
    }

SPI_CC_POR_UNCIPHERED_CC = {
    'counter':'no_counter',
    'ciphering':True,
    'rc_cc_ds': 'cc',
    'por_in_submit':False,
    'por_shall_be_ciphered':False,
    'por_rc_cc_ds': 'cc',
    'por': 'por_required'
}

SPI_CC_POR_UNCIPHERED_NOCC = {
    'counter':'no_counter',
    'ciphering':True,
    'rc_cc_ds': 'cc',
    'por_in_submit':False,
    'por_shall_be_ciphered':False,
    'por_rc_cc_ds': 'no_rc_cc_ds',
    'por': 'por_required'
}

# SJA5 SAMPLE cards provisioned by execute_ipr.py
OTA_KEYSET_SJA5_SAMPLES = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=3,
                                    algo_auth='triple_des_cbc2', kid_idx=3,
                                    kic=h2b('300102030405060708090a0b0c0d0e0f'),
                                    kid=h2b('301102030405060708090a0b0c0d0e0f'))

OTA_KEYSET_SJA5_AES128 = OtaKeyset(algo_crypt='aes_cbc', kic_idx=2,
                                   algo_auth='aes_cmac', kid_idx=2,
                                   kic=h2b('200102030405060708090a0b0c0d0e0f'),
                                   kid=h2b('201102030405060708090a0b0c0d0e0f'))

# TODO: AES192
# TODO: AES256

testcases = [
        {
            'name': '3DES-SJA5-CIPHERED-CC',
            'ota_keyset': OTA_KEYSET_SJA5_SAMPLES,
            'spi': SPI_CC_POR_CIPHERED_CC,
            'request': {
                'apdu': b'\x00\xa4\x00\x04\x02\x3f\x00',
                'encoded_cmd': '00201506193535b00011ae733256918d050b87c94fbfe12e4dc402f262c41cf67f2f',
                'encoded_tpdu': '400881214365877ff6227052000000000302700000201506193535b00011ae733256918d050b87c94fbfe12e4dc402f262c41cf67f2f',
                },
            'response': {
                'encoded_resp': '027100001c12b000118bb989492c632529326a2f4681feb37c825bc9021c9f6d0b',
                }
        }, {
            'name': '3DES-SJA5-UNCIPHERED-CC',
            'ota_keyset': OTA_KEYSET_SJA5_SAMPLES,
            'spi': SPI_CC_POR_UNCIPHERED_CC,
            'request': {
                'apdu': b'\x00\xa4\x00\x04\x02\x3f\x00',
                'encoded_cmd': '00201506093535b00011c49ac91ab8159ba5b83a54fb6385e0a5e31694f8b215fafc',
                'encoded_tpdu': '400881214365877ff6227052000000000302700000201506093535b00011c49ac91ab8159ba5b83a54fb6385e0a5e31694f8b215fafc',
                },
            'response': {
                'encoded_resp': '027100001612b0001100000000000000b5bcd6353a421fae016132',
                }
        }, {
            'name': '3DES-SJA5-UNCIPHERED-NOCC',
            'ota_keyset': OTA_KEYSET_SJA5_SAMPLES,
            'spi': SPI_CC_POR_UNCIPHERED_NOCC,
            'request': {
                'apdu': b'\x00\xa4\x00\x04\x02\x3f\x00',
                'encoded_cmd': '00201506013535b000113190be334900f52b025f3f7eddfe868e96ebf310023b7769',
                'encoded_tpdu': '400881214365877ff6227052000000000302700000201506013535b000113190be334900f52b025f3f7eddfe868e96ebf310023b7769',
                },
            'response': {
                'encoded_resp': '027100000e0ab0001100000000000000016132',
                }
        }, {
            'name': 'AES128-SJA5-CIPHERED-CC',
            'ota_keyset': OTA_KEYSET_SJA5_AES128,
            'spi': SPI_CC_POR_CIPHERED_CC,
            'request': {
                'apdu': b'\x00\xa4\x00\x04\x02\x3f\x00',
                'encoded_cmd': '00281506192222b00011e87cceebb2d93083011ce294f93fc4d8de80da1abae8c37ca3e72ec4432e5058',
                'encoded_tpdu': '400881214365877ff6227052000000000302700000281506192222b00011e87cceebb2d93083011ce294f93fc4d8de80da1abae8c37ca3e72ec4432e5058',
                },
            'response': {
                'encoded_resp': '027100002412b00011ebc6b497e2cad7aedf36ace0e3a29b38853f0fe9ccde81913be5702b73abce1f',
                }
        }
    ]

for t in testcases:
    print()
    print("==== TESTCASE: %s" % t['name'])
    od = t['ota_keyset']

    # RAM: B00000
    # SIM RFM: B00010
    # USIM RFM: B00011
    tar = h2b('B00011')

    dialect = OtaDialectSms()
    outp = dialect.encode_cmd(od, tar, t['spi'], apdu=t['request']['apdu'])
    print("result: %s" % b2h(outp))
    assert(b2h(outp) == t['request']['encoded_cmd'])

    with_udh = b'\x02\x70\x00' + outp
    print("with_udh: %s" % b2h(with_udh))


    # processing of the response from the card
    da = AddressField('12345678', 'unknown', 'isdn_e164')
    #tpdu = SMS_SUBMIT(tp_udhi=True, tp_mr=0x23, tp_da=da, tp_pid=0x7F, tp_dcs=0xF6, tp_udl=3, tp_ud=with_udh)
    tpdu = SMS_DELIVER(tp_udhi=True, tp_oa=da, tp_pid=0x7F, tp_dcs=0xF6, tp_scts=h2b('22705200000000'), tp_udl=3, tp_ud=with_udh)
    print("TPDU: %s" % tpdu)
    print("tpdu: %s" % b2h(tpdu.to_bytes()))
    assert(b2h(tpdu.to_bytes()) == t['request']['encoded_tpdu'])

    r = dialect.decode_resp(od, t['spi'], t['response']['encoded_resp'])
    print("RESP: ", r)
