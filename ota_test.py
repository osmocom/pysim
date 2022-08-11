#!/usr/bin/python3

from pySim.ota import *
from pySim.sms import SMS_SUBMIT, SMS_DELIVER, AddressField
from pySim.utils import h2b, h2b

# KIC1 + KID1 of 8988211000000515398
#KIC1 = h2b('C039ED58F7B81446105E79EBFD373038')
#KID1 = h2b('1799B93FE53F430BD7FD4810C77E1FDF')
#KIC3 = h2b('167F2576D64C8D41862954875C8D7979')
#KID3 = h2b('ECAE122B0E6AE4186D6487D50FDC0922')

# KIC1 + KID1 of 8988211000000467285
KIC1 = h2b('D0FDA31990D8D64178601317191669B4')
KID1 = h2b('D24EB461799C5E035C77451FD9404463')
KIC3 = h2b('C21DD66ACAC13CB3BC8B331B24AFB57B')
KID3 = h2b('12110C78E678C25408233076AA033615')

od = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=3, kic=KIC3,
               algo_auth='triple_des_cbc2', kid_idx=3, kid=KID3)
print(od.crypt)
print(od.auth)

dialect = OtaDialectSms()

# RAM: B00000
# SIM RFM: B00010
# USIM RFM: B00011
tar = h2b('B00011')

spi = {'counter':'no_counter', 'ciphering':True, 'rc_cc_ds': 'cc', 'por_in_submit':False,
       'por_shall_be_ciphered':True, 'por_rc_cc_ds': 'cc', 'por': 'por_required'}
outp = dialect.encode_cmd(od, tar, spi, apdu=b'\x00\xa4\x00\x04\x02\x3f\x00')
print("result: %s" % b2h(outp))

with_udh = b'\x02\x70\x00' + outp
print("with_udh: %s" % b2h(with_udh))


da = AddressField('12345678', 'unknown', 'isdn_e164')
#tpdu = SMS_SUBMIT(tp_udhi=True, tp_mr=0x23, tp_da=da, tp_pid=0x7F, tp_dcs=0xF6, tp_udl=3, tp_ud=with_udh)
tpdu = SMS_DELIVER(tp_udhi=True, tp_oa=da, tp_pid=0x7F, tp_dcs=0xF6, tp_scts=h2b('22705200000000'), tp_udl=3, tp_ud=with_udh)
print(tpdu)
print("tpdu: %s" % b2h(tpdu.toBytes()))

spi = {'counter':'no_counter', 'ciphering':True, 'rc_cc_ds': 'cc', 'por_in_submit':False,
       'por_shall_be_ciphered':True, 'por_rc_cc_ds': 'cc', 'por': 'por_required'}
dialect.decode_resp(od, spi, '027100001c12b000119660ebdb81be189b5e4389e9e7ab2bc0954f963ad869ed7c')

spi = {'counter':'no_counter', 'ciphering':True, 'rc_cc_ds': 'cc', 'por_in_submit':False,
       'por_shall_be_ciphered':False, 'por_rc_cc_ds': 'cc', 'por': 'por_required'}
dialect.decode_resp(od, spi, '027100001612b000110000000000000055f47118381175fb01612f')

spi = {'counter':'no_counter', 'ciphering':True, 'rc_cc_ds': 'cc', 'por_in_submit':False,
       'por_shall_be_ciphered':False, 'por_rc_cc_ds': 'no_rc_cc_ds', 'por': 'por_required'}
dialect.decode_resp(od, spi, '027100000e0ab000110000000000000001612f')

