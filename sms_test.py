#!/usr/bin/env python3

from pySim.sms import *
from pprint import pprint as pp
from construct import setGlobalPrintPrivateEntries


print(UserDataHeader.fromBytes('027100'))
print(UserDataHeader.fromBytes('027100abcdef'))
print(UserDataHeader.fromBytes('03710110'))
print(UserDataHeader.fromBytes('0571007001ffabcd'))

setGlobalPrintPrivateEntries(True)
pp(AddressField.fromBytes('0480214399'))

s = SMS_SUBMIT.fromBytes('550d0b911614261771f000f5a78c0b050423f423f40003010201424547494e3a56434152440d0a56455253494f4e3a322e310d0a4e3a4d650d0a54454c3b505245463b43454c4c3b564f4943453a2b36313431363237313137300d0a54454c3b484f4d453b564f4943453a2b36313339353337303437310d0a54454c3b574f524b3b564f4943453a2b36313339363734373031350d0a454e443a')
pp(s)
print(s.tp_da)
pp(b2h(s.toBytes()))

d = SMS_DELIVER.fromBytes('0408D0E5759A0E7FF6907090307513000824010101BB400101')
pp(d)
pp(b2h(d.toBytes()))
