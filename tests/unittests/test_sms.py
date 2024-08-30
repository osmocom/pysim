#!/usr/bin/env python3

import unittest
from osmocom.utils import h2b, b2h
from pySim.sms import *

class Test_SMS_UDH(unittest.TestCase):
    def test_single_ie(self):
        udh, tail = UserDataHeader.from_bytes('027100')
        self.assertEqual(len(udh.ies), 1)
        ie = udh.ies[0]
        self.assertEqual(ie.iei, 0x71)
        self.assertEqual(ie.length, 0)
        self.assertEqual(ie.value, b'')
        self.assertEqual(tail, b'')

    def test_single_ie_tail(self):
        udh, tail = UserDataHeader.from_bytes('027100abcdef')
        self.assertEqual(len(udh.ies), 1)
        ie = udh.ies[0]
        self.assertEqual(ie.iei, 0x71)
        self.assertEqual(ie.length, 0)
        self.assertEqual(ie.value, b'')
        self.assertEqual(tail, b'\xab\xcd\xef')

    def test_single_ie_value(self):
        udh, tail = UserDataHeader.from_bytes('03710110')
        self.assertEqual(len(udh.ies), 1)
        ie = udh.ies[0]
        self.assertEqual(ie.iei, 0x71)
        self.assertEqual(ie.length, 1)
        self.assertEqual(ie.value, b'\x10')
        self.assertEqual(tail, b'')

    def test_two_ie_data_tail(self):
        udh, tail = UserDataHeader.from_bytes('0571007001ffabcd')
        self.assertEqual(len(udh.ies), 2)
        ie = udh.ies[0]
        self.assertEqual(ie.iei, 0x71)
        self.assertEqual(ie.length, 0)
        self.assertEqual(ie.value, b'')
        ie = udh.ies[1]
        self.assertEqual(ie.iei, 0x70)
        self.assertEqual(ie.length, 1)
        self.assertEqual(ie.value, b'\xff')
        self.assertEqual(tail, b'\xab\xcd')

    def test_to_bytes(self):
        indata = h2b('0571007001ff')
        udh, tail = UserDataHeader.from_bytes(indata)
        encoded = udh.to_bytes()
        self.assertEqual(encoded, indata)

class Test_AddressField(unittest.TestCase):
    def test_from_bytes(self):
        encoded = h2b('0480214399')
        af, trailer = AddressField.from_bytes(encoded)
        self.assertEqual(trailer, b'\x99')
        self.assertEqual(af.ton, 'unknown')
        self.assertEqual(af.npi, 'unknown')
        self.assertEqual(af.digits, '1234')

    def test_from_bytes_odd(self):
        af, trailer = AddressField.from_bytes('038021f399')
        self.assertEqual(trailer, b'\x99')
        self.assertEqual(af.ton, 'unknown')
        self.assertEqual(af.npi, 'unknown')
        self.assertEqual(af.digits, '123')

    def test_to_bytes(self):
        encoded = h2b('04802143')
        af, trailer = AddressField.from_bytes(encoded)
        self.assertEqual(af.to_bytes(), encoded)

    def test_to_bytes_odd(self):
        af = AddressField('12345', 'international', 'isdn_e164')
        encoded = af.to_bytes()
        self.assertEqual(encoded, h2b('05912143f5'))


class Test_SUBMIT(unittest.TestCase):
    def test_from_bytes(self):
        s = SMS_SUBMIT.from_bytes('550d0b911614261771f000f5a78c0b050423f423f40003010201424547494e3a56434152440d0a56455253494f4e3a322e310d0a4e3a4d650d0a54454c3b505245463b43454c4c3b564f4943453a2b36313431363237313137300d0a54454c3b484f4d453b564f4943453a2b36313339353337303437310d0a54454c3b574f524b3b564f4943453a2b36313339363734373031350d0a454e443a')
        self.assertEqual(s.tp_mti, 1)
        self.assertEqual(s.tp_rd, True)
        self.assertEqual(s.tp_vpf, 'relative')
        self.assertEqual(s.tp_rp, False)
        self.assertEqual(s.tp_udhi, True)
        self.assertEqual(s.tp_srr, False)
        self.assertEqual(s.tp_pid, 0)
        self.assertEqual(s.tp_dcs, 0xf5)
        self.assertEqual(s.tp_udl, 140)

class Test_DELIVER(unittest.TestCase):
    def test_from_bytes(self):
        d = SMS_DELIVER.from_bytes('0408D0E5759A0E7FF6907090307513000824010101BB400101')
        self.assertEqual(d.tp_mti, 0)
        self.assertEqual(d.tp_mms, True)
        self.assertEqual(d.tp_lp, False)
        self.assertEqual(d.tp_rp, False)
        self.assertEqual(d.tp_udhi, False)
        self.assertEqual(d.tp_sri, False)
        self.assertEqual(d.tp_pid, 0x7f)
        self.assertEqual(d.tp_dcs, 0xf6)
        self.assertEqual(d.tp_udl, 8)
