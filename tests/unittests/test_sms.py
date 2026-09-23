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


class Test_ConcatenatedSmsReassembler(unittest.TestCase):
    """3GPP TS 23.040 9.2.3.24 reassembly of multi-part SMS.

    An OTA response that exceeds a single SHORT MESSAGE is delivered in several parts using
    the SEND SHORT MESSAGE proactive command. The receiver must recombine the individual
    parts into a single part before decoding."""

    OTA_IE = {'iei': 0x71, 'length': 0, 'value': b''}

    @staticmethod
    def _concat8(ref, tot, seq):
        return {'iei': 0x00, 'length': 3, 'value': bytes([ref, tot, seq])}

    @staticmethod
    def _concat16(ref, tot, seq):
        return {'iei': 0x08, 'length': 4, 'value': ref.to_bytes(2, 'big') + bytes([tot, seq])}

    @staticmethod
    def _part(ies, frag):
        return UserDataHeader(ies).to_bytes() + frag

    def test_ground_truth_udh(self):
        # part 1 UDH observed from sja5: 07 00 03 01 02 01 71 00
        built = self._part([self._concat8(1, 2, 1), self.OTA_IE], b'')
        self.assertEqual(b2h(built), '0700030102017100')

    def test_ground_truth_udh_16bit(self):
        # 9.2.3.24.8: 08 | 08 04 <ref16> <total> <seq> | 71 00
        built = self._part([self._concat16(0x1234, 2, 1), self.OTA_IE], b'')
        self.assertEqual(b2h(built), '080804123402017100')

    def test_single_part_passthrough(self):
        r = ConcatenatedSmsReassembler()
        single = h2b('027100') + bytes(range(20))
        self.assertEqual(r.add(single), single)

    def test_two_part(self):
        # second segment contains only the concat IE, no OTA IE
        pkt = bytes(range(60))
        r = ConcatenatedSmsReassembler()
        self.assertIsNone(r.add(self._part([self._concat8(1, 2, 1), self.OTA_IE], pkt[:35])))
        out = r.add(self._part([self._concat8(1, 2, 2)], pkt[35:]))
        self.assertEqual(out, h2b('027100') + pkt)

    def test_out_of_order(self):
        pkt = bytes(range(60))
        r = ConcatenatedSmsReassembler()
        self.assertIsNone(r.add(self._part([self._concat8(5, 2, 2), self.OTA_IE], pkt[35:])))
        out = r.add(self._part([self._concat8(5, 2, 1), self.OTA_IE], pkt[:35]))
        self.assertEqual(out, h2b('027100') + pkt)

    def test_three_part_out_of_order(self):
        pkt = bytes(range(90))
        r = ConcatenatedSmsReassembler()
        self.assertIsNone(r.add(self._part([self._concat8(7, 3, 3)], pkt[60:])))
        self.assertIsNone(r.add(self._part([self._concat8(7, 3, 1), self.OTA_IE], pkt[:30])))
        out = r.add(self._part([self._concat8(7, 3, 2)], pkt[30:60]))
        self.assertEqual(out, h2b('027100') + pkt)

    def test_16bit_reference(self):
        pkt = bytes(range(40))
        r = ConcatenatedSmsReassembler()
        self.assertIsNone(r.add(self._part([self._concat16(0x1234, 2, 1), self.OTA_IE], pkt[:20])))
        out = r.add(self._part([self._concat16(0x1234, 2, 2)], pkt[20:]))
        self.assertEqual(out, h2b('027100') + pkt)

    def test_interleaved_references(self):
        # two concurrent concatenation sets at the same time
        pkt = bytes(range(60))
        r = ConcatenatedSmsReassembler()
        self.assertIsNone(r.add(self._part([self._concat8(1, 2, 1), self.OTA_IE], pkt[:35])))
        self.assertIsNone(r.add(self._part([self._concat8(9, 2, 1), self.OTA_IE], b'\xaa')))
        self.assertEqual(r.add(self._part([self._concat8(1, 2, 2)], pkt[35:])), h2b('027100') + pkt)
        self.assertEqual(r.add(self._part([self._concat8(9, 2, 2)], b'\xbb')), h2b('027100') + b'\xaa\xbb')

    def test_reserved_concat_ie_is_ignored(self):
        # TS 23.040 9.2.3.24.1:
        # - a total of 0
        # - or a sequence number that is 0 or > total
        # means "the receiving entity shall ignore the whole Information Element"
        # the message is handed back unchanged as a single part msg and not rejected
        # so the caller can handle the problem
        r = ConcatenatedSmsReassembler()
        for tot, seq in [(2, 3),    # seq > total
                         (2, 0),    # seq == 0
                         (0, 1)]:   # total == 0
            with self.subTest(total=tot, seq=seq):
                part = self._part([self._concat8(1, tot, seq)], b'\x00')
                self.assertEqual(r.add(part), part)
        # nothing buffered so later valid set still reassembles properly
        self.assertEqual(r.sets, {})
        pkt = bytes(range(40))
        self.assertIsNone(r.add(self._part([self._concat8(1, 2, 1), self.OTA_IE], pkt[:20])))
        self.assertEqual(r.add(self._part([self._concat8(1, 2, 2)], pkt[20:])), h2b('027100') + pkt)

    def test_inconsistent_totals_do_not_crash(self):
        r = ConcatenatedSmsReassembler()
        self.assertIsNone(r.add(self._part([self._concat8(1, 3, 3)], b'\x33')))
        self.assertIsNone(r.add(self._part([self._concat8(1, 2, 1)], b'\x11')))
        self.assertEqual(r.add(self._part([self._concat8(1, 2, 2)], b'\x22')),
                         h2b('00') + b'\x11\x22')             # complete total=2 set
        self.assertIn((0x00, 1, 3), r.sets)                   # total=3 set still waits

    def test_incomplete_sets_are_capped(self):
        r = ConcatenatedSmsReassembler(max_sets=2)
        for ref in (1, 2, 3):
            self.assertIsNone(r.add(self._part([self._concat8(ref, 2, 1)], bytes([ref]))))
        self.assertEqual(sorted(k[1] for k in r.sets), [2, 3])      # oldest evicted
        self.assertIsNone(r.add(self._part([self._concat8(1, 2, 2)], b'\x11')))
        self.assertEqual(sorted(k[1] for k in r.sets), [1, 3])
        self.assertEqual(r.add(self._part([self._concat8(3, 2, 2)], b'\x33')), h2b('00') + b'\x03\x33')

    def test_same_reference_in_both_ie_forms(self):
        # the refno only unique per IE form (9.2.3.24.1 vs .8) -> two sets
        r = ConcatenatedSmsReassembler()
        self.assertIsNone(r.add(self._part([self._concat8(1, 2, 1)], b'\x0a')))
        self.assertIsNone(r.add(self._part([self._concat16(1, 2, 2)], b'\x1b')))
        self.assertEqual(r.add(self._part([self._concat16(1, 2, 1)], b'\x0b')),
                         h2b('00') + b'\x0b\x1b')
        self.assertEqual(r.add(self._part([self._concat8(1, 2, 2)], b'\x1a')),
                         h2b('00') + b'\x0a\x1a')
