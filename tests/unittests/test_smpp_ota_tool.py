#!/usr/bin/env python3
""" test for smpp-ota-tool SMS handling, specifically the multi part sms OTA response"""

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Eric Wild <ewild@sysmocom.de>
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

import os.path
import importlib.util
import unittest

from osmocom.utils import h2b, b2h

from pySim.ota import OtaKeyset, OtaDialectSms, ExpandedRemoteResp
from pySim.sms import ConcatenatedSmsReassembler, UserDataHeader

# import the hyphenated contrib script as a module to get at SmppHandler
# why do people name python files like that? why does everything have to be so hard?
_TOOL_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'contrib', 'smpp-ota-tool.py')
_spec = importlib.util.spec_from_file_location('smpp_ota_tool', _TOOL_PATH)
smpp_ota_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smpp_ota_tool)
SmppHandler = smpp_ota_tool.SmppHandler


class _FakePdu:
    """Minimal mock for smpplib deliver_sm pdu."""
    def __init__(self, short_message):
        self.short_message = short_message


class MultipartRelayTestCase(unittest.TestCase):
    """message_received_handler must return the reassembled application
    response and survive POR messages."""

    # 3DES test keyset from tests/unittests/test_ota.py) used to make the
    # handler happy. responses are plaintext, tests do not depend on keys.
    def _handler(self, remote_format='expanded'):
        h = object.__new__(SmppHandler)
        h.client = None
        h.ota_dialect = OtaDialectSms()
        h.ota_keyset = OtaKeyset(algo_crypt='triple_des_cbc2', kic_idx=3,
                                 kic=h2b('C21DD66ACAC13CB3BC8B331B24AFB57B'),
                                 algo_auth='triple_des_cbc2', kid_idx=3,
                                 kid=h2b('12110C78E678C25408233076AA033615'))
        h.tar = h2b('000000')
        # unciphered, no CC, PoR required
        h.spi = {'counter': 'no_counter', 'ciphering': False, 'rc_cc_ds': 'no_rc_cc_ds',
                 'por_in_submit': False, 'por': 'por_required',
                 'por_shall_be_ciphered': False, 'por_rc_cc_ds': 'no_rc_cc_ds'}
        h.remote_format = remote_format
        h.reassembler = ConcatenatedSmsReassembler()
        h.response = None
        return h

    @staticmethod
    def _plaintext_resp_sms(secured: bytes, sts: int = 0x00) -> bytes:
        """Build a plaintext (unciphered, no-CC) OTA SMS response packet in the
        canonical single-part form (UDH 02 71 00 + response packet)."""
        rpl = 1 + 3 + 5 + 1 + 1 + len(secured)   # RHL-STS + secured data
        body = (rpl.to_bytes(2, 'big') + b'\x0a' + h2b('000000') + b'\x00' * 5
                + b'\x00' + bytes([sts]) + secured)
        return b'\x02\x71\x00' + body

    @staticmethod
    def _expanded_secured(response_data_hex: str, sw: str = '9000') -> bytes:
        return ExpandedRemoteResp.build(dict(body=dict(
            num_executed=dict(number_of_commands=1),
            responses=[dict(r_apdu=dict(response_data=response_data_hex, status_word=sw))])))

    @staticmethod
    def _fragment_2(tpud: bytes, ref: int, first_len: int):
        """Split 02 71 00 + body TP-UD into two SMS parts:
        - part1 carries the OTA (0x71) IE
        - part2 only concatenat IE
        matches sja5 interaction"""
        assert tpud[:3] == b'\x02\x71\x00'
        body = tpud[3:]
        ota_ie = {'iei': 0x71, 'length': 0, 'value': b''}

        def concat(seq):
            return {'iei': 0x00, 'length': 3, 'value': bytes([ref, 2, seq])}
        p1 = UserDataHeader([concat(1), ota_ie]).to_bytes() + body[:first_len]
        p2 = UserDataHeader([concat(2)]).to_bytes() + body[first_len:]
        return p1, p2

    # ground truth: TP-User-Data captured from a sja5
    REAL_PART1 = h2b('070003010201710000e412000000df63afe4b06db21e2113be1be09e9b66f1c113ae841cca2d030064ec16b5b80ee5ce824604a4568109d25a82fb74a325df6f911bd0a4f858ece2c770039002c480269fc65953f5fd93ebbe528d97838bac4389a7303db2b073a37a9a1a51890457f41b49fc7905ce337e83449b65560501b8b845fe63339d557a928f2643')
    REAL_PART2 = h2b('050003010202fd9c4e50ec40fb4427af518e9c08697405d91fbb6e9fa0b0935f48a560e15f2f3f27a2e44ef3a47280acce77f030fb70eb3df863c159177e2c0e3e53052fc7bb7ed171a491ded3ab7921861176a04305bc09fcf526c07bf6bb48a19e67cf18be5bc1')
    REAL_REASSEMBLED = '02710000e412000000df63afe4b06db21e2113be1be09e9b66f1c113ae841cca2d030064ec16b5b80ee5ce824604a4568109d25a82fb74a325df6f911bd0a4f858ece2c770039002c480269fc65953f5fd93ebbe528d97838bac4389a7303db2b073a37a9a1a51890457f41b49fc7905ce337e83449b65560501b8b845fe63339d557a928f2643fd9c4e50ec40fb4427af518e9c08697405d91fbb6e9fa0b0935f48a560e15f2f3f27a2e44ef3a47280acce77f030fb70eb3df863c159177e2c0e3e53052fc7bb7ed171a491ded3ab7921861176a04305bc09fcf526c07bf6bb48a19e67cf18be5bc1'

    def test_real_card_parts_reassemble(self):
        """two real card TP-UDs recombine into 233-byte single part packet:
        UDH 02 71 00 + response packet"""
        r = ConcatenatedSmsReassembler()
        self.assertIsNone(r.add(self.REAL_PART1))
        out = r.add(self.REAL_PART2)
        self.assertEqual(len(out), 233)
        self.assertEqual(b2h(out), self.REAL_REASSEMBLED)

    def test_multipart_response_not_overwritten_by_por(self):
        """reassembled application response must survive the ENVELOPE
        trailing POR which contains no R-APDU"""
        registry = bytes(range(198))
        app = self._plaintext_resp_sms(self._expanded_secured(b2h(registry)))
        part1, part2 = self._fragment_2(app, ref=0x42, first_len=132)
        # single part form must be too fat -> both parts must be concatenated
        self.assertGreater(len(app), 140)
        # ENVELOPE PoR: por_ok, but no app R-APDU
        inline_por = self._plaintext_resp_sms(b'', sts=0x00)

        h = self._handler()
        # arrival order
        self.assertIsNone(h.message_received_handler(_FakePdu(part1)))
        h.message_received_handler(_FakePdu(part2))
        h.message_received_handler(_FakePdu(inline_por))

        # self.response must be app response, not the PoR!
        self.assertIsNotNone(h.response)
        res, decoded = h.response
        self.assertEqual(res.response_status, 'por_ok')
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.last_response_data, b2h(registry))
        self.assertEqual(decoded.last_status_word, '9000')

    def test_undecodable_response_does_not_crash(self):
        """response the handler can't decode must not escape out of the poll()
        loop which would kill the tool, it must be ignored"""
        # por_ok with a not expanded 'secured data' -> expanded parse raises
        bad = self._plaintext_resp_sms(h2b('01612f'), sts=0x00)
        h = self._handler(remote_format='expanded')
        # must NOT raise
        self.assertIsNone(h.message_received_handler(_FakePdu(bad)))
        self.assertIsNone(h.response)

    def test_undecodable_por_after_good_response(self):
        """real app response followed by undecodable PoR:
        - good response is saved
        - tool does not crash."""
        registry = bytes(range(120))
        app = self._plaintext_resp_sms(self._expanded_secured(b2h(registry)))
        part1, part2 = self._fragment_2(app, ref=0x07, first_len=110)
        bad_por = self._plaintext_resp_sms(h2b('deadbeef'), sts=0x00)

        h = self._handler()
        h.message_received_handler(_FakePdu(part1))
        h.message_received_handler(_FakePdu(part2))
        self.assertIsNone(h.message_received_handler(_FakePdu(bad_por)))  # no crash
        res, decoded = h.response
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.last_response_data, b2h(registry))

    def test_single_part_response_still_works(self):
        """small response that fits one SMS turns into self.response, handled as before"""
        h = self._handler()
        sms = self._plaintext_resp_sms(self._expanded_secured('abcd', sw='9000'))
        self.assertLessEqual(len(sms), 140)
        h.message_received_handler(_FakePdu(sms))
        res, decoded = h.response
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.last_response_data, 'abcd')
        self.assertEqual(decoded.last_status_word, '9000')


if __name__ == '__main__':
    unittest.main()
