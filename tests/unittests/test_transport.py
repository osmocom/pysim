#!/usr/bin/env python3

"""Transport (as in t0/t1) tests"""

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

import unittest
from osmocom.utils import h2b, b2h
from pySim.cat import ProactiveCommand, CommandDetails, DeviceIdentities, Result
from pySim.transport import ProactiveHandler, LinkBaseTpdu


def _send_short_message_pcmd():
    """proactive SEND SHORT MESSAGE:
    D0 | CommandDetails(cmd 1, t 0x13, q 0) | DeviceIdentities(uicc->network)
       | dummy SMS_TPDU"""
    body = h2b('8103011300' + '82028183' + '8B04DEADBEEF')
    pdu = h2b('D0') + bytes([len(body)]) + body
    pcmd = ProactiveCommand()
    decoded = pcmd.from_tlv(pdu)
    return pcmd, decoded


class Test_prepare_response(unittest.TestCase):
    """TERMINAL RESPONSE.
    multi-part OTA response crash regression test."""

    def setUp(self):
        self.h = ProactiveHandler.__new__(ProactiveHandler)

    def test_on_decoded_command(self):
        _pcmd, decoded = _send_short_message_pcmd()
        til = self.h.prepare_response(decoded)
        self.assertEqual([type(c).__name__ for c in til],
                         ['CommandDetails', 'DeviceIdentities', 'Result'])
        # command details echoed, device id inverted, result OK
        self.assertEqual(b2h(til[0].to_tlv()), '8103011300')
        self.assertEqual(b2h(til[1].to_tlv()), '82028381')
        self.assertEqual(b2h(til[2].to_tlv()), '830100')

    def test_on_collection_resolves_via_decoded(self):
        # Check that ProactiveCommand collection (empty .children) still works
        pcmd, _decoded = _send_short_message_pcmd()
        self.assertEqual(list(getattr(pcmd, 'children', []) or []), [])
        til = self.h.prepare_response(pcmd)
        self.assertEqual([type(c).__name__ for c in til],
                         ['CommandDetails', 'DeviceIdentities', 'Result'])
        self.assertEqual(b2h(til[0].to_tlv()), '8103011300')
        self.assertEqual(b2h(til[1].to_tlv()), '82028381')
        self.assertEqual(b2h(til[2].to_tlv()), '830100')

    def test_missing_command_details_raises_clear_error(self):
        class _NoChildren:
            children = []
        with self.assertRaises(ValueError) as ctx:
            self.h.prepare_response(_NoChildren())
        self.assertIn('CommandDetails', str(ctx.exception))


class FakeTpduLink(LinkBaseTpdu):
    """mock LinkBaseTpdu that replays a list of (data, sw) responses + records every TPDU that
    the T=0 state machine sends. Secretly sending more TPDUs than intended is the error,
    designed to test "unsolicited GET RESPONSE" mishaps"""

    def __init__(self, responses):
        super().__init__()
        self._responses = list(responses)
        self.sent = []

    def send_tpdu(self, tpdu):
        self.sent.append(tpdu.lower())
        if not self._responses:
            raise AssertionError('T=0 layer sent an unpexpected TPDU: %s (total so far: %s)'
                                 % (tpdu, self.sent))
        return self._responses.pop(0)

    def __str__(self):
        return 'FakeTpduLink'

    def wait_for_card(self, timeout=None, newcardonly=False):
        pass

    def connect(self):
        pass

    def get_atr(self):
        return '3b00'

    def disconnect(self):
        pass

    def _reset_card(self):
        pass


# GP GET STATUS, wrapped in SCP02 CLA 84, Case #4.
GET_STATUS = '84f22002094f005c054f9f70c5cc' + '00'
GET_STATUS_TPDU = '84f22002094f005c054f9f70c5cc'

# generic #4 SELECT by DF name command
CASE4 = '00a4040c07a0000000871002' + '00'
CASE4_TPDU = '00a4040c07a0000000871002'


class Test_send_apdu_T0(unittest.TestCase):
    """regression tests for the T=0 state machine in LinkBaseTpdu.__send_apdu_T0()"""

    def _exchange(self, apdu, responses, strict=True, protocol=0):
        link = FakeTpduLink(responses)
        link.apdu_strict = strict
        link.set_tpdu_format(protocol)
        data, sw = link._send_apdu(apdu)
        return link, data, sw

    #### TS 102 221 section 7.3.1.1 TPDU construction

    def test_case1_gets_le_appended(self):
        link, data, sw = self._exchange('00200001', [('', '9000')])
        self.assertEqual(link.sent, ['0020000100'])
        self.assertEqual((data, sw), ('', '9000'))

    def test_case3_passed_through_unmodified(self):
        apdu = '00200001081122334455667788'
        link, _data, sw = self._exchange(apdu, [('', '9000')])
        self.assertEqual(link.sent, [apdu])
        self.assertEqual(sw, '9000')

    def test_case4_le_stripped(self):
        link, data, sw = self._exchange(CASE4, [('', '9000')])
        self.assertEqual(link.sent, [CASE4_TPDU])
        self.assertEqual((data, sw), ('', '9000'))

    #### TS 102 221 7.3.1.1.4 4a GP GET RESPONSE for 61xx / 9fxx

    def test_61xx_fetches_response(self):
        link, data, sw = self._exchange(CASE4, [('', '6103'), ('a1b2c3', '9000')])
        self.assertEqual(link.sent, [CASE4_TPDU, '00c0000003'])
        self.assertEqual((data, sw), ('a1b2c3', '9000'))

    def test_61xx_chained(self):
        link, data, sw = self._exchange(CASE4,
                                        [('', '6102'), ('aabb', '6102'), ('ccdd', '9000')])
        self.assertEqual(link.sent, [CASE4_TPDU, '00c0000002', '00c0000002'])
        self.assertEqual((data, sw), ('aabbccdd', '9000'))

    def test_9fxx_fetches_response(self):
        link, data, sw = self._exchange(CASE4, [('', '9f04'), ('deadbeef', '9000')])
        self.assertEqual(link.sent, [CASE4_TPDU, '00c0000004'])
        self.assertEqual((data, sw), ('deadbeef', '9000'))

    def test_get_response_inherits_cla(self):
        """GET RESPONSE must reuse  CLA of command"""
        link, _data, _sw = self._exchange(GET_STATUS, [('', '6102'), ('aabb', '9000')])
        self.assertEqual(link.sent, [GET_STATUS_TPDU, '84c0000002'])

    def test_9100_terminates(self):
        """9100 is final status word, not fetch trigger"""
        link, data, sw = self._exchange(CASE4, [('', '9100')])
        self.assertEqual(link.sent, [CASE4_TPDU])
        self.assertEqual((data, sw), ('', '9100'))

    def test_error_sw_terminates(self):
        link, data, sw = self._exchange(CASE4, [('', '6982')])
        self.assertEqual(link.sent, [CASE4_TPDU])
        self.assertEqual((data, sw), ('', '6982'))

    def test_no_status_word_raises(self):
        with self.assertRaises(ValueError):
            self._exchange(CASE4, [('', None)])

    #### TS 102 221 7.3.1.1.4 4b dummy GET RESPONSE

    def test_clause_4b_warning_before_data_bootstraps(self):
        """warning SW returned for the _command_ TPDU triggers dummy GET RESPONSE (Le=00)"""
        for warn in ('6200', '6281', '62f1', '6300', '63f1'):
            with self.subTest(sw=warn):
                link, data, sw = self._exchange(CASE4,
                                                [('', warn), ('', '6103'), ('a1b2c3', '9000')])
                self.assertEqual(link.sent, [CASE4_TPDU, '00c0000000', '00c0000003'])
                self.assertEqual((data, sw), ('a1b2c3', '9000'))

    def test_warning_after_data_terminates(self):
        """Once the response has been fetched a warning status word is the final result of the command"""
        for warn in ('6281', '6283', '63c2', '6300', '62f1', '63f1', '6310'):
            with self.subTest(sw=warn):
                link, data, sw = self._exchange(CASE4, [('', '6102'), ('aabb', warn)])
                self.assertEqual(link.sent, [CASE4_TPDU, '00c0000002'])
                self.assertEqual((data, sw), ('aabb', warn))

    def test_no_dummy_get_response_when_command_already_returned_data(self):
        """warning that arrives together with response data (for example 6282 on a case #2 read) is final, too"""
        link, data, sw = self._exchange('00b0000004', [('01020304', '6282')], strict=False)
        self.assertEqual(link.sent, ['00b0000004'])
        self.assertEqual((data, sw), ('01020304', '6282'))

    def test_repeated_warning_does_not_loop(self):
        """warning -> dummy GET RESPONSE -> warning again must terminate"""
        link, data, sw = self._exchange(CASE4, [('', '6281'), ('', '6281')])
        self.assertEqual(link.sent, [CASE4_TPDU, '00c0000000'])
        self.assertEqual((data, sw), ('', '6281'))

    #### fixed GlobalPlatform GET STATUS pagination

    def test_gp_6310_reaches_the_caller(self):
        """GET STATUS answers 6310"""
        link, data, sw = self._exchange(GET_STATUS, [('', '6104'), ('e3024f00', '6310')])
        self.assertEqual(link.sent, [GET_STATUS_TPDU, '84c0000004'])
        self.assertEqual((data, sw), ('e3024f00', '6310'))

    def test_gp_get_status_two_pages(self):
        """Both GET STATUS pages, page 1 6310, reissued with P2 bit 1 set, page 2 9000."""
        page1 = self._exchange(GET_STATUS, [('', '6104'), ('e3024f00', '6310')])
        self.assertEqual(page1[1:], ('e3024f00', '6310'))
        page2 = self._exchange('84f22003094f005c054f9f70c5cc00',
                               [('', '6104'), ('e3024f01', '9000')])
        self.assertEqual(page2[0].sent, ['84f22003094f005c054f9f70c5cc', '84c0000004'])
        self.assertEqual(page2[1:], ('e3024f01', '9000'))

    #### 6cxx and apdu_strict

    def test_6cxx_reissues_command_with_correct_length(self):
        link, data, sw = self._exchange('00b0000000', [('', '6c04'), ('01020304', '9000')])
        self.assertEqual(link.sent, ['00b0000000', '00b0000004'])
        self.assertEqual((data, sw), ('01020304', '9000'))

    def test_strict_mode_does_not_auto_fetch_for_case3(self):
        apdu = '00200001081122334455667788'
        link, data, sw = self._exchange(apdu, [('', '6104')], strict=True)
        self.assertEqual(link.sent, [apdu])
        self.assertEqual((data, sw), ('', '6104'))

    def test_non_strict_mode_auto_fetches_for_case3(self):
        apdu = '00200001081122334455667788'
        link, data, sw = self._exchange(apdu, [('', '6104'), ('aabbccdd', '9000')], strict=False)
        self.assertEqual(link.sent, [apdu, '00c0000004'])
        self.assertEqual((data, sw), ('aabbccdd', '9000'))

    #### T=1 briefly

    def test_t1_is_passed_through(self):
        """T=1 has no GET RESPONSE"""
        link, data, sw = self._exchange(GET_STATUS, [('e3024f00', '6310')], protocol=1)
        self.assertEqual(link.sent, [GET_STATUS.lower()])
        self.assertEqual((data, sw), ('e3024f00', '6310'))


if __name__ == "__main__":
    unittest.main()
