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
from pySim.transport import ProactiveHandler


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


if __name__ == "__main__":
    unittest.main()
