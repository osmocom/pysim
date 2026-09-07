#!/usr/bin/env python3

# (C) 2026 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
#
# Author: Eric Wild
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

from pySim.bip import Proact
from pySim.sms import SMS_SUBMIT, AddressField


class BipSinkTest(unittest.TestCase):
    """Both sinks are optional, a driver with no SMS path at all must not crash and burn
    with a card that sends one, and one that has one must get the PDU."""

    def _submit(self):
        return SMS_SUBMIT(tp_da=AddressField('12345', 'unknown', 'unknown'),
                          tp_ud=b'\x01\x02', tp_udl=2, tp_dcs=0xf6)

    def test_sinks_default_to_none(self):
        p = Proact()
        self.assertIsNone(p.sms_sink)

    def test_mo_sms_goes_to_the_sink(self):
        seen = []
        Proact(sms_sink=seen.append).send_sms_via_smpp(self._submit())
        self.assertEqual(len(seen), 1)

    def test_no_sms_sink_drops_instead_of_raising(self):
        with self.assertLogs('pySim.bip', level='INFO'):
            Proact().send_sms_via_smpp(self._submit())
