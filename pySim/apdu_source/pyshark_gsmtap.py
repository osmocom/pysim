# coding=utf-8

# (C) 2022 by Harald Welte <laforge@osmocom.org>
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


import logging
from typing import Tuple
import pyshark
from osmocom.gsmtap import GsmtapMessage

from pySim.utils import h2b
from pySim.apdu.ts_102_221 import ApduCommands as UiccApduCommands
from pySim.apdu.ts_102_222 import ApduCommands as UiccAdmApduCommands
from pySim.apdu.ts_31_102 import ApduCommands as UsimApduCommands
from pySim.apdu.global_platform import ApduCommands as GpApduCommands

from . import ApduSource, PacketType, CardReset

ApduCommands = UiccApduCommands + UiccAdmApduCommands + UsimApduCommands + GpApduCommands

logger = logging.getLogger(__name__)

class _PysharkGsmtap(ApduSource):
    """APDU Source [provider] base class for reading GSMTAP SIM APDU via tshark."""

    def __init__(self, pyshark_inst):
        self.pyshark = pyshark_inst
        self.bank_id = None
        self.bank_slot = None
        self.cmd_tpdu = None
        super().__init__()

    def read_packet(self) -> PacketType:
        p = self.pyshark.next()
        return self._parse_packet(p)

    def _set_or_verify_bank_slot(self, bsl: Tuple[int, int]):
        """Keep track of the bank:slot to make sure we don't mix traces of multiple cards"""
        if not self.bank_id:
            self.bank_id = bsl[0]
            self.bank_slot = bsl[1]
        else:
            if self.bank_id != bsl[0] or self.bank_slot != bsl[1]:
                raise ValueError('Received data for unexpected B(%u:%u)' % (bsl[0], bsl[1]))

    def _parse_packet(self, p) -> PacketType:
        udp_layer = p['udp']
        udp_payload_hex = udp_layer.get_field('payload').replace(':','')
        gsmtap = GsmtapMessage(h2b(udp_payload_hex))
        gsmtap_msg = gsmtap.decode()
        if gsmtap_msg['type'] != 'sim':
            raise ValueError('Unsupported GSMTAP type %s' % gsmtap_msg['type'])
        sub_type = gsmtap_msg['sub_type']
        if sub_type == 'apdu':
            return ApduCommands.parse_cmd_bytes(gsmtap_msg['body'])
        if sub_type == 'atr':
            # card has been reset
            return CardReset(gsmtap_msg['body'])
        if sub_type in ['pps_req', 'pps_rsp']:
            # simply ignore for now
            pass
        else:
            raise ValueError('Unsupported GSMTAP-SIM sub-type %s' % sub_type)

class PysharkGsmtapPcap(_PysharkGsmtap):
    """APDU Source [provider] class for reading GSMTAP from a PCAP
    file via pyshark, which in turn uses tshark (part of wireshark).
    """
    def __init__(self, pcap_filename):
        """
        Args:
            pcap_filename: File name of the pcap file to be opened
        """
        pyshark_inst = pyshark.FileCapture(pcap_filename, display_filter='gsm_sim', use_json=True, keep_packets=False)
        super().__init__(pyshark_inst)
