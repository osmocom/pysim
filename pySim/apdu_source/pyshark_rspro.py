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

from pySim.utils import h2b
from pySim.apdu import Tpdu
from . import ApduSource, PacketType, CardReset

logger = logging.getLogger(__name__)

class _PysharkRspro(ApduSource):
    """APDU Source [provider] base class for reading RSPRO (osmo-remsim) via tshark."""

    def __init__(self, pyshark_inst):
        self.pyshark = pyshark_inst
        self.bank_id = None
        self.bank_slot = None
        self.cmd_tpdu = None
        super().__init__()

    @staticmethod
    def get_bank_slot(bank_slot) -> Tuple[int, int]:
        """Convert a 'bankSlot_element' field into a tuple of bank_id, slot_nr"""
        bank_id = bank_slot.get_field('bankId')
        slot_nr = bank_slot.get_field('slotNr')
        return int(bank_id), int(slot_nr)

    @staticmethod
    def get_client_slot(client_slot) -> Tuple[int, int]:
        """Convert a 'clientSlot_element' field into a tuple of client_id, slot_nr"""
        client_id = client_slot.get_field('clientId')
        slot_nr = client_slot.get_field('slotNr')
        return int(client_id), int(slot_nr)

    @staticmethod
    def get_pstatus(pstatus) -> Tuple[int, int, int]:
        """Convert a 'slotPhysStatus_element' field into a tuple of vcc, reset, clk"""
        vccPresent = int(pstatus.get_field('vccPresent'))
        resetActive = int(pstatus.get_field('resetActive'))
        clkActive = int(pstatus.get_field('clkActive'))
        return vccPresent, resetActive, clkActive

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
        rspro_layer = p['rspro']
        #print("Layer: %s" %  rspro_layer)
        rspro_element = rspro_layer.get_field('RsproPDU_element')
        #print("Element: %s" % rspro_element)
        msg_type = rspro_element.get_field('msg')
        rspro_msg = rspro_element.get_field('msg_tree')
        if msg_type == '12': # tpduModemToCard
            modem2card = rspro_msg.get_field('tpduModemToCard_element')
            #print(modem2card)
            client_slot = modem2card.get_field('fromClientSlot_element')
            csl = self.get_client_slot(client_slot)
            bank_slot = modem2card.get_field('toBankSlot_element')
            bsl = self.get_bank_slot(bank_slot)
            self._set_or_verify_bank_slot(bsl)
            data = modem2card.get_field('data').replace(':','')
            logger.debug("C(%u:%u) -> B(%u:%u): %s", csl[0], csl[1], bsl[0], bsl[1], data)
            # store the CMD portion until the RSP portion arrives later
            self.cmd_tpdu = h2b(data)
        elif msg_type == '13': # tpduCardToModem
            card2modem = rspro_msg.get_field('tpduCardToModem_element')
            #print(card2modem)
            client_slot = card2modem.get_field('toClientSlot_element')
            csl = self.get_client_slot(client_slot)
            bank_slot = card2modem.get_field('fromBankSlot_element')
            bsl = self.get_bank_slot(bank_slot)
            self._set_or_verify_bank_slot(bsl)
            data = card2modem.get_field('data').replace(':','')
            logger.debug("C(%u:%u) <- B(%u:%u): %s", csl[0], csl[1], bsl[0], bsl[1], data)
            rsp_tpdu = h2b(data)
            if self.cmd_tpdu:
                # combine this R-TPDU with the C-TPDU we saw earlier
                r = Tpdu(self.cmd_tpdu, rsp_tpdu)
                self.cmd_tpdu = False
                return r
        elif msg_type == '14': # clientSlotStatus
            cl_slotstatus = rspro_msg.get_field('clientSlotStatusInd_element')
            #print(cl_slotstatus)
            client_slot = cl_slotstatus.get_field('fromClientSlot_element')
            bank_slot = cl_slotstatus.get_field('toBankSlot_element')
            slot_pstatus = cl_slotstatus.get_field('slotPhysStatus_element')
            vccPresent, resetActive, clkActive = self.get_pstatus(slot_pstatus)
            if vccPresent and clkActive and not resetActive:
                logger.debug("RESET")
                #TODO: extract ATR from RSPRO message and use it here
                return CardReset(None)
        else:
            print("Unhandled msg type %s: %s" % (msg_type, rspro_msg))


class PysharkRsproPcap(_PysharkRspro):
    """APDU Source [provider] class for reading RSPRO (osmo-remsim) from a PCAP
    file via pyshark, which in turn uses tshark (part of wireshark).

    In order to use this, you need a wireshark patched with RSPRO support,
    such as can be found at https://gitea.osmocom.org/osmocom/wireshark/src/branch/laforge/rspro

    A STANDARD UPSTREAM WIRESHARK *DOES NOT WORK*.
    """
    def __init__(self, pcap_filename):
        """
        Args:
            pcap_filename: File name of the pcap file to be opened
        """
        pyshark_inst = pyshark.FileCapture(pcap_filename, display_filter='rspro', use_json=True, keep_packets=False)
        super().__init__(pyshark_inst)

class PysharkRsproLive(_PysharkRspro):
    """APDU Source [provider] class for reading RSPRO (osmo-remsim) from a live capture
    via pyshark, which in turn uses tshark (part of wireshark).

    In order to use this, you need a wireshark patched with RSPRO support,
    such as can be found at https://gitea.osmocom.org/osmocom/wireshark/src/branch/laforge/rspro

    A STANDARD UPSTREAM WIRESHARK *DOES NOT WORK*.
    """
    def __init__(self, interface, bpf_filter='tcp port 9999 or tcp port 9998'):
        """
        Args:
            interface: Network interface name to capture packets on (like "eth0")
            bfp_filter: libpcap capture filter to use
        """
        pyshark_inst = pyshark.LiveCapture(interface=interface, display_filter='rspro', bpf_filter=bpf_filter,
                                           use_json=True)
        super().__init__(pyshark_inst)
