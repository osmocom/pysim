# -*- coding: utf-8 -*-

""" Osmocom GSMTAP python implementation.
GSMTAP is a packet format used for conveying a number of different
telecom-related protocol traces over UDP.
"""

#
# Copyright (C) 2022  Harald Welte <laforge@gnumonks.org>
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
#

import socket
from typing import List, Dict, Optional
from construct import Optional as COptional
from construct import *
from pySim.construct import *

# The root definition of GSMTAP can be found at
# https://cgit.osmocom.org/cgit/libosmocore/tree/include/osmocom/core/gsmtap.h

GSMTAP_UDP_PORT = 4729

# GSMTAP_TYPE_*
gsmtap_type_construct = Enum(Int8ub,
                             gsm_um = 0x01,
                             gsm_abis = 0x02,
                             gsm_um_burst = 0x03,
                             sim = 0x04,
                             tetra_i1 = 0x05,
                             tetra_i1_burst = 0x06,
                             wimax_burst = 0x07,
                             gprs_gb_llc = 0x08,
                             gprs_gb_sndcp = 0x09,
                             gmr1_um = 0x0a,
                             umts_rlc_mac = 0x0b,
                             umts_rrc = 0x0c,
                             lte_rrc = 0x0d,
                             lte_mac = 0x0e,
                             lte_mac_framed = 0x0f,
                             osmocore_log = 0x10,
                             qc_diag = 0x11,
                             lte_nas = 0x12,
                             e1_t1 = 0x13)


# TYPE_UM_BURST
gsmtap_subtype_burst_construct = Enum(Int8ub,
                                      unknown = 0x00,
                                      fcch = 0x01,
                                      partial_sch = 0x02,
                                      sch = 0x03,
                                      cts_sch = 0x04,
                                      compact_sch = 0x05,
                                      normal = 0x06,
                                      dummy = 0x07,
                                      access = 0x08,
                                      none = 0x09)

gsmtap_subtype_wimax_burst_construct = Enum(Int8ub,
                                            cdma_code = 0x10,
                                            fch = 0x11,
                                            ffb = 0x12,
                                            pdu = 0x13,
                                            hack = 0x14,
                                            phy_attributes = 0x15)

# GSMTAP_CHANNEL_*
gsmtap_subtype_um_construct = Enum(Int8ub,
                                   unknown = 0x00,
                                   bcch = 0x01,
                                   ccch = 0x02,
                                   rach = 0x03,
                                   agch = 0x04,
                                   pch = 0x05,
                                   sdcch = 0x06,
                                   sdcch4 = 0x07,
                                   sdcch8 = 0x08,
                                   facch_f = 0x09,
                                   facch_h = 0x0a,
                                   pacch = 0x0b,
                                   cbch52 = 0x0c,
                                   pdtch = 0x0d,
                                   ptcch = 0x0e,
                                   cbch51 = 0x0f,
                                   voice_f = 0x10,
                                   voice_h = 0x11)


# GSMTAP_SIM_*
gsmtap_subtype_sim_construct = Enum(Int8ub,
                                    apdu = 0x00,
                                    atr = 0x01,
                                    pps_req = 0x02,
                                    pps_rsp = 0x03,
                                    tpdu_hdr = 0x04,
                                    tpdu_cmd = 0x05,
                                    tpdu_rsp = 0x06,
                                    tpdu_sw = 0x07)

gsmtap_subtype_tetra_construct = Enum(Int8ub,
                                      bsch = 0x01,
                                      aach = 0x02,
                                      sch_hu = 0x03,
                                      sch_hd = 0x04,
                                      sch_f = 0x05,
                                      bnch = 0x06,
                                      stch = 0x07,
                                      tch_f = 0x08,
                                      dmo_sch_s = 0x09,
                                      dmo_sch_h = 0x0a,
                                      dmo_sch_f = 0x0b,
                                      dmo_stch = 0x0c,
                                      dmo_tch = 0x0d)

gsmtap_subtype_gmr1_construct = Enum(Int8ub,
                                     unknown = 0x00,
                                     bcch = 0x01,
                                     ccch = 0x02,
                                     pch = 0x03,
                                     agch = 0x04,
                                     bach = 0x05,
                                     rach = 0x06,
                                     cbch = 0x07,
                                     sdcch = 0x08,
                                     tachh = 0x09,
                                     gbch = 0x0a,
                                     tch3 = 0x10,
                                     tch6 = 0x14,
                                     tch9 = 0x18)

gsmtap_subtype_e1t1_construct = Enum(Int8ub,
                                     lapd = 0x01,
                                     fr = 0x02,
                                     raw = 0x03,
                                     trau16 = 0x04,
                                     trau8 = 0x05)

gsmtap_arfcn_construct = BitStruct('pcs'/Flag, 'uplink'/Flag, 'arfcn'/BitsInteger(14))

gsmtap_hdr_construct = Struct('version'/Int8ub,
                              'hdr_len'/Int8ub,
                              'type'/gsmtap_type_construct,
                              'timeslot'/Int8ub,
                              'arfcn'/gsmtap_arfcn_construct,
                              'signal_dbm'/Int8sb,
                              'snr_db'/Int8sb,
                              'frame_nr'/Int32ub,
                              'sub_type'/Switch(this.type, {
                                                'gsm_um': gsmtap_subtype_um_construct,
                                                'gsm_um_burst': gsmtap_subtype_burst_construct,
                                                'sim': gsmtap_subtype_sim_construct,
                                                'tetra_i1': gsmtap_subtype_tetra_construct,
                                                'tetra_i1_burst': gsmtap_subtype_tetra_construct,
                                                'wimax_burst': gsmtap_subtype_wimax_burst_construct,
                                                'gmr1_um': gsmtap_subtype_gmr1_construct,
                                                'e1_t1': gsmtap_subtype_e1t1_construct,
                                                }),
                              'antenna_nr'/Int8ub,
                              'sub_slot'/Int8ub,
                              'res'/Int8ub,
                              'body'/GreedyBytes)

osmocore_log_ts_construct = Struct('sec'/Int32ub, 'usec'/Int32ub)
osmocore_log_level_construct = Enum(Int8ub, debug=1, info=3, notice=5, error=7, fatal=8)
gsmtap_osmocore_log_hdr_construct = Struct('ts'/osmocore_log_ts_construct,
                                           'proc_name'/PaddedString(16, 'ascii'),
                                           'pid'/Int32ub,
                                           'level'/osmocore_log_level_construct,
                                           Bytes(3),
                                           'subsys'/PaddedString(16, 'ascii'),
                                           'src_file'/Struct('name'/PaddedString(32, 'ascii'), 'line_nr'/Int32ub))


class GsmtapMessage:
    """Class whose objects represent a single GSMTAP message. Can encode and decode messages."""
    def __init__(self, encoded = None):
        self.encoded = encoded
        self.decoded = None

    def decode(self):
        self.decoded = parse_construct(gsmtap_hdr_construct, self.encoded)
        return self.decoded

    def encode(self, decoded):
        self.encoded = gsmtap_hdr_construct.build(decoded)
        return self.encoded

class GsmtapSource:
    def __init__(self, bind_ip:str='127.0.0.1', bind_port:int=4729):
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_ip, self.bind_port))

    def read_packet(self) -> GsmtapMessage:
        data, addr = self.sock.recvfrom(1024)
        gsmtap_msg = GsmtapMessage(data)
        gsmtap_msg.decode()
        if gsmtap_msg.decoded['version'] != 0x02:
            raise ValueError('Unknown GSMTAP version 0x%02x' % gsmtap_msg.decoded['version'])
        return gsmtap_msg.decoded, addr
