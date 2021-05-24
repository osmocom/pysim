"""Code related to the Card Application Toolkit (CAT) as described in
mainly) ETSI TS 102 223, ETSI TS 101 220 and 3GPP TS 31.111."""

# (C) 2021 by Harald Welte <laforge@osmocom.org>
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


from pySim.tlv import *
from pySim.construct import *
from construct import *

# Tag values as per TS 101 220 Table 7.23

# TS 102 223 Section 8.1
class Address(COMPR_TLV_IE, tag=0x06):
    _construct = Struct('ton_npi'/Int8ub,
                        'call_number'/BcdAdapter(Bytes(this._.total_len-1)))

# TS 102 223 Section 8.2
class AlphaIdentifier(COMPR_TLV_IE, tag=0x05):
    # FIXME: like EF.ADN
    pass

# TS 102 223 Section 8.3
class Subaddress(COMPR_TLV_IE, tag=0x08):
    pass

# TS 102 223 Section 8.4
class CapabilityConfigParams(COMPR_TLV_IE, tag=0x07):
    pass

# TS 31.111 Section 8.5
class CBSPage(COMPR_TLV_IE, tag=0x0C):
    pass

# TS 102 223 Section 8.6
class CommandDetails(COMPR_TLV_IE, tag=0x01):
    _construct = Struct('command_number'/Int8ub,
                        'type_of_command'/Int8ub,
                        'command_qualifier'/Int8ub)

# TS 102 223 Section 8.7
class DeviceIdentities(COMPR_TLV_IE, tag=0x02):
    DEV_IDS = bidict({
        0x01: 'keypad',
        0x02: 'display',
        0x03: 'earpiece',
        0x10: 'addl_card_reader_0',
        0x11: 'addl_card_reader_1',
        0x12: 'addl_card_reader_2',
        0x13: 'addl_card_reader_3',
        0x14: 'addl_card_reader_4',
        0x15: 'addl_card_reader_5',
        0x16: 'addl_card_reader_6',
        0x17: 'addl_card_reader_7',
        0x21: 'channel_1',
        0x22: 'channel_2',
        0x23: 'channel_3',
        0x24: 'channel_4',
        0x25: 'channel_5',
        0x26: 'channel_6',
        0x27: 'channel_7',
        0x31: 'ecat_client_1',
        0x32: 'ecat_client_2',
        0x33: 'ecat_client_3',
        0x34: 'ecat_client_4',
        0x35: 'ecat_client_5',
        0x36: 'ecat_client_6',
        0x37: 'ecat_client_7',
        0x38: 'ecat_client_8',
        0x39: 'ecat_client_9',
        0x3a: 'ecat_client_a',
        0x3b: 'ecat_client_b',
        0x3c: 'ecat_client_c',
        0x3d: 'ecat_client_d',
        0x3e: 'ecat_client_e',
        0x3f: 'ecat_client_f',
        0x81: 'uicc',
        0x82: 'terminal',
        0x83: 'network',
        })
    def _from_bytes(self, do:bytes):
        return {'source_dev_id': self.DEV_IDS[do[0]], 'dest_dev_id': self.DEV_IDS[do[1]]}

    def _to_bytes(self):
        src = self.DEV_IDS.inverse[self.decoded['source_dev_id']]
        dst = self.DEV_IDS.inverse[self.decoded['dest_dev_id']]
        return bytes([src, dst])

# TS 102 223 Section 8.8
class Duration(COMPR_TLV_IE, tag=0x04):
    _construct = Struct('time_unit'/Int8ub,
                        'time_interval'/Int8ub)

# TS 102 223 Section 8.9
class Item(COMPR_TLV_IE, tag=0x0f):
    _construct = Struct('identifier'/Int8ub,
                        'text_string'/GsmStringAdapter(GreedyBytes))

# TS 102 223 Section 8.10
class ItemIdentifier(COMPR_TLV_IE, tag=0x10):
    _construct = Struct('identifier'/Int8ub)

# TS 102 223 Section 8.11
class ResponseLength(COMPR_TLV_IE, tag=0x11):
    _construct = Struct('minimum_length'/Int8ub,
                        'maximum_length'/Int8ub)

# TS 102 223 Section 8.12
class Result(COMPR_TLV_IE, tag=0x03):
    _construct = Struct('general_result'/Int8ub,
                        'additional_information'/HexAdapter(GreedyBytes))



# TS 102 223 Section 8.13  + TS 31.111 Section 8.13
class SMS_TPDU(COMPR_TLV_IE, tag=0x0B):
    pass

# TS 102 223 Section 8.15
class TextString(COMPR_TLV_IE, tag=0x0d):
    _construct = Struct('dcs'/Int8ub,
                        'text_string'/HexAdapter(GreedyBytes))

# TS 102 223 Section 8.16
class Tone(COMPR_TLV_IE, tag=0x0e):
    _construct = Struct('tone'/Int8ub)

# TS 31 111 Section 8.17
class USSDString(COMPR_TLV_IE, tag=0x0a):
    _construct = Struct('dcs'/Int8ub,
                        'ussd_string'/HexAdapter(GreedyBytes))



# TS 101 220 Table 7.17
class ProactiveCommand(BER_TLV_IE, tag=0xD0):
    pass

# TS 101 220 Table 7.17 + 31.111 7.1.1.2
class SMSPPDownload(BER_TLV_IE, tag=0xD1,
                    nested=[DeviceIdentities, Address, SMS_TPDU]):
    pass

# TS 101 220 Table 7.17 + 31.111 7.1.1.3
class SMSCBDownload(BER_TLV_IE, tag=0xD2,
                    nested=[DeviceIdentities, CBSPage]):
    pass

class USSDDownload(BER_TLV_IE, tag=0xD9,
                    nested=[DeviceIdentities, USSDString]):
    pass

term_prof_bits = {
      1: 'Profile download',
      2: 'SMS-PP data doanload',
      3: 'Cell Broadcast data download',
      4: 'Menu selection',
      5: 'SMS-PP data download',
      6: 'Timer expiration',
      7: 'USSD string DO support in CC by USIM',
      8: 'Call Control by NAA',

      9: 'Command result',
     10: 'Call Controll by NAA',
     11: 'Call Control by NAA',
     12: 'MO short message control support',
     13: 'Call Control by NAA',
     14: 'UCS2 Entry supported',
     15: 'UCS2 Display supported',
     16: 'Display Text',

     17: 'Proactive UICC: DISPLAY TEXT',
     18: 'Proactive UICC: GET INKEY',
     19: 'Proactive UICC: GET INPUT',
     20: 'Proactive UICC: MORE TIME',
     21: 'Proactive UICC: PLAY TONE',
     22: 'Proactive UICC: POLL INTERVAL',
     23: 'Proactive UICC: POLLING OFF',
     24: 'Proactive UICC: REFRESH',

     25: 'Proactive UICC: SELECT ITEM',
     26: 'Proactive UICC: SEND SHORT MESSAGE with 3GPP-SMS-TPDU',
     27: 'Proactive UICC: SEND SS',
     28: 'Proactive UICC: SEND USSD',
     29: 'Proactive UICC: SET UP CALL',
     30: 'Proactive UICC: SET UP MENU',
     31: 'Proactive UICC: PROVIDE LOCAL INFORMATION (MCC, MNC, LAC, Cell ID & IMEI)',
     32: 'Proactive UICC: PROVIDE LOCAL INFORMATION (NMR)',

     33: 'Proactive UICC: SET UP EVENT LIST',
     34: 'Event: MT call',
     35: 'Event: Call connected',
     36: 'Event: Call disconnected',
     37: 'Event: Location status',
     38: 'Event: User activity',
     39: 'Event: Idle screen available',
     40: 'Event: Card reader status',

     41: 'Event: Language selection',
     42: 'Event: Browser Termination',
     43: 'Event: Data aailable',
     44: 'Event: Channel status',
     45: 'Event: Access Technology Change',
     46: 'Event: Display parameters changed',
     47: 'Event: Local Connection',
     48: 'Event: Network Search Mode Change',

     # FIXME: remainder
}
