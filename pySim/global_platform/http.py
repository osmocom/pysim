"""GlobalPlatform Remote Application Management over HTTP Card Specification v2.3 - Amendment B.
Also known as SCP81 for SIM/USIM/UICC/eUICC/eSIM OTA.
"""

# (C) 2024 by Harald Welte <laforge@osmocom.org>
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

from construct import Struct, Int8ub, Int16ub, GreedyString, BytesInteger
from construct import this, len_, Rebuild, Const
from construct import Optional as COptional
from osmocom.construct import Bytes, GreedyBytes
from osmocom.tlv import BER_TLV_IE

from pySim import cat


# Table 3-3 + Section 3.8.1
class RasConnectionParams(BER_TLV_IE, tag=0x84, nested=cat.OpenChannel.nested_collection_cls.possible_nested):
    pass

# Table 3-3 + Section 3.8.2
class SecurityParams(BER_TLV_IE, tag=0x85):
    _test_de_encode = [
        ( '850804deadbeef020040', {'kid': 64,'kvn': 0, 'psk_id': b'\xde\xad\xbe\xef', 'sha_type': None} )
    ]
    _construct = Struct('_psk_id_len'/Rebuild(Int8ub, len_(this.psk_id)), 'psk_id'/Bytes(this._psk_id_len),
                        '_kid_kvn_len'/Const(2, Int8ub), 'kvn'/Int8ub, 'kid'/Int8ub,
                        'sha_type'/COptional(Int8ub))

# Table 3-3 + ?
class ExtendedSecurityParams(BER_TLV_IE, tag=0xA5):
    _construct = GreedyBytes

# Table 3-3 + Section 3.8.3
class SessionRetryPolicyParams(BER_TLV_IE, tag=0x86):
    _construct = Struct('retry_counter'/Int16ub,
                        'retry_waiting_delay'/BytesInteger(5),
                        'retry_report_failure'/COptional(GreedyBytes))

# Table 3-3 + Section 3.8.4
class AdminHostParam(BER_TLV_IE, tag=0x8A):
    _test_de_encode = [
        ( '8a0a61646d696e2e686f7374', 'admin.host' ),
    ]
    _construct = GreedyString('utf-8')

# Table 3-3 + Section 3.8.5
class AgentIdParam(BER_TLV_IE, tag=0x8B):
    _construct = GreedyString('utf-8')

# Table 3-3 + Section 3.8.6
class AdminUriParam(BER_TLV_IE, tag=0x8C):
    _test_de_encode = [
        ( '8c1668747470733a2f2f61646d696e2e686f73742f757269', 'https://admin.host/uri' ),
    ]
    _construct = GreedyString('utf-8')

# Table 3-3
class HttpPostParams(BER_TLV_IE, tag=0x89, nested=[AdminHostParam, AgentIdParam, AdminUriParam]):
    pass

# Table 3-3
class AdmSessionParams(BER_TLV_IE, tag=0x83, nested=[RasConnectionParams, SecurityParams,
                                                     ExtendedSecurityParams, SessionRetryPolicyParams,
                                                     HttpPostParams]):
    pass

# Table 3-3 + Section 3.11.4
class RasFqdn(BER_TLV_IE, tag=0xD6):
    _construct = GreedyBytes # FIXME: DNS String

# Table 3-3 + Section 3.11.7
class DnsConnectionParams(BER_TLV_IE, tag=0xFA, nested=cat.OpenChannel.nested_collection_cls.possible_nested):
    pass

# Table 3-3
class DnsResolutionParams(BER_TLV_IE, tag=0xB3, nested=[RasFqdn, DnsConnectionParams]):
    pass

# Table 3-3
class AdmSessTriggerParams(BER_TLV_IE, tag=0x81, nested=[AdmSessionParams, DnsResolutionParams]):
    pass
