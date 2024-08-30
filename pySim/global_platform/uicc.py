# coding=utf-8
"""GlobalPLatform UICC Configuration 1.0 parameters

(C) 2024 by Harald Welte <laforge@osmocom.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from construct import Optional as COptional
from construct import Struct, GreedyRange, FlagsEnum, Int16ub, Int24ub, Padding, Bit, Const
from osmocom.construct import *
from osmocom.utils import *
from osmocom.tlv import *

# Section 11.6.2.3 / Table 11-58
class SecurityDomainAid(BER_TLV_IE, tag=0x4f):
    _construct = GreedyBytes
class LoadFileDataBlockSignature(BER_TLV_IE, tag=0xc3):
    _construct = GreedyBytes
class DapBlock(BER_TLV_IE, tag=0xe2, nested=[SecurityDomainAid, LoadFileDataBlockSignature]):
    pass
class LoadFileDataBlock(BER_TLV_IE, tag=0xc4):
    _construct = GreedyBytes
class Icv(BER_TLV_IE, tag=0xd3):
    _construct = GreedyBytes
class CipheredLoadFileDataBlock(BER_TLV_IE, tag=0xd4):
    _construct = GreedyBytes
class LoadFile(TLV_IE_Collection, nested=[DapBlock, LoadFileDataBlock, Icv, CipheredLoadFileDataBlock]):
    pass

# UICC Configuration v1.0.1 / Section 4.3.2
class UiccScp(BER_TLV_IE, tag=0x81):
    _construct = Struct('scp'/Int8ub, 'i'/Int8ub)

class AcceptExtradAppsAndElfToSd(BER_TLV_IE, tag=0x82):
    _construct = GreedyBytes

class AcceptDelOfAssocSd(BER_TLV_IE, tag=0x83):
    _construct = GreedyBytes

class LifeCycleTransitionToPersonalized(BER_TLV_IE, tag=0x84):
    _construct = GreedyBytes

class CasdCapabilityInformation(BER_TLV_IE, tag=0x86):
    _construct = GreedyBytes

class AcceptExtradAssocAppsAndElf(BER_TLV_IE, tag=0x87):
    _construct = GreedyBytes

# Security Domain Install Parameters (inside C9 during INSTALL [for install])
class UiccSdInstallParams(TLV_IE_Collection, nested=[UiccScp, AcceptExtradAppsAndElfToSd, AcceptDelOfAssocSd,
                                                     LifeCycleTransitionToPersonalized,
                                                     CasdCapabilityInformation, AcceptExtradAssocAppsAndElf]):
    def has_scp(self, scp: int) -> bool:
        """Determine if SD Installation parameters already specify given SCP."""
        for c in self.children:
            if not isinstance(c, UiccScp):
                continue
            if c.decoded['scp'] == scp:
                return True
        return False

    def add_scp(self, scp: int, i: int):
        """Add given SCP (and i parameter) to list of SCP of the Security Domain Install Params.
        Example: add_scp(0x03, 0x70) for SCP03, or add_scp(0x02, 0x55) for SCP02."""
        if self.has_scp(scp):
            raise ValueError('SCP%02x already present' % scp)
        self.children.append(UiccScp(decoded={'scp': scp, 'i': i}))

    def remove_scp(self, scp: int):
        """Remove given SCP from list of SCP of the Security Domain Install Params."""
        for c in self.children:
            if not isinstance(c, UiccScp):
                continue
            if c.decoded['scp'] == scp:
                self.children.remove(c)
                return
        raise ValueError("SCP%02x not present" % scp)


# Key Usage:
# KVN 0x01 .. 0x0F reserved for SCP80
# KVN 0x11 reserved for DAP specified in ETSI TS 102 226
# KVN 0x20 .. 0x2F reserved for SCP02
#   KID 0x01 = ENC; 0x02 = MAC; 0x03 = DEK
# KVN 0x30 .. 0x3F reserved for SCP03
#   KID 0x01 = ENC; 0x02 = MAC; 0x03 = DEK
# KVN 0x70 KID 0x01: Token key (RSA public or DES)
# KVN 0x71 KID 0x01: Receipt key (DES)
# KVN 0x73 KID 0x01: DAP verifiation key (RS public or DES)
# KVN 0x74 reserved for CASD
#   KID 0x01: PK.CA.AUT
#   KID 0x02: SK.CASD.AUT (PK) and KS.CASD.AUT (Non-PK)
#   KID 0x03: SK.CASD.CT (P) and KS.CASD.CT (Non-PK)
# KVN 0x75 KID 0x01: 16-byte DES key for  Ciphered Load File Data Block
# KVN 0xFF reserved for ISD with SCP02 without SCP80 s upport
