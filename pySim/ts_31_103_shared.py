"""
Definitions from 3GPP TS 31.103 V18.1.0 which are shared by both USIM (31.102) and ISIM (31.103) and
hence need to be in a separate python module to avoid circular dependencies.
"""

# Copyright (C) 2021-2024 Harald Welte <laforge@osmocom.org>
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

from construct import Struct, Switch, GreedyString, Int8ub, Prefixed, Enum, Byte
from osmocom.tlv import BER_TLV_IE, TLV_IE_Collection
from osmocom.construct import Bytes, HexAdapter, Utf8Adapter, GreedyBytes
from pySim.filesystem import *

# TS 31.103 Section 4.2.16
class EF_UICCIARI(LinFixedEF):
    class iari(BER_TLV_IE, tag=0x80):
        _construct = Utf8Adapter(GreedyBytes)

    def __init__(self, fid='6fe7', sfid=None, name='EF.UICCIARI', desc='UICC IARI', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_UICCIARI.iari

# TS 31.103 Section 4.2.18
class EF_IMSConfigData(BerTlvEF):
    class ImsConfigDataEncoding(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(Bytes(1))
    class ImsConfigData(BER_TLV_IE, tag=0x81):
        _construct = GreedyString
    # pylint: disable=undefined-variable
    class ImsConfigDataCollection(TLV_IE_Collection, nested=[ImsConfigDataEncoding, ImsConfigData]):
        pass
    def __init__(self, fid='6ff8', sfid=None, name='EF.IMSConfigData', desc='IMS Configuration Data', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_IMSConfigData.ImsConfigDataCollection

# TS 31.103 Section 4.2.19
class EF_XCAPConfigData(BerTlvEF):
    class Access(BER_TLV_IE, tag=0x81):
        pass
    class ApplicationName(BER_TLV_IE, tag=0x82):
        pass
    class ProviderID(BER_TLV_IE, tag=0x83):
        pass
    class URI(BER_TLV_IE, tag=0x84):
        pass
    class XcapAuthenticationUserName(BER_TLV_IE, tag=0x85):
        pass
    class XcapAuthenticationPassword(BER_TLV_IE, tag=0x86):
        pass
    class XcapAuthenticationType(BER_TLV_IE, tag=0x87):
        pass
    class AddressType(BER_TLV_IE, tag=0x88):
        pass
    class Address(BER_TLV_IE, tag=0x89):
        pass
    class PDPAuthenticationType(BER_TLV_IE, tag=0x8a):
        pass
    class PDPAuthenticationName(BER_TLV_IE, tag=0x8b):
        pass
    class PDPAuthenticationSecret(BER_TLV_IE, tag=0x8c):
        pass

    class AccessForXCAP(BER_TLV_IE, tag=0x81):
        pass
    class NumberOfXcapConnParPolicy(BER_TLV_IE, tag=0x82):
        _construct = Int8ub
    # pylint: disable=undefined-variable
    class XcapConnParamsPolicyPart(BER_TLV_IE, tag=0xa1, nested=[Access, ApplicationName, ProviderID, URI,
                                 XcapAuthenticationUserName, XcapAuthenticationPassword,
                                 XcapAuthenticationType, AddressType, Address, PDPAuthenticationType,
                                 PDPAuthenticationName, PDPAuthenticationSecret]):
        pass
    class XcapConnParamsPolicy(BER_TLV_IE, tag=0xa0, nested=[AccessForXCAP, NumberOfXcapConnParPolicy, XcapConnParamsPolicyPart]):
        pass
    class XcapConnParamsPolicyDO(BER_TLV_IE, tag=0x80, nested=[XcapConnParamsPolicy]):
        pass
    def __init__(self, fid='6ffc', sfid=None, name='EF.XCAPConfigData', desc='XCAP Configuration Data', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_XCAPConfigData.XcapConnParamsPolicy

# TS 31.103 Section 4.2.20
class EF_WebRTCURI(LinFixedEF):
    class uri(BER_TLV_IE, tag=0x80):
        _construct = Utf8Adapter(GreedyBytes)

    def __init__(self, fid='6ffa', sfid=None, name='EF.WebRTCURI', desc='WebRTC URI', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_WebRTCURI.uri

# TS 31.103 Section 4.2.21
class EF_MuDMiDConfigData(BerTlvEF):
    class MudMidConfigDataEncoding(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(Bytes(1))
    class MudMidConfigData(BER_TLV_IE, tag=0x81):
        _construct = GreedyString
    # pylint: disable=undefined-variable
    class MudMidConfigDataCollection(TLV_IE_Collection, nested=[MudMidConfigDataEncoding, MudMidConfigData]):
        pass
    def __init__(self, fid='6ffe', sfid=None, name='EF.MuDMiDConfigData',
                 desc='MuD and MiD Configuration Data', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_MuDMiDConfigData.MudMidConfigDataCollection

# TS 31.103 Section 4.2.22
class EF_AC_GBAUAPI(LinFixedEF):
    """The use of this EF is eescribed in 3GPP TS 31.130"""
    class AppletNafAccessControl(BER_TLV_IE, tag=0x80):
        # the use of Int8ub as length field in Prefixed is strictly speaking incorrect, as it is a BER-TLV
        # length field whihc will consume two bytes from length > 127 bytes.  However, AIDs and NAF IDs can
        # safely be assumed shorter than that
        _construct = Struct('aid'/Prefixed(Int8ub, GreedyBytes),
                            'naf_id'/Prefixed(Int8ub, GreedyBytes))
    def __init__(self, fid='6f0a', sfid=None, name='EF.GBAUAPI',
                 desc='Access Control to GBA_U_API', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._tlv = EF_AC_GBAUAPI.AppletNafAccessControl

# TS 31.103 Section 4.2.23
class EF_IMSDCI(TransparentEF):
    """See Management object as defined in 3GPP TS 24.275."""
    def __init__(self, fid='6f0b', sfid=None, name='EF.IMSDCI', desc='IMS Data Channel Indication', **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, **kwargs)
        self._construct = Enum(Byte, ims_dc_not_allowed=0x00,
                                     ims_dc_allowed_after_ims_session=0x01,
                                     ims_dc_allowed_simultaneous_ims_session=0x02)
