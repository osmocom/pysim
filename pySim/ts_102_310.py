# coding=utf-8
"""Utilities / Functions related to ETSI TS 102 310, the EAP UICC spec.

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

from construct import *
from construct import Optional as COptional
from osmocom.construct import *

from osmocom.tlv import BER_TLV_IE, TLV_IE_Collection
from pySim.filesystem import CardDF, TransparentEF

# TS102 310 Section 7.1
class EF_EAPKEYS(TransparentEF):
    class Msk(BER_TLV_IE, tag=0x80):
        _construct = HexAdapter(GreedyBytes)
    class Emsk(BER_TLV_IE, tag=0x81):
        _construct = HexAdapter(GreedyBytes)
    class MskCollection(TLV_IE_Collection, nested=[EF_EAPKEYS.Msk, EF_EAPKEYS.Emsk]):
        pass

    def __init__(self, fid='4f01', name='EF.EAPKEYS', desc='EAP derived keys'):
        super().__init__(fid, sfid=0x01, name=name, desc=desc, size=(1,None))
        self._tlv = EF_EAPKEYS.MskCollection

# TS 102 310 Section 7.2
class EF_EAPSTATUS(TransparentEF):
    def __init__(self, fid='4f02', name='EF.EAPSTATUS', desc='EAP Authentication Status'):
        super().__init__(fid, sfid=0x02, name=name, desc=desc, size=(1,1))
        self._construct = Enum(Int8ub, no_auth_started=0, authenticating=1,
                               authenticated=2, held_auth_failure=3)

# TS 102 310 Section 7.3
class EF_PUId(TransparentEF):
    def __init__(self, fid='4f03', name='EF.PUId', desc='Permanent User Identity'):
        super().__init__(fid, sfid=0x03, name=name, desc=desc, size=(10,None))
        self._construct = GreedyBytes

# TS 102 310 Section 7.4
class EF_Ps(TransparentEF):
    def __init__(self, fid='4f04', name='EF.Ps', desc='Pseudonym'):
        super().__init__(fid, sfid=0x04, name=name, desc=desc, size=(1,None))
        self._construct = GreedyBytes

# TS 102 310 Section 7.5
class EF_CurID(TransparentEF):
    def __init__(self, fid='4f20', name='EF.CurID', desc='Current Identity'):
        super().__init__(fid, sfid=0x10, name=name, desc=desc, size=(1,None))
        self._construct = Struct('type'/Enum(Int8ub, permanent=0, pseudonym=1, re_authentication=2, should_not_be_revealed=255),
                                 '_len'/Int8ub,
                                 'value'/Utf8Adapter(this._len))


# TS 102 310 Section 7.6
class EF_ReID(TransparentEF):
    class Identity(BER_TLV_IE, tag=0x80):
        _construct = Utf8Adapter(GreedyBytes)
    class Counter(BER_TLV_IE, tag=0x81):
        _construct = GreedyInteger
    class Collection(TLV_IE_Collection, nested=[EF_ReID.Identity, EF_ReID.Counter]):
        pass

    def __init__(self, fid='4f21', name='EF.ReID', desc='Re-Authentication Identity'):
        super().__init__(fid, sfid=0x11, name=name, desc=desc, size=(1,None))
        self._tlv = EF_ReID.Collection

# TS 102 310 Section 7.7
class EF_Realm(TransparentEF):
    def __init__(self, fid='4f22', name='EF.Realm', desc='Relm value of the identity'):
        super().__init__(fid, sfid=0x12, name=name, desc=desc, size=(1,None))
        self._construct = Struct('_len'/Int8ub,
                                 'realm'/Utf8Adapter(Bytes(this._len)))

class DF_EAP(CardDF):
    # DF.EAP has no default FID; it always must be discovered via the EF.DIR entry
    # and the 0x73 "discretionary template"
    def __init__(self, fid, name='DF.EAP', desc='EAP client', **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, **kwargs)
        files = [
            EF_EAPKEYS(),
            EF_EAPSTATUS(),
            EF_PUId(),
            EF_CurID(),
            EF_ReID(),
        ]
        self.add_files(files)


# TS 102 310 Section 5.2
class EapSupportedTypesList(BER_TLV_IE, tag=0x80):
    _construct = GreedyRange(Int8ub)
class EapDedicatedFilesList(BER_TLV_IE, tag=0x81):
    _construct = GreedyRange(Int16ub)
class EapLabel(BER_TLV_IE, tag=0x82):
    _construct = GreedyBytes
class EapAppSvcSpecData(BER_TLV_IE, tag=0xa0, nested=[EapSupportedTypesList, EapDedicatedFilesList, EapLabel]):
    pass
class DiscretionaryTemplate(BER_TLV_IE, tag=0x73, nested=[EapAppSvcSpecData]):
    pass
