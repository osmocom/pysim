# -*- coding: utf-8 -*-

# without this, pylint will fail when inner classes are used
# within the 'nested' kwarg of our TlvMeta metaclass on python 3.7 :(
# pylint: disable=undefined-variable

"""
DF_PHONEBOOK, DF_MULTIMEDIA as specified in 3GPP TS 31.102 V16.6.0
Needs to be a separate python module to avoid cyclic imports
"""

#
# Copyright (C) 2022 Harald Welte <laforge@osmocom.org>
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

from pySim.tlv import *
from pySim.filesystem import *
from pySim.construct import *
from construct import Optional as COptional
from construct import *

# TS 31.102 Section 4.4.2.1
class EF_PBR(LinFixedEF):
    def __init__(self, fid='4F30', name='EF.PBR', desc='Phone Book Reference', **kwargs):
        super().__init__(fid, name=name, desc=desc, **kwargs)
        #self._tlv = FIXME

# TS 31.102 Section 4.4.2.12.2
class EF_PSC(TransparentEF):
    _construct = Struct('synce_counter'/Int32ub)
    def __init__(self, fid='4F22', name='EF.PSC', desc='Phone Book Synchronization Counter', **kwargs):
        super().__init__(fid, name=name, desc=desc, **kwargs)
        #self._tlv = FIXME

# TS 31.102 Section 4.4.2.12.3
class EF_CC(TransparentEF):
    _construct = Struct('change_counter'/Int16ub)
    def __init__(self, fid='4F23', name='EF.CC', desc='Change Counter', **kwargs):
        super().__init__(fid, name=name, desc=desc, **kwargs)

# TS 31.102 Section 4.4.2.12.4
class EF_PUID(TransparentEF):
    _construct = Struct('previous_uid'/Int16ub)
    def __init__(self, fid='4F24', name='EF.PUID', desc='Previous Unique Identifer', **kwargs):
        super().__init__(fid, name=name, desc=desc, **kwargs)

# TS 31.102 Section 4.4.2
class DF_PHONEBOOK(CardDF):
    def __init__(self, fid='5F3A', name='DF.PHONEBOOK', desc='Phonebook', **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, **kwargs)
        files = [
            EF_PBR(),
            EF_PSC(),
            EF_CC(),
            EF_PUID(),
            # FIXME: Those 4Fxx entries with unspecified FID...
            ]
        self.add_files(files)



# TS 31.102 Section 4.6.3.1
class EF_MML(BerTlvEF):
    def __init__(self, fid='4F47', name='EF.MML', desc='Multimedia Messages List', **kwargs):
        super().__init__(fid, name=name, desc=desc, **kwargs)

# TS 31.102 Section 4.6.3.2
class EF_MMDF(BerTlvEF):
    def __init__(self, fid='4F48', name='EF.MMDF', desc='Multimedia Messages Data File', **kwargs):
        super().__init__(fid, name=name, desc=desc, **kwargs)

class DF_MULTIMEDIA(CardDF):
    def __init__(self, fid='5F3B', name='DF.MULTIMEDIA', desc='Multimedia', **kwargs):
        super().__init__(fid=fid, name=name, desc=desc, **kwargs)
        files = [
            EF_MML(),
            EF_MMDF(),
            ]
        self.add_files(files)
