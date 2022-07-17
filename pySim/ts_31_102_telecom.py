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

# TS 31.102 Section 4.2.8
class EF_UServiceTable(TransparentEF):
    def __init__(self, fid, sfid, name, desc, size, table, **kwargs):
        super().__init__(fid=fid, sfid=sfid, name=name, desc=desc, size=size, **kwargs)
        self.table = table

    @staticmethod
    def _bit_byte_offset_for_service(service: int) -> Tuple[int, int]:
        i = service - 1
        byte_offset = i//8
        bit_offset = (i % 8)
        return (byte_offset, bit_offset)

    def _decode_bin(self, in_bin):
        ret = {}
        for i in range(0, len(in_bin)):
            byte = in_bin[i]
            for bitno in range(0, 8):
                service_nr = i * 8 + bitno + 1
                ret[service_nr] = {
                    'activated': True if byte & (1 << bitno) else False
                }
                if service_nr in self.table:
                    ret[service_nr]['description'] = self.table[service_nr]
        return ret

    def _encode_bin(self, in_json):
        # compute the required binary size
        bin_len = 0
        for srv in in_json.keys():
            service_nr = int(srv)
            (byte_offset, bit_offset) = EF_UServiceTable._bit_byte_offset_for_service(
                service_nr)
            if byte_offset >= bin_len:
                bin_len = byte_offset+1
        # encode the actual data
        out = bytearray(b'\x00' * bin_len)
        for srv in in_json.keys():
            service_nr = int(srv)
            (byte_offset, bit_offset) = EF_UServiceTable._bit_byte_offset_for_service(
                service_nr)
            if in_json[srv]['activated'] == True:
                bit = 1
            else:
                bit = 0
            out[byte_offset] |= (bit) << bit_offset
        return out

    def get_active_services(self, cmd):
        # obtain list of currently active services
        (service_data, sw) = cmd.lchan.read_binary_dec()
        active_services = []
        for s in service_data.keys():
            if service_data[s]['activated']:
                active_services.append(s)
        return active_services

    def ust_service_check(self, cmd):
        """Check consistency between services of this file and files present/activated"""
        num_problems = 0
        # obtain list of currently active services
        active_services = self.get_active_services(cmd)
        # iterate over all the service-constraints we know of
        files_by_service = self.parent.files_by_service
        try:
            for s in sorted(files_by_service.keys()):
                active_str = 'active' if s in active_services else 'inactive'
                cmd.poutput("Checking service No %u (%s)" % (s, active_str))
                for f in files_by_service[s]:
                    should_exist = f.should_exist_for_services(active_services)
                    try:
                        cmd.lchan.select_file(f)
                        sw = None
                        exists = True
                    except SwMatchError as e:
                        sw = str(e)
                        exists = False
                    if exists != should_exist:
                        num_problems += 1
                        if exists:
                            cmd.perror("  ERROR: File %s is selectable but should not!" % f)
                        else:
                            cmd.perror("  ERROR: File %s is not selectable (%s) but should!" %  (f, sw))
        finally:
            # re-select the EF.UST
            cmd.lchan.select_file(self)
        return num_problems



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
