# Implementation of SimAlliance/TCA Interoperable Profile OIDs
#
# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from typing import List, Union

class OID:
    @staticmethod
    def intlist_from_str(instr: str) -> List[int]:
        return [int(x) for x in instr.split('.')]

    @staticmethod
    def str_from_intlist(intlist: List[int]) -> str:
        return '.'.join([str(x) for x in intlist])

    def __init__(self, initializer: Union[List[int], str]):
        if isinstance(initializer, str):
            self.intlist = self.intlist_from_str(initializer)
        else:
            self.intlist = initializer

    def __str__(self) -> str:
        return self.str_from_intlist(self.intlist)

    def __repr__(self) -> str:
        return 'OID(%s)' % (str(self))


class eOID(OID):
    """OID helper for TCA eUICC prefix"""
    __prefix = [2,23,143,1]
    def __init__(self, initializer):
        if isinstance(initializer, str):
            initializer = self.intlist_from_str(initializer)
        super().__init__(self.__prefix + initializer)

MF = eOID("2.1")
DF_CD = eOID("2.2")
DF_TELECOM = eOID("2.3")
DF_TELECOM_v2 = eOID("2.3.2")
ADF_USIM_by_default = eOID("2.4")
ADF_USIM_by_default_v2 = eOID("2.4.2")
ADF_USIM_not_by_default = eOID("2.5")
ADF_USIM_not_by_default_v2 = eOID("2.5.2")
ADF_USIM_not_by_default_v3 = eOID("2.5.3")
DF_PHONEBOOK_ADF_USIM = eOID("2.6")
DF_GSM_ACCESS_ADF_USIM = eOID("2.7")
ADF_ISIM_by_default = eOID("2.8")
ADF_ISIM_not_by_default = eOID("2.9")
ADF_ISIM_not_by_default_v2 = eOID("2.9.2")
ADF_CSIM_by_default = eOID("2.10")
ADF_CSIM_by_default_v2 = eOID("2.10.2")
ADF_CSIM_not_by_default = eOID("2.11")
ADF_CSIM_not_by_default_v2 = eOID("2.11.2")
DF_EAP = eOID("2.12")
DF_5GS = eOID("2.13")
DF_5GS_v2 = eOID("2.13.2")
DF_5GS_v3 = eOID("2.13.3")
DF_5GS_v4 = eOID("2.13.4")
DF_SAIP = eOID("2.14")
DF_SNPN = eOID("2.15")
DF_5GProSe = eOID("2.16")
IoT_default = eOID("2.17")
IoT_default = eOID("2.18")
