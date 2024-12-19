# GlobalPlatform install parameter generator
#
# (C) 2024 by Sysmocom s.f.m.c. GmbH
# All Rights Reserved
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

from osmocom.construct import *
from osmocom.utils import *
from osmocom.tlv import *

class AppSpecificParams(BER_TLV_IE, tag=0xC9):
    # GPD_SPE_013, table 11-49
    _construct = HexAdapter(GreedyBytes)

class VolatileMemoryQuota(BER_TLV_IE, tag=0xC7):
    # GPD_SPE_013, table 11-49
    _construct = StripHeaderAdapter(GreedyBytes, 4, steps = [2,4])

class NonVolatileMemoryQuota(BER_TLV_IE, tag=0xC8):
    # GPD_SPE_013, table 11-49
    _construct = StripHeaderAdapter(GreedyBytes, 4, steps = [2,4])

class StkParameter(BER_TLV_IE, tag=0xCA):
    # GPD_SPE_013, table 11-49
    # ETSI TS 102 226, section 8.2.1.3.2.1
    _construct = HexAdapter(GreedyBytes)

class SystemSpecificParams(BER_TLV_IE, tag=0xEF, nested=[VolatileMemoryQuota, NonVolatileMemoryQuota, StkParameter]):
    # GPD_SPE_013 v1.1 Table 6-5
    pass

class InstallParams(TLV_IE_Collection, nested=[AppSpecificParams, SystemSpecificParams]):
    # GPD_SPE_013, table 11-49
    pass

def gen_install_parameters(non_volatile_memory_quota:int, volatile_memory_quota:int, stk_parameter:str):

    # GPD_SPE_013, table 11-49

    #Mandatory
    install_params = InstallParams()
    install_params_dict = [{'app_specific_params': None}]

    #Conditional
    if non_volatile_memory_quota and volatile_memory_quota and stk_parameter:
        system_specific_params = []
        #Optional
        if non_volatile_memory_quota:
            system_specific_params += [{'non_volatile_memory_quota': non_volatile_memory_quota}]
        #Optional
        if volatile_memory_quota:
            system_specific_params += [{'volatile_memory_quota': volatile_memory_quota}]
        #Optional
        if stk_parameter:
            system_specific_params += [{'stk_parameter': stk_parameter}]
        install_params_dict += [{'system_specific_params': system_specific_params}]

    install_params.from_dict(install_params_dict)
    return b2h(install_params.to_bytes())
