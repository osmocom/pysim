# Copyright (C) 2023 Harald Welte <laforge@osmocom.org>
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

from pySim.profile.ts_102_221 import CardProfileUICC
from pySim.commands import SimCardCommands
from pySim.euicc import CardApplicationISDR, AID_ISD_R, AID_ECASD, GetCertsReq, GetCertsResp

class CardProfileEuiccSGP32(CardProfileUICC):
    ORDER = 5

    def __init__(self):
        super().__init__(name='IoT eUICC (SGP.32)')

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        # try a command only supported by SGP.32
        scc.cla_byte = "00"
        scc.select_adf(AID_ISD_R)
        CardApplicationISDR.store_data_tlv(scc, GetCertsReq(), GetCertsResp)

class CardProfileEuiccSGP22(CardProfileUICC):
    ORDER = 6

    def __init__(self):
        super().__init__(name='Consumer eUICC (SGP.22)')

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        # try to read EID from ISD-R
        scc.cla_byte = "00"
        scc.select_adf(AID_ISD_R)
        eid = CardApplicationISDR.get_eid(scc)
        # TODO: Store EID identity?

class CardProfileEuiccSGP02(CardProfileUICC):
    ORDER = 7

    def __init__(self):
        super().__init__(name='M2M eUICC (SGP.02)')

    @classmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        scc.cla_byte = "00"
        scc.select_adf(AID_ECASD)
        scc.get_data(0x5a)
        # TODO: Store EID identity?
