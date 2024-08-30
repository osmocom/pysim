# -*- coding: utf-8 -*-

""" pySim: Card programmation logic
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2011-2023  Harald Welte <laforge@gnumonks.org>
# Copyright (C) 2017 Alexander.Chemeris <Alexander.Chemeris@gmail.com>
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

from typing import Optional, Tuple
from osmocom.utils import *

from pySim.ts_102_221 import EF_DIR, CardProfileUICC
from pySim.ts_51_011 import DF_GSM
from pySim.utils import SwHexstr
from pySim.commands import Path, SimCardCommands

class CardBase:
    """General base class for some kind of telecommunications card."""
    def __init__(self, scc: SimCardCommands):
        self._scc = scc
        self._aids = []

    def reset(self) -> Optional[Hexstr]:
        rc = self._scc.reset_card()
        if rc == 1:
            return self._scc.get_atr()
        return None

    def set_apdu_parameter(self, cla: Hexstr, sel_ctrl: Hexstr) -> None:
        """Set apdu parameters (class byte and selection control bytes)"""
        self._scc.cla_byte = cla
        self._scc.sel_ctrl = sel_ctrl

    def get_apdu_parameter(self) -> Tuple[Hexstr, Hexstr]:
        """Get apdu parameters (class byte and selection control bytes)"""
        return (self._scc.cla_byte, self._scc.sel_ctrl)

    def erase(self):
        print("warning: erasing is not supported for specified card type!")

    def file_exists(self, fid: Path) -> bool:
        """Determine if the file exists (and is not deactivated)."""
        res_arr = self._scc.try_select_path(fid)
        for res in res_arr:
            if res[1] != '9000':
                return False
        try:
            d = CardProfileUICC.decode_select_response(res_arr[-1][0])
            if d.get('life_cycle_status_integer', 'operational_activated') != 'operational_activated':
                return False
        except:
            pass
        return True

    def read_aids(self) -> List[Hexstr]:
        # a non-UICC doesn't have any applications. Convenience helper to avoid
        # callers having to do hasattr('read_aids') ahead of every call.
        return []


class SimCardBase(CardBase):
    """Here we only add methods for commands specified in TS 51.011, without
    any higher-layer processing."""
    name = 'SIM'

    def __init__(self, scc: SimCardCommands):
        super().__init__(scc)
        self._scc.cla_byte = "A0"
        self._scc.sel_ctrl = "0000"

    def probe(self) -> bool:
        df_gsm = DF_GSM()
        return self.file_exists(df_gsm.fid)


class UiccCardBase(SimCardBase):
    name = 'UICC'

    def __init__(self, scc: SimCardCommands):
        super().__init__(scc)
        self._scc.cla_byte = "00"
        self._scc.sel_ctrl = "0004"  # request an FCP
        # See also: ETSI TS 102 221, Table 9.3
        self._adm_chv_num = 0x0A

    def probe(self) -> bool:
        # EF.DIR is a mandatory EF on all ICCIDs; however it *may* also exist on a TS 51.011 SIM
        ef_dir = EF_DIR()
        return self.file_exists(ef_dir.fid)

    def read_aids(self) -> List[Hexstr]:
        """Fetch all the AIDs present on UICC"""
        self._aids = []
        try:
            ef_dir = EF_DIR()
            # Find out how many records the EF.DIR has
            # and store all the AIDs in the UICC
            rec_cnt = self._scc.record_count(ef_dir.fid)
            for i in range(0, rec_cnt):
                rec = self._scc.read_record(ef_dir.fid, i + 1)
                if (rec[0][0:2], rec[0][4:6]) == ('61', '4f') and len(rec[0]) > 12 \
                        and rec[0][8:8 + int(rec[0][6:8], 16) * 2] not in self._aids:
                    self._aids.append(rec[0][8:8 + int(rec[0][6:8], 16) * 2])
        except Exception as e:
            print("Can't read AIDs from SIM -- %s" % (str(e),))
            self._aids = []
        return self._aids

    @staticmethod
    def _get_aid(adf="usim") -> Optional[Hexstr]:
        aid_map = {}
        # First (known) halves of the U/ISIM AID
        aid_map["usim"] = "a0000000871002"
        aid_map["isim"] = "a0000000871004"
        adf = adf.lower()
        if adf in aid_map:
            return aid_map[adf]
        return None

    def _complete_aid(self, aid: Hexstr) -> Optional[Hexstr]:
        """find the complete version of an ADF.U/ISIM AID"""
        # Find full AID by partial AID:
        if is_hex(aid):
            for aid_known in self._aids:
                if len(aid_known) >= len(aid) and aid == aid_known[0:len(aid)]:
                    return aid_known
        return None

    def adf_present(self, adf: str = "usim") -> bool:
        """Check if the AID of the specified ADF is present in EF.DIR (call read_aids before use)"""
        aid = self._get_aid(adf)
        if aid:
            aid_full = self._complete_aid(aid)
            if aid_full:
                return True
        return False

    def select_adf_by_aid(self, adf: str = "usim", scc: Optional[SimCardCommands] = None) -> Tuple[Optional[Hexstr], Optional[SwHexstr]]:
        """Select ADF.U/ISIM in the Card using its full AID"""
        # caller may pass a custom scc; we fall back to default
        scc = scc or self._scc
        if is_hex(adf):
            aid = adf
        else:
            aid = self._get_aid(adf)
        if aid:
            aid_full = self._complete_aid(aid)
            if aid_full:
                return scc.select_adf(aid_full)
            # If we cannot get the full AID, try with short AID
            return scc.select_adf(aid)
        return (None, None)

def card_detect(scc: SimCardCommands) -> Optional[CardBase]:
    # UICC always has higher preference, as a UICC might also contain a SIM application
    uicc = UiccCardBase(scc)
    if uicc.probe():
        return uicc

    # this is for detecting a real, classic TS 11.11 SIM card without any UICC support
    sim = SimCardBase(scc)
    if sim.probe():
        return sim

    return None
