# (C) 2021-2023 by Harald Welte <laforge@osmocom.org>
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


from typing import Tuple

from pySim.transport import LinkBase
from pySim.commands import SimCardCommands
from pySim.filesystem import CardModel, CardApplication
from pySim.cards import card_detect, SimCardBase, UiccCardBase
from pySim.runtime import RuntimeState
from pySim.profile import CardProfile
from pySim.cdma_ruim import CardProfileRUIM
from pySim.ts_102_221 import CardProfileUICC
from pySim.utils import all_subclasses
from pySim.exceptions import SwMatchError

# we need to import this module so that the SysmocomSJA2 sub-class of
# CardModel is created, which will add the ATR-based matching and
# calling of SysmocomSJA2.add_files.  See  CardModel.apply_matching_models
import pySim.sysmocom_sja2

# we need to import these modules so that the various sub-classes of
# CardProfile are created, which will be used in init_card() to iterate
# over all known CardProfile sub-classes.
import pySim.ts_31_102
import pySim.ts_31_103
import pySim.ts_31_104
import pySim.ara_m
import pySim.global_platform
import pySim.euicc

def init_card(sl: LinkBase) -> Tuple[RuntimeState, SimCardBase]:
    """
    Detect card in reader and setup card profile and runtime state. This
    function must be called at least once on startup. The card and runtime
    state object (rs) is required for all pySim-shell commands.
    """

    # Create command layer
    scc = SimCardCommands(transport=sl)

    # Wait up to three seconds for a card in reader and try to detect
    # the card type.
    print("Waiting for card...")
    sl.wait_for_card(3)

    generic_card = False
    card = card_detect(scc)
    if card is None:
        print("Warning: Could not detect card type - assuming a generic card type...")
        card = SimCardBase(scc)
        generic_card = True

    profile = CardProfile.pick(scc)
    if profile is None:
        # It is not an unrecoverable error in case profile detection fails. It
        # just means that pySim was unable to recognize the card profile. This
        # may happen in particular with unprovisioned cards that do not have
        # any files on them yet.
        print("Unsupported card type!")
        return None, card

    # ETSI TS 102 221, Table 9.3 specifies a default for the PIN key
    # references, however card manufactures may still decide to pick an
    # arbitrary key reference. In case we run on a generic card class that is
    # detected as an UICC, we will pick the key reference that is officially
    # specified.
    if generic_card and isinstance(profile, CardProfileUICC):
        card._adm_chv_num = 0x0A

    print("Info: Card is of type: %s" % str(profile))

    # FIXME: this shouldn't really be here but somewhere else/more generic.
    # We cannot do it within pySim/profile.py as that would create circular
    # dependencies between the individual profiles and profile.py.
    if isinstance(profile, CardProfileUICC):
        for app_cls in all_subclasses(CardApplication):
            # skip any intermediary sub-classes such as CardApplicationSD
            if hasattr(app_cls, '_' + app_cls.__name__ + '__intermediate'):
                continue
            profile.add_application(app_cls())
        # We have chosen SimCard() above, but we now know it actually is an UICC
        # so it's safe to assume it supports USIM application (which we're adding above).
        # IF we don't do this, we will have a SimCard but try USIM specific commands like
        # the update_ust method (see https://osmocom.org/issues/6055)
        if generic_card:
            card = UiccCardBase(scc)

    # Create runtime state with card profile
    rs = RuntimeState(card, profile)

    CardModel.apply_matching_models(scc, rs)

    # inform the transport that we can do context-specific SW interpretation
    sl.set_sw_interpreter(rs)

    # try to obtain the EID, if any
    isd_r = rs.mf.applications.get(pySim.euicc.AID_ISD_R.lower(), None)
    if isd_r:
        rs.lchan[0].select_file(isd_r)
        try:
            rs.identity['EID'] = pySim.euicc.CardApplicationISDR.get_eid(scc)
        except SwMatchError:
            # has ISD-R but not a SGP.22/SGP.32 eUICC - maybe SGP.02?
            pass
        finally:
            rs.reset()

    return rs, card
