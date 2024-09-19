# -*- coding: utf-8 -*-

""" pySim: tell old 2G SIMs apart from UICC
"""

#
# (C) 2021 by Sysmocom s.f.m.c. GmbH
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

import abc
import operator
from typing import List

from pySim.exceptions import SwMatchError
from pySim.commands import SimCardCommands
from pySim.filesystem import CardApplication, interpret_sw
from pySim.utils import all_subclasses

class CardProfile:
    """A Card Profile describes a card, it's filesystem hierarchy, an [initial] list of
    applications as well as profile-specific SW and shell commands.  Every card has
    one card profile, but there may be multiple applications within that profile."""

    def __init__(self, name, **kw):
        """
        Args:
                desc (str) : Description
                files_in_mf : List of CardEF instances present in MF
                applications : List of CardApplications present on card
                sw : List of status word definitions
                shell_cmdsets : List of cmd2 shell command sets of profile-specific commands
                cla : class byte that should be used with cards of this profile
                sel_ctrl : selection control bytes class byte that should be used with cards of this profile
                addons: List of optional CardAddons that a card of this profile might have
        """
        self.name = name
        self.desc = kw.get("desc", None)
        self.files_in_mf = kw.get("files_in_mf", [])
        self.sw = kw.get("sw", {})
        self.applications = kw.get("applications", [])
        self.shell_cmdsets = kw.get("shell_cmdsets", [])
        self.cla = kw.get("cla", "00")
        self.sel_ctrl = kw.get("sel_ctrl", "0004")
        # list of optional addons that a card of this profile might have
        self.addons = kw.get("addons", [])

    def __str__(self):
        return self.name

    def add_application(self, app: CardApplication):
        """Add an application to a card profile.

        Args:
                app : CardApplication instance to be added to profile
        """
        self.applications.append(app)

    def interpret_sw(self, sw: str):
        """Interpret a given status word within the profile.

        Args:
                sw : Status word as string of 4 hex digits

        Returns:
                Tuple of two strings
        """
        return interpret_sw(self.sw, sw)

    @staticmethod
    def decode_select_response(data_hex: str) -> object:
        """Decode the response to a SELECT command.

        This is the fall-back method which doesn't perform any decoding. It mostly
        exists so specific derived classes can overload it for actual decoding.
        This method is implemented in the profile and is only used when application
        specific decoding cannot be performed (no ADF is selected).

        Args:
                data_hex: Hex string of the select response
        """
        return data_hex

    @staticmethod
    def _mf_select_test(scc: SimCardCommands,
                        cla_byte: str, sel_ctrl: str,
                        fids: List[str]) -> bool:
        """Helper function used by some derived _try_match_card() methods."""
        scc.reset_card()

        scc.cla_byte = cla_byte
        scc.sel_ctrl = sel_ctrl
        for fid in fids:
            scc.select_file(fid)

    @classmethod
    @abc.abstractmethod
    def _try_match_card(cls, scc: SimCardCommands) -> None:
        """Try to see if the specific profile matches the card. This method is a
        placeholder that is overloaded by specific dirived classes. The method
        actively probes the card to make sure the profile class matches the
        physical card. This usually also means that the card is reset during
        the process, so this method must not be called at random times. It may
        only be called on startup.  If there is no exception raised, we assume
        the card matches the profile.

        Args:
                scc: SimCardCommands class
        """
        pass

    @classmethod
    def match_with_card(cls, scc: SimCardCommands) -> bool:
        """Check if the specific profile matches the card. The method
        actively probes the card to make sure the profile class matches the
        physical card. This usually also means that the card is reset during
        the process, so this method must not be called at random times. It may
        only be called on startup.

        Args:
                scc: SimCardCommands class
        Returns:
                match = True, no match = False
        """
        sel_backup = scc.sel_ctrl
        cla_backup = scc.cla_byte
        try:
            cls._try_match_card(scc)
            return True
        except SwMatchError:
            return False
        finally:
            scc.sel_ctrl = sel_backup
            scc.cla_byte = cla_backup
            scc.reset_card()

    @staticmethod
    def pick(scc: SimCardCommands):
        profiles = list(all_subclasses(CardProfile))
        profiles.sort(key=operator.attrgetter('ORDER'))

        for p in profiles:
            if p.match_with_card(scc):
                return p()

        return None

    def add_addon(self, addon: 'CardProfileAddon'):
        assert addon not in self.addons
        # we don't install any additional files, as that is happening in the RuntimeState.
        self.addons.append(addon)

class CardProfileAddon(abc.ABC):
    """A Card Profile Add-on is something that is not a card application or a full stand-alone
    card profile, but an add-on to an existing profile.  Think of GSM-R specific files existing
    on what is otherwise a SIM or USIM+SIM card."""

    def __init__(self, name: str, **kw):
        """
        Args:
                desc (str) : Description
                files_in_mf : List of CardEF instances present in MF
                shell_cmdsets : List of cmd2 shell command sets of profile-specific commands
        """
        self.name = name
        self.desc = kw.get("desc", None)
        self.files_in_mf = kw.get("files_in_mf", [])
        self.shell_cmdsets = kw.get("shell_cmdsets", [])

    def __str__(self):
        return self.name

    @abc.abstractmethod
    def probe(self, card: 'CardBase') -> bool:
        """Probe a given card to determine whether or not this add-on is present/supported."""
