# -*- coding: utf-8 -*-

""" pySim: card handler utilities.  A 'card handler' is some method
by which cards can be inserted/removed into the card reader.  For
normal smart card readers, this has to be done manually.  However,
there are also automatic card feeders.
"""

#
# (C) 2019 by Sysmocom s.f.m.c. GmbH
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

import subprocess
import sys
import yaml

from pySim.transport import LinkBase

class CardHandlerBase:
    """Abstract base class representing a mechanism for card insertion/removal."""

    def __init__(self, sl: LinkBase):
        self.sl = sl

    def get(self, first: bool = False):
        """Method called when pySim needs a new card to be inserted.

        Args:
                first : set to true when the get method is called the
                        first time. This is required to prevent blocking
                        when a card is already inserted into the reader.
                        The reader API would not recognize that card as
                        "new card" until it would be removed and re-inserted
                        again.
        """
        print("Ready for Programming: ", end='')
        self._get(first)

    def error(self):
        """Method called when pySim failed to program a card. Move card to 'bad' batch."""
        print("Programming failed: ", end='')
        self._error()

    def done(self):
        """Method called when pySim failed to program a card. Move card to 'good' batch."""
        print("Programming successful: ", end='')
        self._done()

    def _get(self, first: bool = False):
        pass

    def _error(self):
        pass

    def _done(self):
        pass


class CardHandler(CardHandlerBase):
    """Manual card handler: User is prompted to insert/remove card from the reader."""

    def _get(self, first: bool = False):
        print("Insert card now (or CTRL-C to cancel)")
        self.sl.wait_for_card(newcardonly=not first)

    def _error(self):
        print("Remove card from reader")
        print("")

    def _done(self):
        print("Remove card from reader")
        print("")


class CardHandlerAuto(CardHandlerBase):
    """Automatic card handler: A machine is used to handle the cards."""

    verbose = True

    def __init__(self, sl: LinkBase, config_file: str):
        super().__init__(sl)
        print("Card handler Config-file: " + str(config_file))
        with open(config_file) as cfg:
            self.cmds = yaml.load(cfg, Loader=yaml.FullLoader)
        self.verbose = self.cmds.get('verbose') is True

    def __print_outout(self, out):
        print("")
        print("Card handler output:")
        print("---------------------8<---------------------")
        stdout = out[0].strip()
        if len(stdout) > 0:
            print("stdout:")
            print(stdout)
        stderr = out[1].strip()
        if len(stderr) > 0:
            print("stderr:")
            print(stderr)
        print("---------------------8<---------------------")
        print("")

    def __exec_cmd(self, command):
        print("Card handler Commandline: " + str(command))

        proc = subprocess.Popen(
            [command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out = proc.communicate()
        rc = proc.returncode

        if rc != 0 or self.verbose:
            self.__print_outout(out)

        if rc != 0:
            print("")
            print("Error: Card handler failure! (rc=" + str(rc) + ")")
            sys.exit(rc)

    def _get(self, first: bool = False):
        print("Transporting card into the reader-bay...")
        self.__exec_cmd(self.cmds['get'])
        if self.sl:
            self.sl.connect()

    def _error(self):
        print("Transporting card to the error-bin...")
        self.__exec_cmd(self.cmds['error'])
        print("")

    def _done(self):
        print("Transporting card into the collector bin...")
        self.__exec_cmd(self.cmds['done'])
        print("")
