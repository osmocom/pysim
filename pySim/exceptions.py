# -*- coding: utf-8 -*-

""" pySim: Exceptions
"""

#
# Copyright (C) 2009-2010  Sylvain Munaut <tnt@246tNt.com>
# Copyright (C) 2021 Harald Welte <laforge@osmocom.org>
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


class NoCardError(Exception):
    """No card was found in the reader."""


class ProtocolError(Exception):
    """Some kind of protocol level error interfacing with the card."""


class ReaderError(Exception):
    """Some kind of general error with the card reader."""


class SwMatchError(Exception):
    """Raised when an operation specifies an expected SW but the actual SW from
       the card doesn't match."""

    def __init__(self, sw_actual: str, sw_expected: str, rs=None):
        """
        Args:
                sw_actual : the SW we actually received from the card (4 hex digits)
                sw_expected : the SW we expected to receive from the card (4 hex digits)
                rs : interpreter class to convert SW to string
        """
        self.sw_actual = sw_actual
        self.sw_expected = sw_expected
        self.rs = rs

    @property
    def description(self):
        if self.rs and self.rs.lchan[0]:
            r = self.rs.lchan[0].interpret_sw(self.sw_actual)
            if r:
                return "%s - %s" % (r[0], r[1])
        return ''

    def __str__(self):
        description = self.description
        if description:
            description = ": " + description
        else:
            description = "."
        return "SW match failed! Expected %s and got %s%s" % (self.sw_expected, self.sw_actual, description)
