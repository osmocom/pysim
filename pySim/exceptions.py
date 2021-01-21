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

from __future__ import absolute_import

try:
	# This is for compatibility with python 2 and 3
	from exceptions import Exception
except:
	pass

class NoCardError(Exception):
	pass

class ProtocolError(Exception):
	pass

class ReaderError(Exception):
	pass

class SwMatchError(Exception):
	"""Raised when an operation specifies an expected SW but the actual SW from
	   the card doesn't match."""
	def __init__(self, sw_actual, sw_expected):
		self.sw_actual = sw_actual
		self.sw_expected = sw_expected
	def __str__(self):
		return "SW match failed! Expected %s and got %s." % (self.sw_expected, self.sw_actual)
