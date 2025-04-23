# coding=utf-8
"""Utilities / Functions related to ISO 7816-4

(C) 2022 by Harald Welte <laforge@osmocom.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from construct import GreedyString
from osmocom.tlv import *
from osmocom.construct import *

# Table 91 + Section 8.2.1.2
class ApplicationId(BER_TLV_IE, tag=0x4f):
    _construct = GreedyBytes

# Table 91
class ApplicationLabel(BER_TLV_IE, tag=0x50):
    _construct = GreedyBytes

# Table 91 + Section 5.3.1.2
class FileReference(BER_TLV_IE, tag=0x51):
    _construct = GreedyBytes

# Table 91
class CommandApdu(BER_TLV_IE, tag=0x52):
    _construct = GreedyBytes

# Table 91
class DiscretionaryData(BER_TLV_IE, tag=0x53):
    _construct = GreedyBytes

# Table 91
class DiscretionaryTemplate(BER_TLV_IE, tag=0x73):
    _construct = GreedyBytes

# Table 91 + RFC1738 / RFC2396
class URL(BER_TLV_IE, tag=0x5f50):
    _construct = GreedyString('ascii')

# Table 91
class ApplicationRelatedDOSet(BER_TLV_IE, tag=0x61):
    _construct = GreedyBytes

# Section 8.2.1.3 Application Template
class ApplicationTemplate(BER_TLV_IE, tag=0x61, nested=[ApplicationId, ApplicationLabel, FileReference,
                          CommandApdu, DiscretionaryData, DiscretionaryTemplate, URL,
                          ApplicationRelatedDOSet]):
    pass
