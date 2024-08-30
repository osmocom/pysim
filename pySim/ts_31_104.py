# -*- coding: utf-8 -*-

"""
Support for 3GPP TS 31.104 V17.0.0
"""

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
#

from osmocom.utils import *
from osmocom.tlv import *
from pySim.filesystem import *
from pySim.ts_31_102 import ADF_USIM
from pySim.ts_51_011 import EF_IMSI, EF_AD
import pySim.ts_102_221
from pySim.ts_102_221 import EF_ARR


class ADF_HPSIM(CardADF):
    def __init__(self, aid='a000000087100A', has_fs=True, name='ADF.HPSIM', fid=None, sfid=None,
                 desc='HPSIM Application'):
        super().__init__(aid=aid, has_fs=has_fs, fid=fid, sfid=sfid, name=name, desc=desc)

        files = [
            EF_ARR(fid='6f06', sfid=0x06),
            EF_IMSI(fid='6f07', sfid=0x07),
            EF_AD(fid='6fad', sfid=0x03),
        ]
        self.add_files(files)
        # add those commands to the general commands of a TransparentEF
        self.shell_commands += [ADF_USIM.AddlShellCommands()]

    def decode_select_response(self, data_hex):
        return pySim.ts_102_221.CardProfileUICC.decode_select_response(data_hex)


# TS 31.104 Section 7.1
sw_hpsim = {
    'Security management': {
        '9862': 'Authentication error, incorrect MAC',
    }
}


class CardApplicationHPSIM(CardApplication):
    def __init__(self):
        super().__init__('HPSIM', adf=ADF_HPSIM(), sw=sw_hpsim)
