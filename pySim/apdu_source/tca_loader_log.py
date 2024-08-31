# coding=utf-8

# (C) 2024 by Harald Welte <laforge@osmocom.org>
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


from pySim.utils import h2b

from pySim.apdu.ts_102_221 import ApduCommands as UiccApduCommands
from pySim.apdu.ts_102_222 import ApduCommands as UiccAdmApduCommands
from pySim.apdu.ts_31_102 import ApduCommands as UsimApduCommands
from pySim.apdu.global_platform import ApduCommands as GpApduCommands

from . import ApduSource, PacketType, CardReset

ApduCommands = UiccApduCommands + UiccAdmApduCommands + UsimApduCommands + GpApduCommands

class TcaLoaderLogApduSource(ApduSource):
    """ApduSource for reading log files created by TCALoader."""
    def __init__(self, filename:str):
        super().__init__()
        self.logfile = open(filename, 'r')

    def read_packet(self) -> PacketType:
        command = None
        response = None
        for line in self.logfile:
            if line.startswith('Command'):
                command = line.split()[1]
                print("Command: '%s'" % command)
                pass
            elif command and line.startswith('Response'):
                response = line.split()[1]
                print("Response: '%s'" % response)
                return ApduCommands.parse_cmd_bytes(h2b(command) + h2b(response))
        raise StopIteration
