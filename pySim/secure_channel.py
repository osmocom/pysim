# Generic code related to Secure Channel processing
#
# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
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

import abc
from osmocom.utils import b2h, h2b, Hexstr

from pySim.utils import ResTuple

class SecureChannel(abc.ABC):
    @abc.abstractmethod
    def wrap_cmd_apdu(self, apdu: bytes) -> bytes:
        """Wrap Command APDU according to specific Secure Channel Protocol."""
        pass

    @abc.abstractmethod
    def unwrap_rsp_apdu(self, sw: bytes, rsp_apdu: bytes) -> bytes:
        """UnWrap Response-APDU according to specific Secure Channel Protocol."""
        pass

    def send_apdu_wrapper(self, send_fn: callable, pdu: Hexstr, *args, **kwargs) -> ResTuple:
        """Wrapper function to wrap command APDU and unwrap repsonse APDU around send_apdu callable."""
        pdu_wrapped = b2h(self.wrap_cmd_apdu(h2b(pdu)))
        res, sw = send_fn(pdu_wrapped, *args, **kwargs)
        res_unwrapped = b2h(self.unwrap_rsp_apdu(h2b(sw), h2b(res)))
        return res_unwrapped, sw
