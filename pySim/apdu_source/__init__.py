import abc
import logging
from typing import Union
from pySim.apdu import Apdu, Tpdu, CardReset, TpduFilter

PacketType = Union[Apdu, Tpdu, CardReset]

logger = logging.getLogger(__name__)

class ApduSource(abc.ABC):
    def __init__(self):
        self.apdu_filter = TpduFilter(None)

    @abc.abstractmethod
    def read_packet(self) -> PacketType:
        """Read one packet from the source."""

    def read(self) -> Union[Apdu, CardReset]:
        """Main function to call by the user: Blocking read, returns Apdu or CardReset."""
        apdu = None
        # loop until we actually have an APDU to return
        while not apdu:
            r = self.read_packet()
            if not r:
                continue
            if isinstance(r, Tpdu):
                apdu = self.apdu_filter.input_tpdu(r)
            elif isinstance(r, Apdu):
                apdu = r
            elif isinstance(r, CardReset):
                apdu = r
            else:
                raise ValueError('Unknown read_packet() return %s' % r)
        return apdu
