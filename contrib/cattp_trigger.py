#!/usr/bin/env python3
"""cattp_trigger.py -- build the PUSH APDUs that ask the card to open a CAT_TP link."""

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Eric Wild <ewild@sysmocom.de>
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

# TS 102 226 section 9: two PUSH C-APDUs, "request for BIP channel opening" and "request for
# CAT_TP link establishment", printed one per line for smpp-ota-tool.py -a, compact format,
# sent to the TAR of the application that should open the link. The card answers via the POR
# of the SMS once the link is OPEN, the server side is contrib/cattp_admin_server.py.
#
# example:
#    smpp-ota-tool.py ... --tar b00010 $(cattp_trigger.py --ip 10.0.0.1 --port 6001 | sed 's/^/-a /')

import argparse
import sys

from osmocom.utils import h2b
from pySim.ota import encode_push_open_channel, encode_push_cattp_link


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", required=True, help="CAT_TP server IPv4 address, OPEN CHANNEL destination")
    ap.add_argument("--port", type=int, required=True, help="UDP port of the server, used as CAT_TP port too")
    ap.add_argument("--buffer", type=int, default=1024, help="BIP buffer size, bounds the CAT_TP PDU size")
    ap.add_argument("--max-sdu", type=int, help="max SDU size the card should announce (default: card decides)")
    ap.add_argument("--identification", type=h2b, help="identification for the SYN (hex), default: ICCID")
    ap.add_argument("--no-open", action="store_true", help="omit the BIP channel opening PUSH")
    args = ap.parse_args()

    apdus = []
    if not args.no_open:
        apdus.append(encode_push_open_channel(args.ip, args.port, args.buffer))
    apdus.append(encode_push_cattp_link(args.port, args.max_sdu, args.identification))
    for a in apdus:
        print(a.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
