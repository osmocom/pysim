#!/usr/bin/env python3
"""scp81_trigger.py -- build the OTA packet that asks the card to open an SCP81 admin session."""

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


# Prints the apdu line for AdmSessTriggerParams TLV as the sms secured data, Expanded RFM mode,
# to be fed into pysim_shell.py
#
# security params supplied either
# - in the trigger
# - from the cards data object,
# trigger wins when both are present.
# --no-sec omits them from the trigger so the stored ones are used.
#
# example params:
#    --psk-id 'PSK Identity 123' --kvn 0x41 --kid-ref 5
#    --ip 127.0.0.1 --port 8080 --buffer 512
#    --host 172.96.0.1 --uri '/server/adminagent?cmd=1'

import argparse
import sys

from osmocom.utils import b2h                                          # noqa: E402
from pySim.cat import (sms_pp_download_envelope, BearerDescription,  # noqa: E402
                       BufferSize, UiccTransportLevel, OtherAddress)
from pySim.global_platform.http import (AdmSessTriggerParams, AdmSessionParams,  # noqa: E402
                                        SecurityParams, HttpPostParams, RasConnectionParams,
                                        AdminHostParam, AdminUriParam)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--psk-id", help="PSK identity for ClientHello (required, unless --no-sec)")
    ap.add_argument("--kvn", type=lambda s: int(s, 0), help="key version of the PSK (required, unless --no-sec)")
    ap.add_argument("--kid-ref", type=lambda s: int(s, 0), help="PSK key id (required, unless --no-sec)")
    ap.add_argument("--host", help="HTTP Host header (required, unless --no-http)")
    ap.add_argument("--uri", help="HTTP request URI (required, unless --no-http)")
    ap.add_argument("--ip", help="administration server address, BIP (required, unless --no-conn)")
    ap.add_argument("--port", type=int, help="administration server port (required, unless --no-conn)")
    ap.add_argument("--buffer", type=int, help="BIP buffer size (required, unless --no-conn)")
    ap.add_argument("--no-conn", action="store_true", help="omit the connection params (tag 0x84)")
    ap.add_argument("--no-sec", action="store_true", help="omit the security params (tag 0x85)")
    ap.add_argument("--no-http", action="store_true", help="omit the HTTP POST params (tag 0x89)")

    args = ap.parse_args()

    missing = []
    if not args.no_conn:
        missing += [n for n in ('ip', 'port', 'buffer') if getattr(args, n) is None]
    if not args.no_sec:
        missing += [n for n in ('psk_id', 'kvn', 'kid_ref') if getattr(args, n) is None]
    if not args.no_http:
        missing += [n for n in ('host', 'uri') if getattr(args, n) is None]
    if missing:
        ap.error("pass every value required: %s." % " ".join("--" + n.replace('_', '-') for n in missing))

    session = []
    if not args.no_conn:
        session.append(RasConnectionParams(children=[
            BearerDescription(decoded={'bearer_type': 'default', 'bearer_parameters': ''}),
            BufferSize(decoded=args.buffer),
            UiccTransportLevel(decoded={'protocol_type': 'tcp_uicc_client_remote',
                                        'port_number': args.port}),
            OtherAddress(decoded={'type_of_address': 'ipv4',
                                  'address': bytes(int(b) for b in args.ip.split("."))})]))
    if not args.no_sec:
        session.append(SecurityParams(decoded={'psk_id': args.psk_id.encode(), 'kvn': args.kvn,
                                               'kid': args.kid_ref, 'sha_type': None}))
    if not args.no_http:
        session.append(HttpPostParams(children=[AdminHostParam(decoded=args.host),
                                                AdminUriParam(decoded=args.uri)]))
    trig = AdmSessTriggerParams(children=[AdmSessionParams(children=session)]).to_tlv()

    # stderr for logs, stdout for data
    print("# trigger TLV   %d B  %s" % (len(trig), trig.hex()), file=sys.stderr)
    print("# %-13s %d B  %s" % ("secured data", len(trig), trig.hex()), file=sys.stderr)
    print(trig.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
