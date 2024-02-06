#!/usr/bin/env python3

# (C) 2024 by Harald Welte <laforge@osmocom.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import copy
import argparse
from pySim.esim import es2p

EID_HELP='EID of the eUICC for which eSIM shall be made available'
ICCID_HELP='The ICCID of the eSIM that shall be made available'
MATCHID_HELP='MatchingID that shall be used by profile download'

parser = argparse.ArgumentParser(description="""
Utility to manuall issue requests against the ES2+ API of an SM-DP+ according to GSMA SGP.22.""")
parser.add_argument('--url', required=True, help='Base URL of ES2+ API endpoint')
parser.add_argument('--id', required=True, help='Entity identifier passed to SM-DP+')
parser.add_argument('--client-cert', help='X.509 client certificate used to authenticate to server')
parser.add_argument('--server-ca-cert', help="""X.509 CA certificates acceptable for the server side. In
                    production use cases, this would be the GSMA Root CA (CI) certificate.""")
subparsers = parser.add_subparsers(dest='command',help="The command (API function) to call")

parser_dlo = subparsers.add_parser('download-order', help="ES2+ DownloadOrder function")
parser_dlo.add_argument('--eid', help=EID_HELP)
parser_dlo.add_argument('--iccid', help=ICCID_HELP)
parser_dlo.add_argument('--profileType', help='The profile type of which one eSIM shall be made available')

parser_cfo = subparsers.add_parser('confirm-order', help="ES2+ ConfirmOrder function")
parser_cfo.add_argument('--iccid', required=True, help=ICCID_HELP)
parser_cfo.add_argument('--eid', help=EID_HELP)
parser_cfo.add_argument('--matchingId', help=MATCHID_HELP)
parser_cfo.add_argument('--confirmationCode', help='Confirmation code that shall be used by profile download')
parser_cfo.add_argument('--smdsAddress', help='SM-DS Address')
parser_cfo.add_argument('--releaseFlag', action='store_true', help='Shall the profile be immediately released?')

parser_co = subparsers.add_parser('cancel-order', help="ES2+ CancelOrder function")
parser_co.add_argument('--iccid', required=True, help=ICCID_HELP)
parser_co.add_argument('--eid', help=EID_HELP)
parser_co.add_argument('--matchingId', help=MATCHID_HELP)
parser_co.add_argument('--finalProfileStatusIndicator', required=True, choices=['Available','Unavailable'])

parser_rp = subparsers.add_parser('release-profile', help='ES2+ ReleaseProfile function')
parser_rp.add_argument('--iccid', required=True, help=ICCID_HELP)

if __name__ == '__main__':
    opts = parser.parse_args()
    #print(opts)

    peer = es2p.Es2pApiClient(opts.url, opts.id, server_cert_verify=opts.server_ca_cert, client_cert=opts.client_cert)

    data = {}
    for k, v in vars(opts).items():
        if k in ['url', 'id', 'client_cert', 'server_ca_cert', 'command']:
            # remove keys from dict that shold not end up in JSON...
            continue
        if v is not None:
            data[k] = v

    print(data)
    if opts.command == 'download-order':
        res = peer.call_downloadOrder(data)
    elif opts.command == 'confirm-order':
        res = peer.call_confirmOrder(data)
    elif opts.command == 'cancel-order':
        res = peer.call_cancelOrder(data)
    elif opts.command == 'release-profile':
        res = peer.call_releaseProfile(data)
