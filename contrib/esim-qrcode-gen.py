#!/usr/bin/env python3

# Small command line utility program to encode eSIM QR-Codes

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

import sys
import argparse

from pySim.esim import ActivationCode


option_parser = argparse.ArgumentParser(description="""
eSIM QR code generator. Will encode the given hostname + activation code
into the eSIM RSP String format as specified in SGP.22 Section 4.1.  If
a PNG output file is specified, it will also generate a QR code.""")
option_parser.add_argument('hostname', help='FQDN of SM-DP+')
option_parser.add_argument('token', help='MatchingID / Token')
option_parser.add_argument('--oid', help='SM-DP+ OID in CERT.DPauth.ECDSA')
option_parser.add_argument('--confirmation-code-required', action='store_true',
                           help='Whether a Confirmation Code is required')
option_parser.add_argument('--png', help='Output PNG file name (no PNG is written if omitted)')



if __name__ == '__main__':
    opts = option_parser.parse_args()

    ac = ActivationCode(opts.hostname, opts.token, opts.oid, opts.confirmation_code_required)
    print(ac.to_string())
    if opts.png:
        with open(opts.png, 'wb') as f:
            img = ac.to_qrcode()
            img.save(f)
            print("# generated QR code stored to '%s'" % (opts.png))
