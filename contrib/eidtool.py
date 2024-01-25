#!/usr/bin/env python3

# Command line tool to compute or verify EID (eUICC ID) values
#
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

import sys
import argparse

from pySim.euicc import compute_eid_checksum, verify_eid_checksum


option_parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                        description="""pySim EID Tool
This utility program can be used to compute or verify the checksum of an EID
(eUICC Identifier).  See GSMA SGP.29 for the algorithm details.

Example (verification):
    $ eidtool.py --verify 89882119900000000000000000001654
    EID checksum verified successfully

Example (generation, passing first 30 digits):
    $ eidtool.py --compute 898821199000000000000000000016
    89882119900000000000000000001654

Example (generation, passing all 32 digits):
    $ eidtool.py --compute 89882119900000000000000000001600
    89882119900000000000000000001654

Example (generation, specifying base 30 digits and number to add):
    $ eidtool.py --compute 898821199000000000000000000000 --add 16
    89882119900000000000000000001654
""")
group = option_parser.add_mutually_exclusive_group(required=True)
group.add_argument('--verify', help='Verify given EID csum')
group.add_argument('--compute', help='Generate EID csum')
option_parser.add_argument('--add', type=int, help='Add value to EID base before computing')


if __name__ == '__main__':
    opts = option_parser.parse_args()

    if opts.verify:
        res = verify_eid_checksum(opts.verify)
        if res:
            print("EID checksum verified successfully")
            sys.exit(0)
        else:
            print("EID checksum invalid")
            sys.exit(1)
    elif opts.compute:
        eid = opts.compute
        if opts.add:
            if len(eid) != 30:
                print("EID base must be 30 digits when using --add")
                sys.exit(2)
            eid = str(int(eid) + int(opts.add))
        res = compute_eid_checksum(eid)
        print(res)

