#!/usr/bin/env python3

# (C) 2025 by Harald Welte <laforge@osmocom.org>
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

import argparse
from osmocom.utils import h2b, swap_nibbles
from pySim.esim.es8p import ProfileMetadata

parser = argparse.ArgumentParser(description="""Utility program to generate profile metadata in the
StoreMetadataRequest format based on input values from the command line.""")
parser.add_argument('--iccid', required=True, help="ICCID of eSIM profile");
parser.add_argument('--spn', required=True, help="Service Provider Name");
parser.add_argument('--profile-name', required=True, help="eSIM Profile Name");
parser.add_argument('--profile-class', choices=['test', 'operational', 'provisioning'],
                    default='operational', help="Profile Class");
parser.add_argument('--outfile', required=True, help="Output File Name");

if __name__ == '__main__':
    opts = parser.parse_args()

    iccid_bin = h2b(swap_nibbles(opts.iccid))
    pmd = ProfileMetadata(iccid_bin, spn=opts.spn, profile_name=opts.profile_name,
                          profile_class=opts.profile_class)

    with open(opts.outfile, 'wb') as f:
        f.write(pmd.gen_store_metadata_request())
    print("Written StoreMetadataRequest to '%s'" % opts.outfile)
