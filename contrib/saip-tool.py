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

import os
import sys
import argparse
import logging
from pathlib import Path
from typing import List

from pySim.esim.saip import *
from pySim.esim.saip.validation import CheckBasicStructure
from pySim.utils import h2b, b2h, swap_nibbles
from pySim.pprint import HexBytesPrettyPrinter

pp = HexBytesPrettyPrinter(indent=4,width=500)

logging.basicConfig(level=logging.DEBUG)

parser = argparse.ArgumentParser(description="""
Utility program to work with eSIM SAIP (SimAlliance Interoperable Profile) files.""")
parser.add_argument('INPUT_UPP', help='Unprotected Profile Package Input file')
subparsers = parser.add_subparsers(dest='command', help="The command to perform", required=True)

parser_split = subparsers.add_parser('split', help='Split PE-Sequence into individual PEs')
parser_split.add_argument('--output-prefix', default='.', help='Prefix path/filename for output files')

parser_dump = subparsers.add_parser('dump', help='Dump information on PE-Sequence')
parser_dump.add_argument('mode', choices=['all_pe', 'all_pe_by_type', 'all_pe_by_naa'])
parser_dump.add_argument('--dump-decoded', action='store_true', help='Dump decoded PEs')

parser_check = subparsers.add_parser('check', help='Run constraint checkers on PE-Sequence')

parser_rpe = subparsers.add_parser('remove-pe', help='Remove specified PEs from PE-Sequence')
parser_rpe.add_argument('--output-file', required=True, help='Output file name')
parser_rpe.add_argument('--identification', type=int, action='append', help='Remove PEs matching specified identification')

parser_rn = subparsers.add_parser('remove-naa', help='Remove speciifed NAAs from PE-Sequence')
parser_rn.add_argument('--output-file', required=True, help='Output file name')
parser_rn.add_argument('--naa-type', required=True, choices=NAAs.keys(), help='Network Access Application type to remove')
# TODO: add an --naa-index or the like, so only one given instance can be removed


def do_split(pes: ProfileElementSequence, opts):
    i = 0
    for pe in pes.pe_list:
        basename = Path(opts.INPUT_UPP).stem
        if not pe.identification:
            fname = '%s-%02u-%s.der' % (basename, i, pe.type)
        else:
            fname = '%s-%02u-%05u-%s.der' % (basename, i, pe.identification, pe.type)
        print("writing single PE to file '%s'" % fname)
        with open(os.path.join(opts.output_prefix, fname), 'wb') as outf:
            outf.write(pe.to_der())
        i += 1

def do_dump(pes: ProfileElementSequence, opts):
    def print_all_pe(pes: ProfileElementSequence, dump_decoded:bool = False):
        # iterate over each pe in the pes (using its __iter__ method)
        for pe in pes:
            print("="*70 + " " + pe.type)
            if dump_decoded:
                pp.pprint(pe.decoded)

    def print_all_pe_by_type(pes: ProfileElementSequence, dump_decoded:bool = False):
        # sort by PE type and show all PE within that type
        for pe_type in pes.pe_by_type.keys():
            print("="*70 + " " + pe_type)
            for pe in pes.pe_by_type[pe_type]:
                pp.pprint(pe)
                if dump_decoded:
                    pp.pprint(pe.decoded)

    def print_all_pe_by_naa(pes: ProfileElementSequence, dump_decoded:bool = False):
        for naa in pes.pes_by_naa:
            i = 0
            for naa_instance in pes.pes_by_naa[naa]:
                print("="*70 + " " + naa + str(i))
                i += 1
                for pe in naa_instance:
                    pp.pprint(pe.type)
                    if dump_decoded:
                        for d in pe.decoded:
                            print("    %s" % d)

    if opts.mode == 'all_pe':
        print_all_pe(pes, opts.dump_decoded)
    elif opts.mode == 'all_pe_by_type':
        print_all_pe_by_type(pes, opts.dump_decoded)
    elif opts.mode == 'all_pe_by_naa':
        print_all_pe_by_naa(pes, opts.dump_decoded)

def do_check(pes: ProfileElementSequence, opts):
    print("Checking PE-Sequence structure...")
    checker = CheckBasicStructure()
    checker.check(pes)
    print("All good!")

def do_remove_pe(pes: ProfileElementSequence, opts):
    new_pe_list = []
    for pe in pes.pe_list:
        identification = pe.identification
        if identification:
            if identification in opts.identification:
                print("Removing PE %s (id=%u) from Sequence..." % (pe, identification))
                continue
        new_pe_list.append(pe)

    pes.pe_list = new_pe_list
    pes._process_pelist()
    print("Writing %u PEs to file '%s'..." % (len(pes.pe_list), opts.output_file))
    with open(opts.output_file, 'wb') as f:
        f.write(pes.to_der())

def do_remove_naa(pes: ProfileElementSequence, opts):
    if not opts.naa_type in NAAs:
        raise ValueError('unsupported NAA type %s' % opts.naa_type)
    naa = NAAs[opts.naa_type]
    print("Removing NAAs of type '%s' from Sequence..." % opts.naa_type)
    pes.remove_naas_of_type(naa)
    print("Writing %u PEs to file '%s'..." % (len(pes.pe_list), opts.output_file))
    with open(opts.output_file, 'wb') as f:
        f.write(pes.to_der())


if __name__ == '__main__':
    opts = parser.parse_args()

    with open(opts.INPUT_UPP, 'rb') as f:
        pes = ProfileElementSequence.from_der(f.read())

    print("Read %u PEs from file '%s'" % (len(pes.pe_list), opts.INPUT_UPP))

    if opts.command == 'split':
        do_split(pes, opts)
    elif opts.command == 'dump':
        do_dump(pes, opts)
    elif opts.command == 'check':
        do_check(pes, opts)
    elif opts.command == 'remove-pe':
        do_remove_pe(pes, opts)
    elif opts.command == 'remove-naa':
        do_remove_naa(pes, opts)
