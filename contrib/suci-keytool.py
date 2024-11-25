#!/usr/bin/env python3

# small utility program to deal with 5G SUCI key material, at least for the ECIES Protection Scheme
# Profile A (curve25519) and B (secp256r1)

# (C) 2024 by Harald Welte <laforge@osmocom.org>
# SPDX-License-Identifier: GPL-2.0+

import argparse

from osmocom.utils import b2h
from Cryptodome.PublicKey import ECC
# if used with pycryptodome < v3.21.0 you will get the following error when using curve25519:
# "Cryptodome.PublicKey.ECC.UnsupportedEccFeature: Unsupported ECC purpose (OID: 1.3.101.110)"

def gen_key(opts):
    # FIXME: avoid overwriting key files
    mykey = ECC.generate(curve=opts.curve)
    data = mykey.export_key(format='PEM')
    with open(opts.key_file, "wt") as f:
        f.write(data)

def dump_pkey(opts):

    #with open("curve25519-1.key", "r") as f:

    with open(opts.key_file, "r") as f:
        data = f.read()
        mykey = ECC.import_key(data)

        der = mykey.public_key().export_key(format='raw', compress=opts.compressed)
        print(b2h(der))

arg_parser = argparse.ArgumentParser(description="""Generate or export SUCI keys for 5G SA networks""")
arg_parser.add_argument('--key-file', help='The key file to use', required=True)

subparsers = arg_parser.add_subparsers(dest='command', help="The command to perform", required=True)

parser_genkey = subparsers.add_parser('generate-key', help='Generate a new key pair')
parser_genkey.add_argument('--curve', help='The ECC curve to use', choices=['secp256r1','curve25519'], required=True)

parser_dump_pkey = subparsers.add_parser('dump-pub-key', help='Dump the public key')
parser_dump_pkey.add_argument('--compressed', help='Use point compression', action='store_true')

if __name__ == '__main__':

    opts = arg_parser.parse_args()

    if opts.command == 'generate-key':
        gen_key(opts)
    elif opts.command == 'dump-pub-key':
        dump_pkey(opts)
