#!/usr/bin/env python3

# A more useful verion of the 'unber' tool provided with asn1c:
# Give a hierarchical decode of BER/DER-encoded ASN.1 TLVs

import sys
import argparse

from osmocom.utils import b2h, h2b
from osmocom.tlv import bertlv_parse_one, bertlv_encode_tag

def process_one_level(content: bytes, indent: int):
    remainder = content
    while len(remainder):
        tdict, l, v, remainder = bertlv_parse_one(remainder)
        #print(tdict)
        rawtag = bertlv_encode_tag(tdict)
        if tdict['constructed']:
            print("%s%s l=%d" % (indent*"  ", b2h(rawtag), l))
            process_one_level(v, indent + 1)
        else:
            print("%s%s l=%d %s" % (indent*"  ", b2h(rawtag), l, b2h(v)))


option_parser = argparse.ArgumentParser(description='BER/DER data dumper')
group = option_parser.add_mutually_exclusive_group(required=True)
group.add_argument('--file', help='Input file')
group.add_argument('--hex', help='Input hexstring')


if __name__ == '__main__':
    opts = option_parser.parse_args()

    if opts.file:
        with open(opts.file, 'rb') as f:
            content = f.read()
    elif opts.hex:
        content = h2b(opts.hex)
    else:
        # avoid pylint "(possibly-used-before-assignment)" below
        sys.exit(2)

    process_one_level(content, 0)
