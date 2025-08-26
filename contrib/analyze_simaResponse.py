#!/usr/bin/env python3

# A tool to analyze the eUICC simaResponse (series of EUICCResponse)
#
# (C) 2025 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
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
#
import argparse
from osmocom.utils import h2b, b2h
from osmocom.tlv import bertlv_parse_one, bertlv_encode_tag, bertlv_encode_len
from pySim.esim.saip import *

parser = argparse.ArgumentParser(description="""Utility program to analyze the contents of an eUICC simaResponse.""")
parser.add_argument('SIMA_RESPONSE', help='Hexstring containing the simaResponse as received from the eUICC')

def split_sima_response(sima_response):
    """split an eUICC simaResponse field into a list of EUICCResponse fields"""

    remainder = sima_response
    result = []
    while len(remainder):
        tdict, l, v, next_remainder = bertlv_parse_one(remainder)
        rawtag = bertlv_encode_tag(tdict)
        rawlen = bertlv_encode_len(l)
        result = result + [remainder[0:len(rawtag) + len(rawlen) + l]]
        remainder = next_remainder
    return result

def analyze_status(status):
    """
    Convert a status code (integer) into a human readable string
    (see eUICC Profile Package: Interoperable Format Technical Specification, section 8.11)
    """

    # SIMA status codes
    string_values = {0 : 'ok',
                     1 : 'pe-not-supported',
                     2 : 'memory-failure',
                     3 : 'bad-values',
                     4 : 'not-enough-memory',
                     5 : 'invalid-request-format',
                     6 : 'invalid-parameter',
                     7 : 'runtime-not-supported',
                     8 : 'lib-not-supported',
                     9 : 'template-not-supported ',
                     10 : 'feature-not-supported',
                     11 : 'pin-code-missing',
                     31 : 'unsupported-profile-version'}

    string_value = string_values.get(status, None)
    if string_value is not None:
        return "%d = %s (SIMA status code)" % (status, string_value)

    # ISO 7816 status words
    if status >= 24576 and status <= 28671:
        return "%d = %04x (ISO7816 status word)" % (status, status)
    elif status >= 36864 and status <= 40959:
        return "%d = %04x (ISO7816 status word)" % (status, status)

    # Proprietary status codes
    elif status >= 40960 and status <= 65535:
        return "%d = %04x (proprietary)" % (status, status)

    # Unknown status codes
    return "%d (unknown, proprietary?)" % status

def analyze_euicc_response(euicc_response):
    """Analyze and display the contents of an EUICCResponse"""

    print(" EUICCResponse: %s" % b2h(euicc_response))
    euicc_response_decoded = asn1.decode('EUICCResponse', euicc_response)

    pe_status = euicc_response_decoded.get('peStatus')
    print("  peStatus:")
    for s in pe_status:
        print("   status: %s" % analyze_status(s.get('status')))
        print("   identification: %s" % str(s.get('identification', None)))
        print("   additional-information: %s" % str(s.get('additional-information', None)))
        print("   offset: %s" % str(s.get('offset', None)))

    if euicc_response_decoded.get('profileInstallationAborted', False) is None:
        # This type is defined as profileInstallationAborted NULL OPTIONAL, so when it is present it
        # will have the value None, otherwise it is simply not present.
        print("  profileInstallationAborted: True")
    else:
        print("  profileInstallationAborted: False")

    status_message = euicc_response_decoded.get('statusMessage', None)
    print("  statusMessage: %s" % str(status_message))

if __name__ == '__main__':
    opts = parser.parse_args()
    sima_response = h2b(opts.SIMA_RESPONSE);

    print("simaResponse: %s" % b2h(sima_response))
    euicc_response_list = split_sima_response(sima_response)

    for euicc_response in euicc_response_list:
        analyze_euicc_response(euicc_response)
