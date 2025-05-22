#!/usr/bin/env python3

# (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
# All Rights Reserved
#
# Author: Eric Wild <ewild@sysmocom.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Integrates C++ BSP implementation for testing getBoundProfilePackage in osmo-smdpp.py
"""

import os
import sys
from typing import Dict, List, Optional, Tuple
from osmocom.utils import h2b, b2h
from osmocom.tlv import bertlv_parse_one_rawtag, bertlv_return_one_rawtlv
import base64

try:
    import bsp_crypto
    CPP_BSP_AVAILABLE = True
    print("C++ BSP module loaded successfully")
except ImportError as e:
    CPP_BSP_AVAILABLE = False
    print(f"C++ BSP module not available: {e} - Please compile the C++ extension with: python setup.py build_ext --inplace")

class BspTestIntegration:
    """Integration class for testing BSP functionality with C++ implementation"""

    def __init__(self):
        self.cpp_available = CPP_BSP_AVAILABLE

    def parse_bound_profile_package(self, bpp_der: bytes) -> Dict:
        def split_bertlv_sequence(sequence: bytes) -> List[bytes]:
            """Split a SEQUENCE OF into individual TLV elements"""
            remainder = sequence
            ret = []
            while remainder:
                _tag, _l, tlv, remainder = bertlv_return_one_rawtlv(remainder)
                ret.append(tlv)
            return ret

        # outer BoundProfilePackage structure
        tag, _l, v, _remainder = bertlv_parse_one_rawtag(bpp_der)
        if len(_remainder):
            raise ValueError('Excess data at end of BPP TLV')
        if tag != 0xbf36:
            raise ValueError(f'Unexpected BPP outer tag: 0x{tag:x}')

        result = {}

        # InitialiseSecureChannelRequest
        tag, _l, iscr_bin, remainder = bertlv_return_one_rawtlv(v)
        if tag != 0xbf23:  # Expected tag for InitialiseSecureChannelRequest
            raise ValueError(f"Unexpected ISCR tag: 0x{tag:x}")
        result['iscr'] = iscr_bin

        # firstSequenceOf87 (ConfigureISDP)
        tag, _l, firstSeqOf87, remainder = bertlv_parse_one_rawtag(remainder)
        if tag != 0xa0:
            raise ValueError(f"Unexpected 'firstSequenceOf87' tag: 0x{tag:x}")
        result['firstSequenceOf87'] = split_bertlv_sequence(firstSeqOf87)

        # sequenceOf88 (StoreMetadata)
        tag, _l, seqOf88, remainder = bertlv_parse_one_rawtag(remainder)
        if tag != 0xa1:
            raise ValueError(f"Unexpected 'sequenceOf88' tag: 0x{tag:x}")
        result['sequenceOf88'] = split_bertlv_sequence(seqOf88)

        # optional secondSequenceOf87 or sequenceOf86
        tag, _l, tlv, remainder = bertlv_parse_one_rawtag(remainder)
        if tag == 0xa2:  # secondSequenceOf87 (ReplaceSessionKeys)
            result['secondSequenceOf87'] = split_bertlv_sequence(tlv)
            # sequenceOf86
            tag2, _l, seqOf86, remainder = bertlv_parse_one_rawtag(remainder)
            if tag2 != 0xa3:
                raise ValueError(f"Unexpected 'sequenceOf86' tag: 0x{tag2:x}")
            result['sequenceOf86'] = split_bertlv_sequence(seqOf86)
        elif tag == 0xa3:  # straight sequenceOf86 (no ReplaceSessionKeys)
            result['secondSequenceOf87'] = []
            result['sequenceOf86'] = split_bertlv_sequence(tlv)
        else:
            raise ValueError(f"Unexpected tag after sequenceOf88: 0x{tag:x}")

        if remainder:
            raise ValueError("Unexpected data after BPP structure")

        return result

    def verify_bound_profile_package(self,
                                   shared_secret: bytes,
                                   key_type: int,
                                   key_length: int,
                                   host_id: bytes,
                                   eid: bytes,
                                   bpp_der: bytes,
                                   expected_configure_isdp: Optional[bytes] = None,
                                   expected_store_metadata: Optional[bytes] = None,
                                   expected_profile_data: Optional[bytes] = None) -> Dict:
        if not self.cpp_available:
            raise RuntimeError("C++ BSP module not available")

        parsed = self.parse_bound_profile_package(bpp_der)

        print(f"BPP_VERIFY: Parsed BPP with {len(parsed['firstSequenceOf87'])} ConfigureISDP segments")
        print(f"BPP_VERIFY: {len(parsed['sequenceOf88'])} StoreMetadata segments")
        print(f"BPP_VERIFY: {len(parsed['secondSequenceOf87'])} ReplaceSessionKeys segments")
        print(f"BPP_VERIFY: {len(parsed['sequenceOf86'])} profile data segments")

        # Convert bytes to lists for C++ - just to be safe
        shared_secret_list = list(shared_secret)
        host_id_list = list(host_id)
        eid_bytes_list = list(eid)

        bsp = bsp_crypto.BspCrypto.from_kdf(shared_secret_list, key_type, key_length, host_id_list, eid_bytes_list)

        try:
            # result = bsp.process_bound_profile_package(
            #     parsed['firstSequenceOf87'][0],
            #     parsed['sequenceOf88'][0],
            #     parsed['secondSequenceOf87'][0],
            #     parsed['sequenceOf86'][0]
            # )

            result = bsp.process_bound_profile_package2(bpp_der)

            verification_result = {
                'success': True,
                'error': None,
                'configureIsdp': bytes(result['configureIsdp']),
                'storeMetadata': bytes(result['storeMetadata']),
                'profileData': bytes(result['profileData']),
                'hasReplaceSessionKeys': result['hasReplaceSessionKeys']
            }

            if result['hasReplaceSessionKeys']:
                rsk = result['replaceSessionKeys']
                verification_result['replaceSessionKeys'] = {
                    'ppkEnc': bytes(rsk['ppkEnc']),
                    'ppkCmac': bytes(rsk['ppkCmac']),
                    'initialMacChainingValue': bytes(rsk['initialMacChainingValue'])
                }

            verification_result['verification'] = {}
            if expected_configure_isdp is not None:
                verification_result['verification']['configureIsdp'] = (
                    verification_result['configureIsdp'] == expected_configure_isdp
                )
            if expected_store_metadata is not None:
                verification_result['verification']['storeMetadata'] = (
                    verification_result['storeMetadata'] == expected_store_metadata
                )
            if expected_profile_data is not None:
                verification_result['verification']['profileData'] = (
                    verification_result['profileData'] == expected_profile_data
                )

            print("BPP_VERIFY: Successfully processed BoundProfilePackage")
            print(f"BPP_VERIFY: ConfigureISDP: {len(verification_result['configureIsdp'])} bytes")
            print(f"BPP_VERIFY: StoreMetadata: {len(verification_result['storeMetadata'])} bytes")
            print(f"BPP_VERIFY: ProfileData: {len(verification_result['profileData'])} bytes")
            print(f"BPP_VERIFY: Has ReplaceSessionKeys: {verification_result['hasReplaceSessionKeys']}")

            return verification_result

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'configureIsdp': None,
                'storeMetadata': None,
                'profileData': None,
                'hasReplaceSessionKeys': False
            }
