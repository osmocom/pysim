#!/usr/bin/env python3

# Early proof-of-concept towards a SM-DP+ HTTP service for GSMA consumer eSIM RSP
#
# (C) 2023-2024 by Harald Welte <laforge@osmocom.org>
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

# asn1tools issue https://github.com/eerimoq/asn1tools/issues/194
# must be first here
import asn1tools
import asn1tools.codecs.ber
import asn1tools.codecs.der
# do not move the code
def fix_asn1_oid_decoding():
    fix_asn1_schema = """
    TestModule DEFINITIONS ::= BEGIN
        TestOid ::= SEQUENCE {
            oid OBJECT IDENTIFIER
        }
    END
    """

    fix_asn1_asn1 = asn1tools.compile_string(fix_asn1_schema, codec='der')
    fix_asn1_oid_string = '2.999.10'
    fix_asn1_encoded = fix_asn1_asn1.encode('TestOid', {'oid': fix_asn1_oid_string})
    fix_asn1_decoded = fix_asn1_asn1.decode('TestOid', fix_asn1_encoded)

    if (fix_asn1_decoded['oid'] != fix_asn1_oid_string):
        # ASN.1 OBJECT IDENTIFIER Decoding Issue:
        #
        # In ASN.1 BER/DER encoding, the first two arcs of an OBJECT IDENTIFIER are
        # combined into a single value: (40 * arc0) + arc1. This is encoded as a base-128
        # variable-length quantity (and commonly known as VLQ or base-128 encoding)
        # as specified in ITU-T X.690 §8.19, it can span multiple bytes if
        # the value is large.
        #
        # For arc0 = 0 or 1, arc1 must be in [0, 39]. For arc0 = 2, arc1 can be any non-negative integer.
        # All subsequent arcs (arc2, arc3, ...) are each encoded as a separate base-128 VLQ.
        #
        # The decoding bug occurs when the decoder does not properly split the first
        # subidentifier for arc0 = 2 and arc1 >= 40. Instead of decoding:
        #   - arc0 = 2
        #   - arc1 = (first_subidentifier - 80)
        # it may incorrectly interpret the first_subidentifier as arc0 = (first_subidentifier // 40),
        # arc1 = (first_subidentifier % 40), which is only valid for arc1 < 40.
        #
        # This patch handles it properly for all valid OBJECT IDENTIFIERs
        # with large second arcs, by applying the ASN.1 rules:
        #   - if first_subidentifier < 40: arc0 = 0, arc1 = first_subidentifier
        #   - elif first_subidentifier < 80: arc0 = 1, arc1 = first_subidentifier - 40
        #   - else: arc0 = 2, arc1 = first_subidentifier - 80
        #
        # This problem is not uncommon, see for example https://github.com/randombit/botan/issues/4023

        def fixed_decode_object_identifier(data, offset, end_offset):
            """Decode ASN.1 OBJECT IDENTIFIER from bytes to dotted string, fixing large second arc handling."""
            def read_subidentifier(data, offset):
                value = 0
                while True:
                    b = data[offset]
                    value = (value << 7) | (b & 0x7F)
                    offset += 1
                    if not (b & 0x80):
                        break
                return value, offset

            subid, offset = read_subidentifier(data, offset)
            if subid < 40:
                first = 0
                second = subid
            elif subid < 80:
                first = 1
                second = subid - 40
            else:
                first = 2
                second = subid - 80
            arcs = [first, second]

            while offset < end_offset:
                subid, offset = read_subidentifier(data, offset)
                arcs.append(subid)

            return '.'.join(str(x) for x in arcs)

        asn1tools.codecs.ber.decode_object_identifier = fixed_decode_object_identifier
        asn1tools.codecs.der.decode_object_identifier = fixed_decode_object_identifier

        # test our patch
        asn1 = asn1tools.compile_string(fix_asn1_schema, codec='der')
        decoded = asn1.decode('TestOid', fix_asn1_encoded)['oid']
        assert fix_asn1_oid_string == str(decoded)

fix_asn1_oid_decoding()

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, ParameterFormat
from cryptography.x509.oid import ExtensionOID, NameOID
from pathlib import Path
import json
import sys
import argparse
import uuid
import os
import functools
from typing import Optional, Dict, List
from pprint import pprint as pp

import base64
import time
from base64 import b64decode
from klein import Klein
from twisted.web.iweb import IRequest

from osmocom.utils import h2b, b2h, swap_nibbles

import pySim.esim.rsp as rsp
from pySim.esim import saip, PMO
from pySim.esim.es8p import *
from pySim.esim.x509_cert import oid, cert_policy_has_oid, cert_get_auth_key_id
from cryptography.x509 import ExtensionNotFound
from pySim.esim.x509_cert import CertAndPrivkey, CertificateSet, cert_get_subject_key_id
from pySim.esim import x509_err
from datetime import datetime, timezone
import hashlib

import logging
logger = logging.getLogger(__name__)

# HACK: make this configurable
DATA_DIR = './smdpp-data'
HOSTNAME = 'testsmdpplus1.example.com' # must match certificates!


def b64encode2str(req: bytes) -> str:
    """Encode given input bytes as base64 and return result as string."""
    return base64.b64encode(req).decode('ascii')

def set_headers(request: IRequest):
    """Set the request headers as mandatory by GSMA eSIM RSP."""
    request.setHeader('Content-Type', 'application/json;charset=UTF-8')
    request.setHeader('X-Admin-Protocol', 'gsma/rsp/v2.1.0')

def validate_request_headers(request: IRequest):
    """Validate mandatory HTTP headers according to SGP.22."""
    content_type = request.getHeader('Content-Type')
    if not content_type or not content_type.startswith('application/json'):
        raise ApiError('1.2.1', '2.1', 'Invalid Content-Type header')

    admin_protocol = request.getHeader('X-Admin-Protocol')
    if admin_protocol and not admin_protocol.startswith('gsma/rsp/v'):
        raise ApiError('1.2.2', '2.1', 'Unsupported X-Admin-Protocol version')

def get_eum_certificate_variant(eum_cert) -> str:
    """Determine EUM certificate variant by checking Certificate Policies extension.
    Returns 'O' for old variant, or 'NEW' for Ov3/A/B/C variants."""

    try:
        cert_policies_ext = eum_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.CERTIFICATE_POLICIES
        )

        for policy in cert_policies_ext.value:
            policy_oid = policy.policy_identifier.dotted_string
            logger.debug(f"Found certificate policy: {policy_oid}")

            if policy_oid == '2.23.146.1.2.1.2':
                logger.debug("Detected EUM certificate variant: O (old)")
                return 'O'
            elif policy_oid == '2.23.146.1.2.1.0.0.0':
                logger.debug("Detected EUM certificate variant: Ov3/A/B/C (new)")
                return 'NEW'
    except x509.ExtensionNotFound:
        logger.debug("No Certificate Policies extension found")
    except Exception as e:
        logger.debug(f"Error checking certificate policies: {e}")

def parse_permitted_eins_from_cert(eum_cert) -> List[str]:
    """Extract permitted IINs from EUM certificate using the appropriate method
    based on certificate variant (O vs Ov3/A/B/C).
    Returns list of permitted IINs (basically prefixes that valid EIDs must start with)."""

    # Determine certificate variant first
    cert_variant = get_eum_certificate_variant(eum_cert)
    permitted_iins = []

    if cert_variant == 'O':
        # Old variant - use nameConstraints extension
        #print("Using nameConstraints parsing for variant O certificate")
        permitted_iins.extend(_parse_name_constraints_eins(eum_cert))

    else:
        # New variants (Ov3, A, B, C) - use GSMA permittedEins extension
        #print("Using GSMA permittedEins parsing for newer certificate variant")
        permitted_iins.extend(_parse_gsma_permitted_eins(eum_cert))

    unique_iins = list(set(permitted_iins))

    logger.debug(f"Total unique permitted IINs found: {len(unique_iins)}")
    return unique_iins

def _parse_gsma_permitted_eins(eum_cert) -> List[str]:
    """Parse the GSMA permittedEins extension using correct ASN.1 structure.
    PermittedEins ::= SEQUENCE OF PrintableString
    Each string contains an IIN (Issuer Identification Number) - a prefix of valid EIDs."""
    permitted_iins = []

    try:
        permitted_eins_oid = x509.ObjectIdentifier('2.23.146.1.2.2.0')  # sgp26: 2.23.146.1.2.2.0 = ASN1:SEQUENCE:permittedEins

        for ext in eum_cert.extensions:
            if ext.oid == permitted_eins_oid:
                logger.debug(f"Found GSMA permittedEins extension: {ext.oid}")

                # Get the DER-encoded extension value
                ext_der = ext.value.value if hasattr(ext.value, 'value') else ext.value

                if isinstance(ext_der, bytes):
                    try:
                        permitted_eins_schema = """
                        PermittedEins DEFINITIONS ::= BEGIN
                            PermittedEins ::= SEQUENCE OF PrintableString
                        END
                        """
                        decoder = asn1tools.compile_string(permitted_eins_schema)
                        decoded_strings = decoder.decode('PermittedEins', ext_der)

                        for iin_string in decoded_strings:
                            # Each string contains an IIN -> prefix of euicc EID
                            iin_clean = iin_string.strip().upper()

                            # IINs is 8 chars per sgp22, var len according to sgp29, fortunately we don't care
                            if (len(iin_clean) == 8 and
                                all(c in '0123456789ABCDEF' for c in iin_clean) and
                                    len(iin_clean) % 2 == 0):
                                permitted_iins.append(iin_clean)
                                logger.debug(f"Found permitted IIN (GSMA): {iin_clean}")
                            else:
                                logger.debug(f"Invalid IIN format: {iin_string} (cleaned: {iin_clean})")
                    except Exception as e:
                        logger.debug(f"Error parsing GSMA permittedEins extension: {e}")

    except Exception as e:
        logger.debug(f"Error accessing GSMA certificate extensions: {e}")

    return permitted_iins


def _parse_name_constraints_eins(eum_cert) -> List[str]:
    """Parse permitted IINs from nameConstraints extension (variant O)."""
    permitted_iins = []

    try:
        # Look for nameConstraints extension
        name_constraints_ext = eum_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.NAME_CONSTRAINTS
        )

        # print("Found nameConstraints extension (variant O)")
        name_constraints = name_constraints_ext.value

        # Check permittedSubtrees for IIN constraints
        if name_constraints.permitted_subtrees:
            for subtree in name_constraints.permitted_subtrees:
                # print(f"Processing permitted subtree: {subtree}")

                if isinstance(subtree, x509.DirectoryName):
                    for attribute in subtree.value:
                        # IINs for O in serialNumber
                        if attribute.oid == x509.oid.NameOID.SERIAL_NUMBER:
                            serial_value = attribute.value.upper()
                            # sgp22 8, sgp29 var len, fortunately we don't care
                            if (len(serial_value) == 8 and
                                all(c in '0123456789ABCDEF' for c in serial_value) and
                                    len(serial_value) % 2 == 0):
                                permitted_iins.append(serial_value)
                                logger.debug(f"Found permitted IIN (nameConstraints/DN): {serial_value}")

    except x509.ExtensionNotFound:
        logger.debug("No nameConstraints extension found")
    except Exception as e:
        logger.debug(f"Error parsing nameConstraints: {e}")

    return permitted_iins


def validate_eid_range(eid: str, eum_cert) -> bool:
    """Validate that EID is within the permitted EINs of the EUM certificate."""
    if not eid or len(eid) != 32:
        logger.debug(f"Invalid EID format: {eid}")
        return False

    try:
        permitted_eins = parse_permitted_eins_from_cert(eum_cert)

        if not permitted_eins:
            logger.debug("Warning: No permitted EINs found in EUM certificate")
            return False

        eid_normalized = eid.upper()
        logger.debug(f"Validating EID {eid_normalized} against {len(permitted_eins)} permitted EINs")

        for permitted_ein in permitted_eins:
                if eid_normalized.startswith(permitted_ein):
                    logger.debug(f"EID {eid_normalized} matches permitted EIN {permitted_ein}")
                    return True

        logger.debug(f"EID {eid_normalized} is not in any permitted EIN list")
        return False

    except Exception as e:
        logger.debug(f"Error validating EID: {e}")
        return False

def build_status_code(subject_code: str, reason_code: str, subject_id: Optional[str], message: Optional[str]) -> Dict:
    r = {'subjectCode': subject_code, 'reasonCode': reason_code }
    if subject_id:
        r['subjectIdentifier'] = subject_id
    if message:
        r['message'] = message
    return r

def build_resp_header(js: dict, status: str = 'Executed-Success', status_code_data = None) -> None:
    # SGP.22 v3.0 6.5.1.4
    js['header'] = {
        'functionExecutionStatus': {
            'status': status,
        }
    }
    if status_code_data:
        js['header']['functionExecutionStatus']['statusCodeData'] = status_code_data


def ecdsa_tr03111_to_dss(sig: bytes) -> bytes:
    """convert an ECDSA signature from BSI TR-03111 format to DER: first get long integers; then encode those."""
    assert len(sig) == 64
    r = int.from_bytes(sig[0:32], 'big')
    s = int.from_bytes(sig[32:32*2], 'big')
    return encode_dss_signature(r, s)


def compute_confirmation_code_hash(confirmation_code: str, transaction_id: bytes) -> bytes:
    """Compute confirmation code hash according to SGP.22 specification.
    Hashed Confirmation Code = SHA256(SHA256(Confirmation Code) | TransactionID)
    """

    # Convert confirmation code from hex string to bytes (like EID handling)
    cc_bytes = h2b(confirmation_code)

    # Step 1: SHA256(Confirmation Code)
    first_hash = hashlib.sha256(cc_bytes).digest()

    # Step 2: SHA256(SHA256(CC) | TransactionID)
    return hashlib.sha256(first_hash + transaction_id).digest()


def validate_eum_certificate(eum_cert: x509.Certificate) -> None:
    """Validate EUM certificate according to SGP.22 requirements.
    Raises ApiError with appropriate error codes for different validation failures."""

    # Check KeyUsage extension
    try:
        key_usage = eum_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        # EUM certificates are intermediate CAs that sign eUICC certificates, so they need keyCertSign
        if not key_usage.value.key_cert_sign:
            # SGP.22 Table 49: EUM Certificate - Verification Failed
            raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
        # Check for critical flag
        if not key_usage.critical:
            # SGP.22 Table 49: EUM Certificate - Verification Failed
            raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
    except x509.ExtensionNotFound:
        # SGP.22 Table 49: EUM Certificate - Verification Failed
        raise ApiError('8.1.2', '6.1', 'Certificate is invalid')

    # ExtendedKeyUsage not present in EUM certificates as they are intermediate CAs (?)

    # Check Certificate Policies
    try:
        cert_policies = eum_cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        # Check for required EUM policy OIDs
        has_valid_policy = False
        for policy in cert_policies.value:
            policy_oid = policy.policy_identifier.dotted_string
            # EUM policies: 2.23.146.1.2.1.2 (old) or 2.23.146.1.2.1.0.0.0 (new)
            if policy_oid in ['2.23.146.1.2.1.2', '2.23.146.1.2.1.0.0.0']:
                has_valid_policy = True
                break
        if not has_valid_policy:
            # SGP.22 Table 49: EUM Certificate - Verification Failed
            raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
    except x509.ExtensionNotFound:
        # SGP.22 Table 49: EUM Certificate - Verification Failed
        raise ApiError('8.1.2', '6.1', 'Certificate is invalid')

    # Check BasicConstraints - EUM is an intermediate CA so it should have CA:TRUE (?)
    try:
        basic_constraints = eum_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        if not basic_constraints.value.ca:
            # SGP.22 Table 49: EUM Certificate - Verification Failed
            raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
        # pathLenConstraint of 0 means it can only sign end-entity certificates
        if basic_constraints.value.path_length is not None and basic_constraints.value.path_length != 0:
            # SGP.22 Table 49: EUM Certificate - Verification Failed
            raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
    except x509.ExtensionNotFound:
        # SGP.22 Table 49: EUM Certificate - Verification Failed
        raise ApiError('8.1.2', '6.1', 'Certificate is invalid')


def validate_euicc_certificate(euicc_cert: x509.Certificate) -> None:
    """Validate eUICC certificate according to SGP.22 requirements.
    Raises ApiError with appropriate error codes for different validation failures."""

    # Check KeyUsage extension
    try:
        key_usage = euicc_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        if not key_usage.value.digital_signature:
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
        if key_usage.value.key_cert_sign:
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
    except x509.ExtensionNotFound:
        # SGP.22 Table 49: eUICC Certificate - Verification Failed
        raise ApiError('8.1.3', '6.1', 'Certificate is invalid')

    # ExtendedKeyUsage not present in eUICC certificates

    # Check Certificate Policies
    try:
        cert_policies = euicc_cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
        # Check for required eUICC policy OIDs
        has_valid_policy = False
        for policy in cert_policies.value:
            policy_oid = policy.policy_identifier.dotted_string
            # eUICC policies would be under GSMA arc
            if policy_oid.startswith('2.23.146.1.2.1'):
                has_valid_policy = True
                break
        if not has_valid_policy:
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
    except x509.ExtensionNotFound:
        # SGP.22 Table 49: eUICC Certificate - Verification Failed
        raise ApiError('8.1.3', '6.1', 'Certificate is invalid')

    # Check Subject fields
    subject = euicc_cert.subject

    # Verify Organization field
    try:
        org_attrs = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if not org_attrs:
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
    except Exception:
        # SGP.22 Table 49: eUICC Certificate - Verification Failed
        raise ApiError('8.1.3', '6.1', 'Certificate is invalid')

    # Verify SerialNumber field (contains EID)
    try:
        serial_attrs = subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        if not serial_attrs:
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
        eid = serial_attrs[0].value
        if len(eid) != 32 or not all(c in '0123456789ABCDEFabcdef' for c in eid):
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
    except Exception as e:
        if not isinstance(e, ApiError):
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')


class ApiError(Exception):
    def __init__(self, subject_code: str, reason_code: str, message: Optional[str] = None,
                 subject_id: Optional[str] = None):
        self.status_code = build_status_code(subject_code, reason_code, subject_id, message)

    def encode(self) -> str:
        """Encode the API Error into a responseHeader string."""
        js = {}
        build_resp_header(js, 'Failed', self.status_code)
        return json.dumps(js)

class SmDppHttpServer:
    app = Klein()

    @staticmethod
    def load_certs_from_path(path: str) -> List[x509.Certificate]:
        """Load all DER + PEM files from given directory path and return them as list of x509.Certificate
        instances."""
        certs = []
        for dirpath, dirnames, filenames in os.walk(path):
            for filename in filenames:
                cert = None
                if filename.endswith('.der'):
                    with open(os.path.join(dirpath, filename), 'rb') as f:
                        cert = x509.load_der_x509_certificate(f.read())
                elif filename.endswith('.pem'):
                    with open(os.path.join(dirpath, filename), 'rb') as f:
                        cert = x509.load_pem_x509_certificate(f.read())
                if cert:
                    # verify it is a CI certificate (keyCertSign + i-rspRole-ci)
                    if not cert_policy_has_oid(cert, oid.id_rspRole_ci):
                        raise ValueError("alleged CI certificate %s doesn't have CI policy" % filename)
                    certs.append(cert)
        return certs

    def ci_get_cert_for_pkid(self, ci_pkid: bytes) -> Optional[x509.Certificate]:
        """Find CI certificate for given key identifier."""
        for cert in self.ci_certs:
            logger.debug("cert: %s" % cert)
            subject_exts = list(filter(lambda x: isinstance(x.value, x509.SubjectKeyIdentifier), cert.extensions))
            logger.debug(subject_exts)
            subject_pkid = subject_exts[0].value
            logger.debug(subject_pkid)
            if subject_pkid and subject_pkid.key_identifier == ci_pkid:
                return cert
        return None

    def validate_certificate_chain_for_verification(self, euicc_ci_pkid_list: List[bytes]) -> bool:
        """Validate that SM-DP+ has valid certificate chains for the given CI PKIDs."""
        for ci_pkid in euicc_ci_pkid_list:
            ci_cert = self.ci_get_cert_for_pkid(ci_pkid)
            if ci_cert:
                # Check if our DPauth certificate chains to this CI
                try:
                    cs = CertificateSet(ci_cert)
                    cs.verify_cert_chain(self.dp_auth.cert)
                    return True
                except x509_err.VerifyError:
                    continue
        return False

    def __init__(self, server_hostname: str, ci_certs_path: str, common_cert_path: str, use_brainpool: bool = False, in_memory: bool = False, test_mode: bool = False):
        self.server_hostname = server_hostname
        self.upp_dir = os.path.realpath(os.path.join(DATA_DIR, 'upp'))
        self.ci_certs = self.load_certs_from_path(ci_certs_path)
        self.test_mode = test_mode
        self.confirmation_codes = {
            "CC_REQUIRED_TEST": "12345678"  # Special matchingId for confirmation code tests
        } if test_mode else {}

        self.require_confirmation_code = False  # Global flag - disabled by default
        # load DPauth cert + key
        self.dp_auth = CertAndPrivkey(oid.id_rspRole_dp_auth_v2)
        cert_dir = common_cert_path
        if use_brainpool:
            self.dp_auth.cert_from_der_file(os.path.join(cert_dir, 'DPauth', 'CERT_S_SM_DPauth_ECDSA_BRP.der'))
            self.dp_auth.privkey_from_pem_file(os.path.join(cert_dir, 'DPauth', 'SK_S_SM_DPauth_ECDSA_BRP.pem'))
        else:
            self.dp_auth.cert_from_der_file(os.path.join(cert_dir, 'DPauth', 'CERT_S_SM_DPauth_ECDSA_NIST.der'))
            self.dp_auth.privkey_from_pem_file(os.path.join(cert_dir, 'DPauth', 'SK_S_SM_DPauth_ECDSA_NIST.pem'))
        # load DPpb cert + key
        self.dp_pb = CertAndPrivkey(oid.id_rspRole_dp_pb_v2)
        if use_brainpool:
            self.dp_pb.cert_from_der_file(os.path.join(cert_dir, 'DPpb', 'CERT_S_SM_DPpb_ECDSA_BRP.der'))
            self.dp_pb.privkey_from_pem_file(os.path.join(cert_dir, 'DPpb', 'SK_S_SM_DPpb_ECDSA_BRP.pem'))
        else:
            self.dp_pb.cert_from_der_file(os.path.join(cert_dir, 'DPpb', 'CERT_S_SM_DPpb_ECDSA_NIST.der'))
            self.dp_pb.privkey_from_pem_file(os.path.join(cert_dir, 'DPpb', 'SK_S_SM_DPpb_ECDSA_NIST.pem'))
        if in_memory:
            self.rss = rsp.RspSessionStore(in_memory=True)
            logger.info("Using in-memory session storage")
        else:
            # Use different session database files for BRP and NIST to avoid file locking during concurrent runs
            session_db_suffix = "BRP" if use_brainpool else "NIST"
            db_path = os.path.join(DATA_DIR, f"sm-dp-sessions-{session_db_suffix}")
            self.rss = rsp.RspSessionStore(filename=db_path, in_memory=False)
            logger.info(f"Using file-based session storage: {db_path}")
        self.used_euicc_challenges = set()  # Track used eUICC challenges to prevent reuse
        self.otpk_mapping = {}  # Maps euicc_otpk -> (smdp_ot, smdp_otpk) for retry scenarios

        # Initialize profile configurations for test cases
        if test_mode:
            self._init_test_profiles()
        else:
            # Initialize empty profile dictionaries when not in test mode
            self.activation_code_profiles = {}
            self.event_based_profiles = {}
            self.default_profiles = {}

    def _init_test_profiles(self):
        """Initialize test profiles for different use cases."""
        # Activation code profiles
        print("INIT: Initializing test profiles...")
        self.activation_code_profiles = {
            'TEST123': {
                'matchingId': 'TEST123',
                'confirmationCode': '12345678',  # 8-digit numeric code
                'iccid': '8900000000000000001F',
                'profileName': 'Test Profile 1',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None
            },
            'AC_NOT_RELEASED': {
                'matchingId': 'AC_NOT_RELEASED',
                'confirmationCode': '87654321',
                'iccid': '8900000000000000002F',
                'profileName': 'Not Released Profile',
                'state': 'not_released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None
            },
            'AC_WITH_CC': {
                'matchingId': 'AC_WITH_CC',
                'confirmationCode': '11223344',
                'iccid': '8900000000000000003F',
                'profileName': 'Profile Requiring CC',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None
            },
            'AC_NO_CC': {
                'matchingId': 'AC_NO_CC',
                'confirmationCode': None,  # No confirmation code required
                'iccid': '8900000000000000004F',
                'profileName': 'Profile Without CC',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None
            },
            # Error test profiles
            'AC_NO_ELIGIBLE': {
                'matchingId': 'AC_NO_ELIGIBLE',
                'confirmationCode': None,
                'iccid': '8900000000000000009F',
                'profileName': 'Profile with No Eligible Device',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None,
                'device_requirements': {
                    'min_memory_mb': 999999,  # Impossible requirement
                    'required_features': ['IMPOSSIBLE_FEATURE']
                }
            },
            'AC_EXPIRED': {
                'matchingId': 'AC_EXPIRED',
                'confirmationCode': None,
                'iccid': '8900000000000000010F',
                'profileName': 'Expired Download Order',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': '2020-01-01T00:00:00Z'  # Expired
            },
            'AC_MAX_RETRIES': {
                'matchingId': 'AC_MAX_RETRIES',
                'confirmationCode': None,
                'iccid': '8900000000000000011F',
                'profileName': 'Max Retries Exceeded',
                'state': 'released',
                'download_attempts': 5,  # Already exceeded max attempts
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None
            },
            'AC_RESTRICTED_EID': {
                'matchingId': 'AC_RESTRICTED_EID',
                'confirmationCode': None,
                'iccid': '8900000000000000012F',
                'profileName': 'Profile Restricted to Different EID',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': '89999999999999999999999999999999',  # Different EID
                'expiration': None
            },
            'AC_OTHER_EID': {
                'matchingId': 'AC_OTHER_EID',
                'confirmationCode': None,
                'iccid': '8900000000000000013F',
                'profileName': 'Profile for Other EID',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': '89888888888888888888888888888888',  # Different EID
                'expiration': None
            },
            'MATCHING_ID_1': {
                'matchingId': 'MATCHING_ID_1',
                'confirmationCode': None,
                'iccid': '8900000000000000017F',
                'profileName': 'Test Activation Code Profile',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': '89049032123451234512345678901235',
                'expiration': None
            },
            'CC_REQUIRED_TEST': {
                'matchingId': 'CC_REQUIRED_TEST',
                'confirmationCode': '12345678',  # Requires confirmation code
                'iccid': '8900000000000000019F',
                'profileName': 'CC Required Test Profile',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None
            }
        }

        # SM-DS event-based profiles
        self.event_based_profiles = {
            'EVENT_001': {
                'matchingId': 'EVENT_001',
                'confirmationCode': '55667788',
                'iccid': '8900000000000000005F',
                'profileName': 'Event-based Profile 1',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None
            },
            'UNMATCHED_EVENT': {
                'matchingId': 'UNMATCHED_EVENT',
                'confirmationCode': '99887766',
                'iccid': '8900000000000000006F',
                'profileName': 'Unmatched Event Profile',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': '89001012012341234012345678901224',  # Different EID
                'expiration': None
            },
            'EVENT_NORMAL': {
                'matchingId': 'EVENT_NORMAL',
                'confirmationCode': None,
                'iccid': '8900000000000000014F',
                'profileName': 'Normal SM-DS Event',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None
            },
            'EVENT_RESTRICTED': {
                'matchingId': 'EVENT_RESTRICTED',
                'confirmationCode': None,
                'iccid': '8900000000000000015F',
                'profileName': 'SM-DS Event Restricted to Different EID',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': '89777777777777777777777777777777',  # Different EID
                'expiration': None
            },
            'MATCHING_ID_EVENT': {
                'matchingId': 'MATCHING_ID_EVENT',
                'confirmationCode': None,
                'iccid': '8900000000000000018F',
                'profileName': 'Test Event-based Profile',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': '89049032123451234512345678901235',
                'expiration': None
            }
        }

        # Default SM-DP+ profiles (associated with specific EIDs)
        self.default_profiles = {
            '89001012012341234012345678901234': {  # Test EID
                'confirmationCode': '12345678',
                'iccid': '8900000000000000007F',
                'profileName': 'Default Profile for Test EID',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'expiration': None
            },
            '89049032123451234512345678901235': {  # EID1 from test specs
                'confirmationCode': None,
                'iccid': '8900000000000000020F',
                'profileName': 'Default Profile for EID1',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'expiration': None
            },
        }

    @app.handle_errors(ApiError)
    def handle_apierror(self, request: IRequest, failure):
        request.setResponseCode(200)
        pp(failure)
        return failure.value.encode()

    @staticmethod
    def _ecdsa_verify(cert: x509.Certificate, signature: bytes, data: bytes) -> bool:
        pubkey = cert.public_key()
        dss_sig = ecdsa_tr03111_to_dss(signature)
        try:
            pubkey.verify(dss_sig, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def rsp_api_wrapper(func):
        """Wrapper that can be used as decorator in order to perform common REST API endpoint entry/exit
        functionality, such as JSON decoding/encoding and debug-printing."""
        @functools.wraps(func)
        def _api_wrapper(self, request: IRequest):
            validate_request_headers(request)

            content = json.loads(request.content.read())
            #logger.debug("Rx JSON: %s" % json.dumps(content))
            set_headers(request)

            output = func(self, request, content)
            if output == None:
                return ''

            build_resp_header(output)
            logger.debug("Tx JSON: %s" % json.dumps(output)[:200])
            return json.dumps(output)
        return _api_wrapper

    @app.route('/gsma/rsp2/es9plus/initiateAuthentication', methods=['POST'])
    @rsp_api_wrapper
    def initiateAuthentication(self, request: IRequest, content: dict) -> dict:
        """See ES9+ InitiateAuthentication SGP.22 Section 5.6.1"""
        # SGP.22 v2.5 Section 5.6.1: Verify that the received address matches its own SM-DP+ address,
        # where the comparison SHALL be case-insensitive.
        if content['smdpAddress'].lower() != self.server_hostname.lower():
           raise ApiError('8.8.1', '3.8', 'Invalid SM-DP+ Address')  # SGP.22 Table 46

        euiccChallenge = b64decode(content['euiccChallenge'])
        if len(euiccChallenge) != 16:
            raise ValueError

        # Check for eUICC challenge reuse (security requirement, not in spec)
        if euiccChallenge in self.used_euicc_challenges:
            raise ApiError('8.1', '3.1', 'eUICC challenge reuse detected')  # Generic security error
        self.used_euicc_challenges.add(euiccChallenge)

        euiccInfo1_bin = b64decode(content['euiccInfo1'])
        euiccInfo1 = rsp.asn1.decode('EUICCInfo1', euiccInfo1_bin)
        logger.debug("Rx euiccInfo1: %s" % euiccInfo1)

        # Validate specification version (SVN)
        svn = euiccInfo1.get('svn', b'\x02\x02\x00')  # Default to v2.2.0 if not present
        # Convert SVN bytes to version tuple (major, minor, revision)
        svn_version = (svn[0], svn[1], svn[2])

        # SM-DP+ supports versions from 2.0.0 to 2.3.x
        min_version = (2, 0, 0)
        max_version = (2, 3, 255)  # Allow any 2.3.x version

        if svn_version < min_version:
            # SGP.22 Table 46: Specification Version Number - Unsupported
            raise ApiError('8.8.3', '3.1', 'The Specification Version Number indicated by the eUICC is not supported by the SM-DP+')
        elif svn_version[:2] > max_version[:2]:  # Compare major.minor only for upper bound
            # SGP.22 Table 46: Specification Version Number - Unsupported
            raise ApiError('8.8.3', '3.1', 'The Specification Version Number indicated by the eUICC is not supported by the SM-DP+')

        # TODO: If euiccCiPKIdListForSigningV3 is present ...

        pkid_list = euiccInfo1['euiccCiPKIdListForSigning']
        if 'euiccCiPKIdListForSigningV3' in euiccInfo1:
            pkid_list = pkid_list + euiccInfo1['euiccCiPKIdListForSigningV3']

        # First verify PKIDs for signing are supported (check this before verification PKIDs)
        ci_cert = None
        for x in pkid_list:
            ci_cert = self.ci_get_cert_for_pkid(x)
            if not ci_cert:
                # Skip if no certificate found for this PKID
                continue
            # we already support multiple CI certificates but only one set of DPauth + DPpb keys. So we must
            # make sure we choose a CI key-id which has issued both the eUICC as well as our own SM-DP side
            # certs.
            try:
                ci_subject_key_id = cert_get_subject_key_id(ci_cert)
            except:
                # For CI certs, we need to get the subject key identifier differently
                subject_key_ext = ci_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                ci_subject_key_id = subject_key_ext.value.key_identifier

            if ci_subject_key_id == self.dp_auth.get_authority_key_identifier().key_identifier:
                break
            else:
                ci_cert = None
        if not ci_cert:
           raise ApiError('8.8.2', '3.1', 'None of the proposed Public Key Identifiers is supported by the SM-DP+')

        # After verifying signing PKIDs, validate certificate chains for verification
        verification_pkid_list = euiccInfo1.get('euiccCiPKIdListForVerification', [])
        if verification_pkid_list and not self.validate_certificate_chain_for_verification(verification_pkid_list):
            # SGP.22 Table 46: SM-DP+ Certificate - Unavailable
            raise ApiError('8.8.4', '3.7', 'The SM-DP+ has no CERT.DPAuth.ECDSA signed by one of the GSMA CI Public Key supported by the eUICC')

        # Generate a TransactionID which is used to identify the ongoing RSP session. The TransactionID
        # SHALL be unique within the scope and lifetime of each SM-DP+.
        transactionId = uuid.uuid4().hex.upper()
        assert not transactionId in self.rss

        # Generate a serverChallenge for eUICC authentication attached to the ongoing RSP session.
        serverChallenge = os.urandom(16)

        # Generate a serverSigned1 data object as expected by the eUICC and described in section 5.7.13 "ES10b.AuthenticateServer". If and only if both eUICC and LPA indicate crlStaplingV3Support, the SM-DP+ SHALL indicate crlStaplingV3Used in sessionContext.
        serverSigned1 = {
            'transactionId': h2b(transactionId),
            'euiccChallenge': euiccChallenge,
            'serverAddress': self.server_hostname,
            'serverChallenge': serverChallenge,
            }
        logger.debug("Tx serverSigned1: %s" % serverSigned1)
        serverSigned1_bin = rsp.asn1.encode('ServerSigned1', serverSigned1)
        logger.debug("Tx serverSigned1: %s" % rsp.asn1.decode('ServerSigned1', serverSigned1_bin))
        output = {}
        output['serverSigned1'] = b64encode2str(serverSigned1_bin)

        # Generate a signature (serverSignature1) as described in section 5.7.13 "ES10b.AuthenticateServer" using the SK related to the selected CERT.DPauth.SIG.
        # serverSignature1 SHALL be created using the private key associated to the RSP Server Certificate for authentication, and verified by the eUICC using the contained public key as described in section 2.6.9. serverSignature1 SHALL apply on serverSigned1 data object.
        output['serverSignature1'] = b64encode2str(b'\x5f\x37\x40' + self.dp_auth.ecdsa_sign(serverSigned1_bin))

        output['transactionId'] = transactionId
        server_cert_aki = self.dp_auth.get_authority_key_identifier()
        output['euiccCiPKIdToBeUsed'] = b64encode2str(b'\x04\x14' + server_cert_aki.key_identifier)
        output['serverCertificate'] = b64encode2str(self.dp_auth.get_cert_as_der()) # CERT.DPauth.SIG
        # FIXME: add those certificate
        #output['otherCertsInChain'] = b64encode2str()

        # create SessionState and store it in rss
        self.rss[transactionId] = rsp.RspSessionState(transactionId, serverChallenge,
                                                      cert_get_subject_key_id(ci_cert))

        return output

    @app.route('/gsma/rsp2/es9plus/authenticateClient', methods=['POST'])
    @rsp_api_wrapper
    def authenticateClient(self, request: IRequest, content: dict) -> dict:
        """See ES9+ AuthenticateClient in SGP.22 Section 5.6.3"""
        transactionId = content['transactionId']

        authenticateServerResp_bin = b64decode(content['authenticateServerResponse'])
        authenticateServerResp = rsp.asn1.decode('AuthenticateServerResponse', authenticateServerResp_bin)
        logger.debug("Rx %s: %s" % authenticateServerResp)
        if authenticateServerResp[0] == 'authenticateResponseError':
            r_err = authenticateServerResp[1]
            #r_err['transactionId']
            #r_err['authenticateErrorCode']
            raise ValueError("authenticateResponseError %s" % r_err)

        r_ok = authenticateServerResp[1]
        euiccSigned1 = r_ok['euiccSigned1']
        euiccSigned1_bin = rsp.extract_euiccSigned1(authenticateServerResp_bin)
        euiccSignature1_bin = r_ok['euiccSignature1']
        euiccCertificate_dec = r_ok['euiccCertificate']
        # TODO: use original data, don't re-encode?
        euiccCertificate_bin = rsp.asn1.encode('Certificate', euiccCertificate_dec)
        eumCertificate_dec = r_ok['eumCertificate']
        eumCertificate_bin = rsp.asn1.encode('Certificate', eumCertificate_dec)
        # TODO v3: otherCertsInChain

        # load certificate
        euicc_cert = x509.load_der_x509_certificate(euiccCertificate_bin)
        eum_cert = x509.load_der_x509_certificate(eumCertificate_bin)

        # Verify that the transactionId is known and relates to an ongoing RSP session.
        ss = self.rss.get(transactionId, None)
        if ss is None:
            # SGP.22 Table 49: TransactionId - Unknown
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the TransactionID is unknown')
        ss.euicc_cert = euicc_cert
        ss.eum_cert = eum_cert # TODO: do we need this in the state?

        # First verify that the Root Certificate of the eUICC certificate chain corresponds to the
        # euiccCiPKIdToBeUsed - this check must come before detailed certificate validation
        try:
            eum_auth_key_id = cert_get_auth_key_id(eum_cert)
        except (ExtensionNotFound, Exception) as e:
            logger.error(f"Failed to get AuthorityKeyIdentifier from EUM certificate: {e}")
            # SGP.22 Table 49: EUM Certificate - Verification Failed
            raise ApiError('8.1.2', '6.1', 'Certificate is invalid')

        if eum_auth_key_id != ss.ci_cert_id:
            # SGP.22 Table 49: CI Public Key - Unknown
            raise ApiError('8.11.1', '3.9', 'Unknown CI Public Key. The CI used by the EUM Certificate is not a trusted root for the SM-DP+')

        # Certificate validation checks - only do after CI key verification
        try:
            # Check if certificates are valid (not expired, proper format, etc.)
            now = datetime.now(timezone.utc)

            # Check EUM certificate validity period
            if eum_cert.not_valid_after_utc < now:
                # SGP.22 Table 49: EUM Certificate - Expired
                raise ApiError('8.1.2', '6.3', 'Certificate has expired')
            if eum_cert.not_valid_before_utc > now:
                # SGP.22 Table 49: EUM Certificate - Verification Failed
                raise ApiError('8.1.2', '6.1', 'Certificate is invalid')

            # Check eUICC certificate validity period
            if euicc_cert.not_valid_after_utc < now:
                # SGP.22 Table 49: eUICC Certificate - Expired
                raise ApiError('8.1.3', '6.3', 'Certificate has expired')
            if euicc_cert.not_valid_before_utc > now:
                # SGP.22 Table 49: eUICC Certificate - Verification Failed
                raise ApiError('8.1.3', '6.1', 'Certificate is invalid')

            # Perform detailed certificate validation
            validate_eum_certificate(eum_cert)
            validate_euicc_certificate(euicc_cert)

        except ApiError:
            raise  # Re-raise our API errors
        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')

        # Verify the validity of the eUICC certificate chain
        try:
            cs = CertificateSet(self.ci_get_cert_for_pkid(ss.ci_cert_id))
            cs.add_intermediate_cert(eum_cert)
            # TODO v3: otherCertsInChain
            cs.verify_cert_chain(euicc_cert)
        except x509_err.MissingIntermediateCert as e:
            # Check if the missing certificate is the EUM cert
            if hasattr(e, 'auth_key_id') and e.auth_key_id == b2h(cert_get_auth_key_id(eum_cert)):
                # SGP.22 Table 49: EUM Certificate - Verification Failed
                raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
            else:
                # SGP.22 Table 49: eUICC Certificate - Verification Failed
                raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
        except x509_err.CertificateRevoked as e:
            # Determine which certificate is revoked based on the error details
            if 'EUM' in str(e) or (hasattr(e, 'cert') and e.cert == eum_cert):
                # SGP.22 Table 49: EUM Certificate - Expired (revoked uses expired code)
                raise ApiError('8.1.2', '6.3', 'Certificate has expired')
            else:
                # SGP.22 Table 49: eUICC Certificate - Expired (revoked uses expired code)
                raise ApiError('8.1.3', '6.3', 'Certificate has expired')
        except x509_err.MaxDepthExceeded as e:
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
        except x509_err.SignatureVerification as e:
            # Check which certificate's signature failed
            error_str = str(e)
            if 'EUM' in error_str or 'intermediate' in error_str:
                # SGP.22 Table 49: EUM Certificate - Verification Failed
                raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
            else:
                # SGP.22 Table 49: eUICC Certificate - Verification Failed
                raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
        except x509_err.VerifyError as e:
            # Generic certificate chain error for any other x509_err subclasses
            error_str = str(e)
            if 'EUM' in error_str or 'intermediate' in error_str:
                # SGP.22 Table 49: EUM Certificate - Verification Failed
                raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
            else:
                # SGP.22 Table 49: eUICC Certificate - Verification Failed
                raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
        except ValueError as e:
            # This could be raised by add_intermediate_cert for invalid EUM cert
            if 'intermediate certificate' in str(e):
                # SGP.22 Table 49: EUM Certificate - Verification Failed
                raise ApiError('8.1.2', '6.1', 'Certificate is invalid')
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')
        except Exception as e:
            logger.error(f"Certificate chain verification error: {e}")
            # Check if it's a missing CI certificate issue
            if 'ci_cert_id' in str(e) or 'Unknown' in str(e):
                # SGP.22 Table 49: CI Public Key - Unknown
                raise ApiError('8.11.1', '3.9', 'Unknown CI Public Key. The CI used by the EUM Certificate is not a trusted root for the SM-DP+')
            # SGP.22 Table 49: eUICC Certificate - Verification Failed
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')


        # Verify euiccSignature1 over euiccSigned1 using pubkey from euiccCertificate.
        if not self._ecdsa_verify(euicc_cert, euiccSignature1_bin, euiccSigned1_bin):
            # SGP.22 Table 49: eUICC - Verification Failed
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid or serverChallenge is invalid')

        ss.eid = ss.euicc_cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
        logger.debug("EID (from eUICC cert): %s" % ss.eid)

        # Verify EID is within permitted range of EUM certificate
        if not validate_eid_range(ss.eid, eum_cert):
            # Use eUICC Certificate error since EID is from eUICC cert
            raise ApiError('8.1.3', '6.1', 'Certificate is invalid')

        # Verify that the serverChallenge attached to the ongoing RSP session matches the
        # serverChallenge returned by the eUICC.
        if euiccSigned1['serverChallenge'] != ss.serverChallenge:
            # SGP.22 Table 49: eUICC - Verification Failed
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid or serverChallenge is invalid')

        # Verify that the transactionId in euiccSigned1 matches the outer transactionId
        if euiccSigned1['transactionId'] != h2b(transactionId):
            # SGP.22 Table 49: TransactionId - Unknown
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the TransactionID is unknown')

        # If ctxParams1 contains a ctxParamsForCommonAuthentication data object, the SM-DP+ Shall [...]
        if euiccSigned1['ctxParams1'][0] == 'ctxParamsForCommonAuthentication':
            cpca = euiccSigned1['ctxParams1'][1]
            matchingId = cpca.get('matchingId', None)
            logger.debug(f"Extracted matchingId from request: {matchingId}")

            # Determine use case and find profile
            profile_info = None
            iccid_str = None

            if not matchingId or matchingId == '':
                # Default SM-DP+ address use case - check if EID has pending profile
                logger.debug(f"Default SM-DP+ use case for EID: {ss.eid}")
                if self.test_mode and ss.eid in self.default_profiles:
                    profile_info = self.default_profiles[ss.eid]
                    iccid_str = profile_info['iccid']
                    ss.matchingId = None  # No matchingId for default case
                elif not self.test_mode:
                    # In production mode, try to load a default profile from file system
                    # This is where real implementation would check database/backend
                    # SGP.22 Table 49: EID - Refused
                    raise ApiError('8.1.1', '3.8', 'EID doesn\'t match the expected value')
                else:
                    # Test mode but no profile for this EID
                    # SGP.22 Table 49: EID - Refused
                    raise ApiError('8.1.1', '3.8', 'EID doesn\'t match the expected value')

            elif self.test_mode and matchingId.startswith('EVENT_'):
                # SM-DS event-based use case (test mode only)
                logger.debug(f"SM-DS event use case with matchingId: {matchingId}")
                if matchingId in self.event_based_profiles:
                    profile_info = self.event_based_profiles[matchingId]
                    # Check if profile is associated with specific EID
                    if profile_info.get('associated_eid') and profile_info['associated_eid'] != ss.eid:
                        # SGP.22 Table 49: EID - Refused
                        raise ApiError('8.1.1', '3.8', 'EID doesn\'t match the expected value')
                    iccid_str = profile_info['iccid']
                    ss.matchingId = matchingId
                else:
                    # SGP.22 Table 49: MatchingID - Refused
                    raise ApiError('8.2.6', '3.8', 'MatchingID (AC_Token or EventID) is refused')

            else:
                # Activation code use case
                logger.debug(f"Activation code use case with matchingId: {matchingId}")
                logger.debug(f"Available activation codes: {list(self.activation_code_profiles.keys())}")
                if self.test_mode and matchingId in self.activation_code_profiles:
                    profile_info = self.activation_code_profiles[matchingId]
                    # Check if profile is associated with specific EID
                    if profile_info.get('associated_eid') and profile_info['associated_eid'] != ss.eid:
                        # SGP.22 Table 49: EID - Refused
                        raise ApiError('8.1.1', '3.8', 'EID doesn\'t match the expected value')
                    iccid_str = profile_info['iccid']
                    ss.matchingId = matchingId
                else:
                    # Try to load from file system (legacy support)
                    path = os.path.join(self.upp_dir, matchingId) + '.der'
                    # prevent directory traversal attack
                    if os.path.commonprefix((os.path.realpath(path),self.upp_dir)) != self.upp_dir:
                        # SGP.22 Table 49: MatchingID - Refused
                        raise ApiError('8.2.6', '3.8', 'MatchingID (AC_Token or EventID) is refused')
                    if os.path.isfile(path) and os.access(path, os.R_OK):
                        with open(path, 'rb') as f:
                            pes = saip.ProfileElementSequence.from_der(f.read())
                            iccid_str = b2h(pes.get_pe_for_type('header').decoded['iccid'])
                        ss.matchingId = matchingId
                        # Create a temporary profile info for legacy files
                        profile_info = {
                            'confirmationCode': self.confirmation_codes.get(matchingId),
                            'state': 'released',
                            'profileName': matchingId
                        }
                    else:
                        # SGP.22 Table 49: MatchingID - Refused
                        raise ApiError('8.2.6', '3.8', 'MatchingID (AC_Token or EventID) is refused')

            # Validate profile state and other conditions
            if profile_info:
                # Check if profile is released
                if profile_info.get('state') == 'not_released':
                    # SGP.22 Table 49: Profile - Not allowed
                    raise ApiError('8.2', '1.2', 'Profile has not yet been released')

                # Check for expired download order
                if profile_info.get('expiration'):
                    exp_date = datetime.fromisoformat(profile_info['expiration'].replace('Z', '+00:00'))
                    if datetime.now(timezone.utc) > exp_date:
                        # SGP.22 Table 49: Download order - Time to Live Expired
                        raise ApiError('8.8.5', '4.10', 'The Download order has expired')

                # Check maximum download attempts
                if profile_info.get('download_attempts', 0) >= 3:
                    # SGP.22 Table 49: Download order - Maximum number of retries exceeded
                    raise ApiError('8.8.5', '6.4', 'The maximum number of retries for the Profile download order has been exceeded')

                # Check device eligibility (for Test #15 - test mode only)
                if self.test_mode and profile_info.get('device_requirements'):
                    # Simple check - in real implementation would check against actual device capabilities
                    if profile_info['device_requirements'].get('min_memory_mb', 0) > 1000:
                        # SGP.22 Table 49: Profile Type - Stopped on warning
                        raise ApiError('8.2.5', '4.3', 'No eligible Profile for this eUICC/Device')

                # Set confirmation code requirement
                # Special handling: When matchingId is omitted or empty, don't require confirmation code
                # per SGP.23 test sequences #14-#18
                if not matchingId or matchingId == '':
                    ss.ccRequiredFlag = False
                    logger.info("ccRequiredFlag=False for omitted/empty matchingId (default SM-DP+ use case)")
                elif profile_info.get('confirmationCode'):
                    ss.ccRequiredFlag = True
                    ss.expected_confirmation_code = profile_info['confirmationCode']
                    logger.info(f"Set ccRequiredFlag=True with code: {ss.expected_confirmation_code}")
                else:
                    ss.ccRequiredFlag = False
                    logger.info("ccRequiredFlag=False, no confirmation code required")

                # Use profile name from profile_info if available
                profile_name = profile_info.get('profileName', matchingId or 'DefaultProfile')
            else:
                # Should not happen if all cases are handled above
                raise ApiError('8.2.6', '3.8', 'Profile not found')
        else:
            # there's currently no other option in the ctxParams1 choice, so this cannot happen
            raise ApiError('1.3.1', '2.2', 'ctxParams1 missing mandatory ctxParamsForCommonAuthentication')

        # FIXME: we actually want to perform the profile binding herr, and read the profile metadat from the profile

        # Put together profileMetadata + _bin
        ss.profileMetadata = ProfileMetadata(iccid_bin=h2b(swap_nibbles(iccid_str)), spn="OsmocomSPN", profile_name=profile_name)
        # enable notifications for all operations
        for event in ['enable', 'disable', 'delete']:
            ss.profileMetadata.add_notification(event, self.server_hostname)
        profileMetadata_bin = ss.profileMetadata.gen_store_metadata_request()

        # Put together smdpSigned2 + _bin
        cc_flag = getattr(ss, 'ccRequiredFlag', False)
        logger.info(f"Setting ccRequiredFlag in SmdpSigned2: {cc_flag}")
        logger.info(f"Session state has ccRequiredFlag: {hasattr(ss, 'ccRequiredFlag')}")
        if hasattr(ss, 'ccRequiredFlag'):
            logger.info(f"Session ccRequiredFlag value: {ss.ccRequiredFlag}")
        smdpSigned2 = {
            'transactionId': h2b(ss.transactionId),
            'ccRequiredFlag': cc_flag,  # whether the Confirmation Code is required
            #'bppEuiccOtpk': None,           # whether otPK.EUICC.ECKA already used for binding the BPP, tag '5F49'
            }
        smdpSigned2_bin = rsp.asn1.encode('SmdpSigned2', smdpSigned2)
        logger.info(f"Encoded smdpSigned2 with ccRequiredFlag={cc_flag}")

        ss.smdpSignature2_do = b'\x5f\x37\x40' + self.dp_pb.ecdsa_sign(smdpSigned2_bin + b'\x5f\x37\x40' + euiccSignature1_bin)

        # update non-volatile state with updated ss object
        self.rss[transactionId] = ss
        return {
            'transactionId': transactionId,
            'profileMetadata': b64encode2str(profileMetadata_bin),
            'smdpSigned2': b64encode2str(smdpSigned2_bin),
            'smdpSignature2': b64encode2str(ss.smdpSignature2_do),
            'smdpCertificate': b64encode2str(self.dp_pb.get_cert_as_der()), # CERT.DPpb.SIG
        }

    @app.route('/gsma/rsp2/es9plus/getBoundProfilePackage', methods=['POST'])
    @rsp_api_wrapper
    def getBoundProfilePackage(self, request: IRequest, content: dict) -> dict:
        """See ES9+ GetBoundProfilePackage SGP.22 Section 5.6.2"""
        transactionId = content['transactionId']

        # Verify that the received transactionId is known and relates to an ongoing RSP session
        ss = self.rss.get(transactionId, None)
        if not ss:
            # SGP.22 Table 51: TransactionId - Unknown
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the TransactionID is unknown')

        prepDownloadResp_bin = b64decode(content['prepareDownloadResponse'])
        prepDownloadResp = rsp.asn1.decode('PrepareDownloadResponse', prepDownloadResp_bin)
        logger.debug("Rx %s: %s" % prepDownloadResp)

        if prepDownloadResp[0] == 'downloadResponseError':
            r_err = prepDownloadResp[1]
            #r_err['transactionId']
            #r_err['downloadErrorCode']
            # Download error from eUICC - use generic eUICC verification failed
            download_error_code = r_err.get('downloadErrorCode', 'unknown')
            # SGP.22 Table 51: eUICC - Verification Failed
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid')

        r_ok = prepDownloadResp[1]

        # Verify the euiccSignature2 computed over euiccSigned2 and smdpSignature2 using the PK.EUICC.SIG attached to the ongoing RSP session
        euiccSigned2 = r_ok['euiccSigned2']
        euiccSigned2_bin = rsp.extract_euiccSigned2(prepDownloadResp_bin)
        if not self._ecdsa_verify(ss.euicc_cert, r_ok['euiccSignature2'], euiccSigned2_bin + ss.smdpSignature2_do):
            # SGP.22 Table 51: eUICC - Verification Failed
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid')

        # not in spec: Verify that signed TransactionID is outer transaction ID
        if h2b(transactionId) != euiccSigned2['transactionId']:
            # SGP.22 Table 51: TransactionId - Unknown
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the TransactionID is unknown')

        # store otPK.EUICC.ECKA in session state
        ss.euicc_otpk = euiccSigned2['euiccOtpk']
        logger.debug("euiccOtpk: %s" % (b2h(ss.euicc_otpk)))

        # Generate a one-time ECKA key pair (ot{PK,SK}.DP.ECKA) using the curve indicated by the Key Parameter
        # Reference value of CERT.DPpb.ECDDSA
        logger.debug("curve = %s" % self.dp_pb.get_curve())

        # Check if we've seen this euicc_otpk before (retry scenario)
        euicc_otpk_hex = b2h(euiccSigned2['euiccOtpk'])
        if euicc_otpk_hex in self.otpk_mapping:
            # Retry scenario - reuse existing keys
            existing_data = self.otpk_mapping[euicc_otpk_hex]
            ss.smdp_ot = existing_data['smdp_ot']
            ss.smdp_otpk = existing_data['smdp_otpk']
            logger.debug("Retry scenario detected - reusing existing smdp_otpk")
            logger.debug("smdpOtpk (reused): %s" % b2h(ss.smdp_otpk))
        else:
            # Generate new keys
            ss.smdp_ot = ec.generate_private_key(self.dp_pb.get_curve())
            # extract the public key in (hopefully) the right format for the ES8+ interface
            ss.smdp_otpk = ss.smdp_ot.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            logger.debug("smdpOtpk: %s" % b2h(ss.smdp_otpk))
            logger.debug("smdpOtsk: %s" % b2h(ss.smdp_ot.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())))

            # Store the mapping for retry scenarios
            self.otpk_mapping[euicc_otpk_hex] = {
                'smdp_ot': ss.smdp_ot,
                'smdp_otpk': ss.smdp_otpk,
                'timestamp': time.time()
            }

        ss.host_id = b'mahlzeit'

        # Generate Session Keys using the CRT, otPK.eUICC.ECKA and otSK.DP.ECKA according to annex G
        euicc_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ss.smdp_ot.curve, ss.euicc_otpk)
        ss.shared_secret = ss.smdp_ot.exchange(ec.ECDH(), euicc_public_key)
        logger.debug("shared_secret: %s" % b2h(ss.shared_secret))

        # Check if this order requires a Confirmation Code verification
        if getattr(ss, 'ccRequiredFlag', False):
            if 'hashCc' not in euiccSigned2:
                # SGP.22 Table 51: Confirmation Code - Mandatory Element Missing
                raise ApiError('8.2.7', '2.2', 'Confirmation Code is missing')

            received_hash = euiccSigned2['hashCc']
            expected_hash = compute_confirmation_code_hash(
                getattr(ss, 'expected_confirmation_code', ''),
                h2b(transactionId)
            )

            if received_hash != expected_hash:
                logger.debug("Confirmation code verification failed")
                logger.debug(f"Expected hash: {b2h(expected_hash)}")
                logger.debug(f"Received hash: {b2h(received_hash)}")
                # SGP.22 Table 51: Confirmation Code - Refused
                raise ApiError('8.2.7', '3.8', 'Confirmation Code is refused')

        # Perform actual protection + binding of profile package (or return  pre-bound one)
        with open(os.path.join(self.upp_dir, ss.matchingId)+'.der', 'rb') as f:
            upp = UnprotectedProfilePackage.from_der(f.read(), metadata=ss.profileMetadata)
            # HACK: Use empty PPP as we're still debuggin the configureISDP step, and we want to avoid
            # cluttering the log with stuff happening after the failure
            #upp = UnprotectedProfilePackage.from_der(b'', metadata=ss.profileMetadata)
        if False:
            # Use random keys
            bpp = BoundProfilePackage.from_upp(upp)
        else:
            # Use sesssion keys
            ppp = ProtectedProfilePackage.from_upp(upp, BspInstance(b'\x00'*16, b'\x11'*16, b'\x22'*16))
            bpp = BoundProfilePackage.from_ppp(ppp)

        # update non-volatile state with updated ss object
        self.rss[transactionId] = ss
        return {
            'transactionId': transactionId,
            'boundProfilePackage': b64encode2str(bpp.encode(ss, self.dp_pb)),
        }

    @app.route('/gsma/rsp2/es9plus/handleNotification', methods=['POST'])
    @rsp_api_wrapper
    def handleNotification(self, request: IRequest, content: dict) -> dict:
        """See ES9+ HandleNotification in SGP.22 Section 5.6.4"""
        # SGP.22 Section 6.3: "A normal notification function execution status (MEP Notification)
        # SHALL be indicated by the HTTP status code '204' (No Content) with an empty HTTP response body"
        request.setResponseCode(204)
        pendingNotification_bin = b64decode(content['pendingNotification'])
        pendingNotification = rsp.asn1.decode('PendingNotification', pendingNotification_bin)
        logger.debug("Rx %s: %s" % pendingNotification)
        if pendingNotification[0] == 'profileInstallationResult':
            profileInstallRes = pendingNotification[1]
            pird = profileInstallRes['profileInstallationResultData']
            transactionId = b2h(pird['transactionId'])
            ss = self.rss.get(transactionId, None)
            if ss is None:
                # For unknown transactionId, terminate processing but still return 204
                logger.warning(f"Unable to find session for transactionId: {transactionId}")
                return None  # Will return HTTP 204 with empty body
            profileInstallRes['euiccSignPIR']
            # TODO: use original data, don't re-encode?
            pird_bin = rsp.asn1.encode('ProfileInstallationResultData', pird)
            # verify eUICC signature
            if not self._ecdsa_verify(ss.euicc_cert, profileInstallRes['euiccSignPIR'], pird_bin):
                # Even on verification failure, acknowledge receipt with HTTP 204
                logger.error('ECDSA signature verification failed on notification')
                return None  # Will return HTTP 204 with empty body
            logger.debug("Profile Installation Final Result: %s", pird['finalResult'])
            # remove session state
            del self.rss[transactionId]
        elif pendingNotification[0] == 'otherSignedNotification':
            otherSignedNotif = pendingNotification[1]
            # TODO: use some kind of partially-parsed original data, don't re-encode?
            euiccCertificate_bin = rsp.asn1.encode('Certificate', otherSignedNotif['euiccCertificate'])
            eumCertificate_bin = rsp.asn1.encode('Certificate', otherSignedNotif['eumCertificate'])
            euicc_cert = x509.load_der_x509_certificate(euiccCertificate_bin)
            eum_cert = x509.load_der_x509_certificate(eumCertificate_bin)
            ci_cert_id = cert_get_auth_key_id(eum_cert)
            # Verify the validity of the eUICC certificate chain
            cs = CertificateSet(self.ci_get_cert_for_pkid(ci_cert_id))
            cs.add_intermediate_cert(eum_cert)
            # TODO v3: otherCertsInChain
            cs.verify_cert_chain(euicc_cert)
            tbs_bin = rsp.asn1.encode('NotificationMetadata', otherSignedNotif['tbsOtherNotification'])
            if not self._ecdsa_verify(euicc_cert, otherSignedNotif['euiccNotificationSignature'], tbs_bin):
                # Even on verification failure, acknowledge receipt with HTTP 204
                logger.error('ECDSA signature verification failed on notification')
                return None  # Will return HTTP 204 with empty body
            other_notif = otherSignedNotif['tbsOtherNotification']
            pmo = PMO.from_bitstring(other_notif['profileManagementOperation'])
            eid = euicc_cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
            iccid = other_notif.get('iccid', None)
            if iccid:
                iccid = swap_nibbles(b2h(iccid))
            logger.debug("handleNotification: EID %s: %s of %s" % (eid, pmo, iccid))
        else:
            # Unknown notification type - still acknowledge with HTTP 204
            logger.error(f"Unknown notification type: {pendingNotification[0]}")
        return None  # Always return HTTP 204 with empty body

    #@app.route('/gsma/rsp3/es9plus/handleDeviceChangeRequest, methods=['POST']')
    #@rsp_api_wrapper
        #"""See ES9+ ConfirmDeviceChange in SGP.22 Section 5.6.6"""
        # TODO: implement this

    @app.route('/gsma/rsp2/es9plus/cancelSession', methods=['POST'])
    @rsp_api_wrapper
    def cancelSession(self, request: IRequest, content: dict) -> dict:
        """See ES9+ CancelSession in SGP.22 Section 5.6.5"""
        logger.debug("Rx JSON: %s" % content)
        transactionId = content['transactionId']

        # Verify that the received transactionId is known and relates to an ongoing RSP session
        ss = self.rss.get(transactionId, None)
        if ss is None:
            # SGP.22 Table 52: TransactionId - Unknown
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the TransactionID is unknown')

        cancelSessionResponse_bin = b64decode(content['cancelSessionResponse'])
        cancelSessionResponse = rsp.asn1.decode('CancelSessionResponse', cancelSessionResponse_bin)
        logger.debug("Rx %s: %s" % cancelSessionResponse)

        if cancelSessionResponse[0] == 'cancelSessionResponseError':
            # FIXME: print some error
            return
        cancelSessionResponseOk = cancelSessionResponse[1]
        # TODO: use original data, don't re-encode?
        ecsr = cancelSessionResponseOk['euiccCancelSessionSigned']
        ecsr_bin = rsp.asn1.encode('EuiccCancelSessionSigned', ecsr)
        # Verify the eUICC signature (euiccCancelSessionSignature) using the PK.EUICC.SIG attached to the ongoing RSP session
        if not self._ecdsa_verify(ss.euicc_cert, cancelSessionResponseOk['euiccCancelSessionSignature'], ecsr_bin):
            # SGP.22 Table 52: eUICC - Verification Failed
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid')

        # Verify that the received smdpOid corresponds to the one in SM-DP+ CERT.DPauth.SIG
        subj_alt_name = self.dp_auth.get_subject_alt_name()

        # Extract the SM-DP+ OID from the SubjectAlternativeName extension
        smdp_oid_from_cert = None
        for item in subj_alt_name:
            if isinstance(item, x509.RegisteredID):
                smdp_oid_from_cert = item.value
                break

        if not smdp_oid_from_cert:
            logger.error("No RegisteredID found in SM-DP+ certificate SubjectAlternativeName")
            # SGP.22 Table 52: SM-DP+ - Invalid Association
            raise ApiError('8.8', '3.10', 'The provided SM-DP+ OID is invalid')

        received_oid = x509.ObjectIdentifier(ecsr['smdpOid'])

        if received_oid != smdp_oid_from_cert:
            logger.error(f"OID mismatch: received {received_oid}, expected {smdp_oid_from_cert}")
            # SGP.22 Table 52: SM-DP+ - Invalid Association
            raise ApiError('8.8', '3.10', 'The provided SM-DP+ OID is invalid')

        if ecsr['transactionId'] != h2b(transactionId):
            # SGP.22 Table 52: TransactionId - Unknown
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the TransactionID is unknown')

        # TODO: 1. Notify the Operator using the function "ES2+.HandleNotification" function
        # TODO: 2. Terminate the corresponding pending download process.
        # TODO: 3. If required, execute the SM-DS Event Deletion procedure described in section 3.6.3.

        # delete actual session data
        del self.rss[transactionId]
        # Per SGP.22 section 6.5.2.10, cancelSession returns an empty response (header only)
        return {}


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host/IP to bind HTTP to", default="localhost")
    parser.add_argument("-p", "--port", help="TCP port to bind HTTP to", default=8000)
    parser.add_argument("-c", "--certdir", help=f"cert subdir relative to {DATA_DIR}", default="certs")
    parser.add_argument("-s", "--nossl", help="do NOT use ssl", action='store_true', default=False)
    parser.add_argument("-v", "--verbose", help="dump more raw info", action='store_true', default=False)
    parser.add_argument("-b", "--brainpool", help="Use Brainpool curves instead of NIST",
                        action='store_true', default=False)
    parser.add_argument("-m", "--in-memory", help="Use ephermal in-memory session storage (for concurrent runs)",
                        action='store_true', default=False)
    parser.add_argument("-t", "--test", help="Enable test mode with hardcoded test profiles",
                        action='store_true', default=False)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    common_cert_path = os.path.join(DATA_DIR, args.certdir)
    hs = SmDppHttpServer(server_hostname=HOSTNAME, ci_certs_path=os.path.join(common_cert_path, 'CertificateIssuer'), common_cert_path=common_cert_path, use_brainpool=args.brainpool, test_mode=args.test)
    if(args.nossl):
        hs.app.run(args.host, args.port)
    else:
        curve_type = 'BRP' if args.brainpool else 'NIST'
        cert_derpath = Path(common_cert_path) / 'DPtls' / f'CERT_S_SM_DP_TLS_{curve_type}.der'
        cert_pempath = Path(common_cert_path) / 'DPtls' / f'CERT_S_SM_DP_TLS_{curve_type}.pem'
        cert_skpath = Path(common_cert_path) / 'DPtls' / f'SK_S_SM_DP_TLS_{curve_type}.pem'
        dhparam_path = Path(common_cert_path) / "dhparam2048.pem"
        if not dhparam_path.exists():
            print("Generating dh params, this takes a few seconds..")
            # Generate DH parameters with 2048-bit key size and generator 2
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            pem_data = parameters.parameter_bytes(encoding=Encoding.PEM,format=ParameterFormat.PKCS3)
            with open(dhparam_path, 'wb') as file:
                file.write(pem_data)
            print("DH params created successfully")

        if not cert_pempath.exists():
            print("Translating tls server cert from DER to PEM..")
            with open(cert_derpath, 'rb') as der_file:
                der_cert_data = der_file.read()

            cert = x509.load_der_x509_certificate(der_cert_data)
            pem_cert = cert.public_bytes(Encoding.PEM) #.decode('utf-8')

            with open(cert_pempath, 'wb') as pem_file:
                pem_file.write(pem_cert)

        SERVER_STRING = f'ssl:{args.port}:privateKey={cert_skpath}:certKey={cert_pempath}:dhParameters={dhparam_path}'
        print(SERVER_STRING)

        hs.app.run(host=HOSTNAME, port=args.port, endpoint_description=SERVER_STRING)

if __name__ == "__main__":
    main(sys.argv)
