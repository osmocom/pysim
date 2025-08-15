#!/usr/bin/env python3
# Common validation and utility functions for the smdpp.
#
# (C) 2025 by Eric Wild <ewild@sysmocom.de>
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

import json
from typing import Dict, List, Optional
import logging
import asn1tools
from cryptography import x509

logger = logging.getLogger(__name__)

class ApiError(Exception):
    def __init__(self, subject_code: str, reason_code: str, message: Optional[str] = None,
                 subject_id: Optional[str] = None):
        self.status_code = build_status_code(subject_code, reason_code, subject_id, message)

    def encode(self) -> str:
        """Encode the API Error into a responseHeader string."""
        js = {}
        build_resp_header(js, 'Failed', self.status_code)
        return json.dumps(js)

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
        permitted_iins.extend(_parse_name_constraints_eins(eum_cert))

    else:
        # New variants (Ov3, A, B, C) - use GSMA permittedEins extension
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

        name_constraints = name_constraints_ext.value

        # Check permittedSubtrees for IIN constraints
        if name_constraints.permitted_subtrees:
            for subtree in name_constraints.permitted_subtrees:

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
