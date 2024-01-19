# Implementation of X.509 certificate handling in GSMA eSIM
# as per SGP22 v3.0
#
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

import requests
from typing import Optional, List

from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography import x509

from pySim.utils import b2h

def check_signed(signed: x509.Certificate, signer: x509.Certificate) -> bool:
    """Verify if 'signed' certificate was signed using 'signer'."""
    # this code only works for ECDSA, but this is all we need for GSMA eSIM
    pkey = signer.public_key()
    # this 'signed.signature_algorithm_parameters' below requires cryptopgraphy 41.0.0 :(
    pkey.verify(signed.signature, signed.tbs_certificate_bytes, signed.signature_algorithm_parameters)

def cert_get_subject_key_id(cert: x509.Certificate) -> bytes:
    """Obtain the subject key identifier of the given cert object (as raw bytes)."""
    ski_ext = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return ski_ext.key_identifier

def cert_get_auth_key_id(cert: x509.Certificate) -> bytes:
    """Obtain the authority key identifier of the given cert object (as raw bytes)."""
    aki_ext = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    return aki_ext.key_identifier

class VerifyError(Exception):
    """An error during certificate verification,"""
    pass

class CertificateSet:
    """A set of certificates consisting of a trusted [self-signed] CA root certificate,
    and an optional number of intermediate certificates.  Can be used to verify the certificate chain
    of any given other certificate."""
    def __init__(self, root_cert: x509.Certificate):
        check_signed(root_cert, root_cert)
        # TODO: check other mandatory attributes for CA Cert
        usage_ext = root_cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage_ext.key_cert_sign:
            raise ValueError('Given root certificate key usage does not permit signing of certificates')
        if not usage_ext.crl_sign:
            raise ValueError('Given root certificate key usage does not permit signing of CRLs')
        self.root_cert = root_cert
        self.intermediate_certs = {}
        self.crl = None

    def load_crl(self, urls: Optional[List[str]] = None):
        if urls and type(urls) is str:
            urls = [urls]
        if not urls:
            # generate list of CRL URLs from root CA certificate
            crl_ext = self.root_cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
            name_list = [x.full_name for x in crl_ext]
            merged_list = []
            for n in name_list:
                merged_list += n
            uri_list = filter(lambda x: isinstance(x, x509.UniformResourceIdentifier), merged_list)
            urls = [x.value for x in uri_list]

        for url in urls:
            try:
                crl_bytes = requests.get(url)
            except requests.exceptions.ConnectionError:
                continue
            crl = x509.load_der_x509_crl(crl_bytes)
            if not crl.is_signature_valid(self.root_cert.public_key()):
                raise ValueError('Given CRL has incorrect signature and cannot be trusted')
            # FIXME: various other checks
            self.crl = crl
            # FIXME: should we support multiple CRLs? we only support a single CRL right now
            return
        # FIXME: report on success/failure

    @property
    def root_cert_id(self) -> bytes:
        return cert_get_subject_key_id(self.root_cert)

    def add_intermediate_cert(self, cert: x509.Certificate):
        """Add a potential intermediate certificate to the CertificateSet."""
        # TODO: check mandatory attributes for intermediate cert
        usage_ext = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage_ext.key_cert_sign:
            raise ValueError('Given intermediate certificate key usage does not permit signing of certificates')
        aki = cert_get_auth_key_id(cert)
        ski = cert_get_subject_key_id(cert)
        if aki == ski:
            raise ValueError('Cannot add self-signed cert as intermediate cert')
        self.intermediate_certs[ski] = cert
        # TODO: we could test if this cert verifies against the root, and mark it as pre-verified
        # so we don't need to verify again and again the chain of intermediate certificates

    def verify_cert_crl(self, cert: x509.Certificate):
        if not self.crl:
            # we cannot check if there's no CRL
            return
        if self.crl.get_revoked_certificate_by_serial_number(cert.serial_nr):
            raise VerifyError('Certificate is present in CRL, verification failed')

    def verify_cert_chain(self, cert: x509.Certificate, max_depth: int = 100):
        """Verify if a given certificate's signature chain can be traced back to the root CA of this
        CertificateSet."""
        depth = 1
        c = cert
        while True:
            aki = cert_get_auth_key_id(c)
            if aki == self.root_cert_id:
                # last step:
                check_signed(c, self.root_cert)
                return
            parent_cert = self.intermediate_certs.get(aki, None)
            if not aki:
                raise VerifyError('Could not find intermediate certificate for AuthKeyId %s' % b2h(aki))
            check_signed(c, parent_cert)
            # if we reach here, we passed (no exception raised)
            c = parent_cert
            depth += 1
            if depth > max_depth:
                raise VerifyError('Maximum depth %u exceeded while verifying certificate chain' % max_depth)
