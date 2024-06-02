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
import hashlib

from typing import List
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec

import pySim.esim.rsp as rsp
from pySim.esim import es9p
from pySim.utils import h2b, b2h, swap_nibbles, bertlv_parse_one_rawtag, bertlv_return_one_rawtlv
from pySim.esim.x509_cert import CertAndPrivkey
from pySim.esim.es8p import BoundProfilePackage

logging.basicConfig(level=logging.DEBUG)

parser = argparse.ArgumentParser(description="""
Utility to manually issue requests against the ES9+ API of an SM-DP+ according to GSMA SGP.22.""")
parser.add_argument('--url', required=True, help='Base URL of ES9+ API endpoint')
parser.add_argument('--server-ca-cert', help="""X.509 CA certificates acceptable for the server side. In
                    production use cases, this would be the GSMA Root CA (CI) certificate.""")
subparsers = parser.add_subparsers(dest='command',help="The command (API function) to call", required=True)

parser_dl = subparsers.add_parser('download', help="ES9+ download")
parser_dl.add_argument('--certificate-path', default='.',
                       help="Path in which to look for certificate and key files.")
parser_dl.add_argument('--euicc-certificate', default='CERT_EUICC_ECDSA_NIST.der',
                       help="File name of DER-encoded eUICC certificate file.")
parser_dl.add_argument('--euicc-private-key', default='SK_EUICC_ECDSA_NIST.pem',
                       help="File name of PEM-format eUICC secret key file.")
parser_dl.add_argument('--eum-certificate', default='CERT_EUM_ECDSA_NIST.der',
                       help="File name of DER-encoded EUM certificate file.")
parser_dl.add_argument('--ci-certificate', default='CERT_CI_ECDSA_NIST.der',
                       help="File name of DER-encoded CI certificate file.")
parser_dl.add_argument('--matchingId', required=True,
                       help='MatchingID that shall be used by profile download')
parser_dl.add_argument('--output-path', default='.',
                       help="Path to which the output files will be written.")
parser_dl.add_argument('--confirmation-code',
                       help="Confirmation Code for the eSIM download")


def do_download(opts):

    cert_and_key = CertAndPrivkey()
    cert_and_key.cert_from_der_file(os.path.join(opts.certificate_path, opts.euicc_certificate))
    cert_and_key.privkey_from_pem_file(os.path.join(opts.certificate_path, opts.euicc_private_key))

    with open(os.path.join(opts.certificate_path, opts.eum_certificate), 'rb') as f:
        eum_cert = x509.load_der_x509_certificate(f.read())

    with open(os.path.join(opts.certificate_path, opts.ci_certificate), 'rb') as f:
        ci_cert = x509.load_der_x509_certificate(f.read())
        subject_exts = list(filter(lambda x: isinstance(x.value, x509.SubjectKeyIdentifier), ci_cert.extensions))
        subject_pkid = subject_exts[0].value
        ci_pkid = subject_pkid.key_identifier

    print("EUICC: %s" % cert_and_key.cert.subject)
    print("EUM: %s" % eum_cert.subject)
    print("CI: %s" % ci_cert.subject)

    eid = cert_and_key.cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
    print("EID: %s" % eid)
    print("CI PKID: %s" % b2h(ci_pkid))
    print()

    peer = es9p.Es9pApiClient(opts.url, server_cert_verify=opts.server_ca_cert)

    print("Step 1: InitiateAuthentication...")

    euiccInfo1 = {
            'svn': b'\x02\x04\x00',
            'euiccCiPKIdListForVerification': [
                ci_pkid,
            ],
            'euiccCiPKIdListForSigning': [
                ci_pkid,
            ],
      }

    data = {
        'euiccChallenge': os.urandom(16),
        'euiccInfo1': euiccInfo1,
        'smdpAddress': urlparse(opts.url).netloc,
      }
    init_auth_res = peer.call_initiateAuthentication(data)
    print(init_auth_res)

    print("Step 2: AuthenticateClient...")

    #res['serverSigned1']
    #res['serverSignature1']
    print("TODO: verify serverSignature1 over serverSigned1")
    #res['transactionId']
    print("TODO: verify transactionId matches the signed one in serverSigned1")
    #res['euiccCiPKIdToBeUsed']
    # TODO: select eUICC certificate based on CI
    #res['serverCertificate']
    # TODO: verify server certificate against CI

    euiccInfo2 = {
        'profileVersion': b'\x02\x03\x01',
        'svn': euiccInfo1['svn'],
        'euiccFirmwareVer': b'\x23\x42\x00',
        'extCardResource': b'\x81\x01\x00\x82\x04\x00\x04\x9ch\x83\x02"#',
        'uiccCapability': (b'k6\xd3\xc3', 32),
        'javacardVersion': b'\x11\x02\x00',
        'globalplatformVersion': b'\x02\x03\x00',
        'rspCapability': (b'\x9c', 6),
        'euiccCiPKIdListForVerification': euiccInfo1['euiccCiPKIdListForVerification'],
        'euiccCiPKIdListForSigning': euiccInfo1['euiccCiPKIdListForSigning'],
        #'euiccCategory':
        #'forbiddenProfilePolicyRules':
        'ppVersion': b'\x01\x00\x00',
        'sasAcreditationNumber': 'OSMOCOM-TEST-1', #TODO: make configurable
        #'certificationDataObject':
    }

    euiccSigned1 = {
        'transactionId': h2b(init_auth_res['transactionId']),
        'serverAddress': init_auth_res['serverSigned1']['serverAddress'],
        'serverChallenge': init_auth_res['serverSigned1']['serverChallenge'],
        'euiccInfo2': euiccInfo2,
        'ctxParams1':
            ('ctxParamsForCommonAuthentication', {
                'matchingId': opts.matchingId,
                'deviceInfo': {
                    'tac': b'\x00'*8,
                    'deviceCapabilities': {},
                    #imei:
                }
            }),
    }
    euiccSigned1_bin = rsp.asn1.encode('EuiccSigned1', euiccSigned1)
    euiccSignature1 = cert_and_key.ecdsa_sign(euiccSigned1_bin)
    auth_clnt_req = {
        'transactionId': init_auth_res['transactionId'],
        'authenticateServerResponse':
            ('authenticateResponseOk', {
                'euiccSigned1': euiccSigned1,
                'euiccSignature1': euiccSignature1,
                'euiccCertificate': rsp.asn1.decode('Certificate', cert_and_key.get_cert_as_der()),
                'eumCertificate': rsp.asn1.decode('Certificate', eum_cert.public_bytes(Encoding.DER))
             })
    }
    auth_clnt_res = peer.call_authenticateClient(auth_clnt_req)
    print(auth_clnt_res)
    #auth_clnt_res['transactionId']
    print("TODO: verify transactionId matches previous ones")
    #auth_clnt_res['profileMetadata']
    # TODO: what's in here?
    #auth_clnt_res['smdpSigned2']['bppEuiccOtpk']
    #auth_clnt_res['smdpSignature2']
    print("TODO: verify serverSignature2 over smdpSigned2")

    smdp_cert = x509.load_der_x509_certificate(auth_clnt_res['smdpCertificate'])

    print("Step 3: GetBoundProfilePackage...")
    # Generate a one-time ECKA key pair (ot{PK,SK}.DP.ECKA) using the curve indicated by the Key Parameter
    # Reference value of CERT.DPpb.ECDSA
    euicc_ot = ec.generate_private_key(smdp_cert.public_key().public_numbers().curve)

    # extract the public key in (hopefully) the right format for the ES8+ interface
    euicc_otpk = euicc_ot.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    euiccSigned2 = {
        'transactionId': h2b(auth_clnt_res['transactionId']),
        'euiccOtpk': euicc_otpk,
        #hashCC
    }
    # check for smdpSigned2 ccRequiredFlag, and send it in PrepareDownloadRequest hashCc
    if auth_clnt_res['smdpSigned2']['ccRequiredFlag']:
        if not opts.confirmation_code:
            raise ValueError('Confirmation Code required but not provided')
        cc_hash = hashlib.sha256(opts.confirmation_code.encode('ascii')).digest()
        euiccSigned2['hashCc'] = hashlib.sha256(cc_hash + euiccSigned2['transactionId']).digest()
    euiccSigned2_bin = rsp.asn1.encode('EUICCSigned2', euiccSigned2)
    euiccSignature2 = cert_and_key.ecdsa_sign(euiccSigned2_bin + auth_clnt_res['smdpSignature2'])
    gbp_req = {
        'transactionId': auth_clnt_res['transactionId'],
        'prepareDownloadResponse':
            ('downloadResponseOk', {
                'euiccSigned2': euiccSigned2,
                'euiccSignature2': euiccSignature2,
             })
    }
    gbp_res = peer.call_getBoundProfilePackage(gbp_req)
    print(gbp_res)
    #gbp_res['transactionId']
    # TODO: verify transactionId
    print("TODO: verify transactionId matches previous ones")
    bpp_bin = gbp_res['boundProfilePackage']
    print("TODO: verify boundProfilePackage smdpSignature")

    bpp = BoundProfilePackage()
    upp_bin = bpp.decode(euicc_ot, eid, bpp_bin)

    iccid = swap_nibbles(b2h(bpp.storeMetadataRequest['iccid']))
    base_name = os.path.join(opts.output_path, '%s' % iccid)

    print("SUCCESS: Storing files as %s.*.der" % base_name)

    # write various output files
    with open(base_name+'.upp.der', 'wb') as f:
        f.write(bpp.upp)
    with open(base_name+'.isdp.der', 'wb') as f:
        f.write(bpp.encoded_configureISDPRequest)
    with open(base_name+'.smr.der', 'wb') as f:
        f.write(bpp.encoded_storeMetadataRequest)


if __name__ == '__main__':
    opts = parser.parse_args()

    if opts.command == 'download':
        do_download(opts)
