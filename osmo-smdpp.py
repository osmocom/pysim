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

import json
import sys
import argparse
import uuid
import os
import functools
from typing import Optional, Dict, List
from pprint import pprint as pp

import base64
from base64 import b64decode
from klein import Klein
from twisted.web.iweb import IRequest
import asn1tools

from osmocom.utils import h2b, b2h, swap_nibbles

import pySim.esim.rsp as rsp
from pySim.esim import saip, PMO
from pySim.esim.es8p import *
from pySim.esim.x509_cert import oid, cert_policy_has_oid, cert_get_auth_key_id
from pySim.esim.x509_cert import CertAndPrivkey, CertificateSet, cert_get_subject_key_id, VerifyError

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

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography import x509

def ecdsa_tr03111_to_dss(sig: bytes) -> bytes:
    """convert an ECDSA signature from BSI TR-03111 format to DER: first get long integers; then encode those."""
    assert len(sig) == 64
    r = int.from_bytes(sig[0:32], 'big')
    s = int.from_bytes(sig[32:32*2], 'big')
    return encode_dss_signature(r, s)


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
            print("cert: %s" % cert)
            subject_exts = list(filter(lambda x: isinstance(x.value, x509.SubjectKeyIdentifier), cert.extensions))
            print(subject_exts)
            subject_pkid = subject_exts[0].value
            print(subject_pkid)
            if subject_pkid and subject_pkid.key_identifier == ci_pkid:
                return cert
        return None

    def __init__(self, server_hostname: str, ci_certs_path: str, use_brainpool: bool = False):
        self.server_hostname = server_hostname
        self.upp_dir = os.path.realpath(os.path.join(DATA_DIR, 'upp'))
        self.ci_certs = self.load_certs_from_path(ci_certs_path)
        # load DPauth cert + key
        self.dp_auth = CertAndPrivkey(oid.id_rspRole_dp_auth_v2)
        cert_dir = os.path.join(DATA_DIR, 'certs')
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
        self.rss = rsp.RspSessionStore(os.path.join(DATA_DIR, "sm-dp-sessions"))

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
            # TODO: evaluate User-Agent + X-Admin-Protocol header
            # TODO: reject any non-JSON Content-type

            content = json.loads(request.content.read())
            print("Rx JSON: %s" % json.dumps(content))
            set_headers(request)

            output = func(self, request, content)
            if output == None:
                return ''

            build_resp_header(output)
            print("Tx JSON: %s" % json.dumps(output))
            return json.dumps(output)
        return _api_wrapper

    @app.route('/gsma/rsp2/es9plus/initiateAuthentication', methods=['POST'])
    @rsp_api_wrapper
    def initiateAutentication(self, request: IRequest, content: dict) -> dict:
        """See ES9+ InitiateAuthentication SGP.22 Section 5.6.1"""
        # Verify that the received address matches its own SM-DP+ address, where the comparison SHALL be
        # case-insensitive. Otherwise, the SM-DP+ SHALL return a status code "SM-DP+ Address - Refused".
        if content['smdpAddress'] != self.server_hostname:
           raise ApiError('8.8.1', '3.8', 'Invalid SM-DP+ Address')

        euiccChallenge = b64decode(content['euiccChallenge'])
        if len(euiccChallenge) != 16:
            raise ValueError

        euiccInfo1_bin = b64decode(content['euiccInfo1'])
        euiccInfo1 = rsp.asn1.decode('EUICCInfo1', euiccInfo1_bin)
        print("Rx euiccInfo1: %s" % euiccInfo1)
        #euiccInfo1['svn']

        # TODO: If euiccCiPKIdListForSigningV3 is present ...

        pkid_list = euiccInfo1['euiccCiPKIdListForSigning']
        if 'euiccCiPKIdListForSigningV3' in euiccInfo1:
            pkid_list = pkid_list + euiccInfo1['euiccCiPKIdListForSigningV3']
        # verify it supports one of the keys indicated by euiccCiPKIdListForSigning
        ci_cert = None
        for x in pkid_list:
            ci_cert = self.ci_get_cert_for_pkid(x)
            # we already support multiple CI certificates but only one set of DPauth + DPpb keys. So we must
            # make sure we choose a CI key-id which has issued both the eUICC as well as our own SM-DP side
            # certs.
            if ci_cert and cert_get_subject_key_id(ci_cert) == self.dp_auth.get_authority_key_identifier().key_identifier:
                break
            else:
                ci_cert = None
        if not ci_cert:
           raise ApiError('8.8.2', '3.1', 'None of the proposed Public Key Identifiers is supported by the SM-DP+')

        # TODO: Determine the set of CERT.DPauth.SIG that satisfy the following criteria:
        # * Part of a certificate chain ending at one of the eSIM CA RootCA Certificate, whose Public Keys is
        #   supported by the eUICC (indicated by euiccCiPKIdListForVerification).
        # * Using a certificate chain that the eUICC and the LPA both support:
        #euiccInfo1['euiccCiPKIdListForVerification']
        #   raise ApiError('8.8.4', '3.7', 'The SM-DP+ has no CERT.DPauth.SIG which chains to one of the eSIM CA Root CA CErtificate with a Public Key supported by the eUICC')

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
        print("Tx serverSigned1: %s" % serverSigned1)
        serverSigned1_bin = rsp.asn1.encode('ServerSigned1', serverSigned1)
        print("Tx serverSigned1: %s" % rsp.asn1.decode('ServerSigned1', serverSigned1_bin))
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
        print("Rx %s: %s" % authenticateServerResp)
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

        # Verify that the transactionId is known and relates to an ongoing RSP session.  Otherwise, the SM-DP+
        # SHALL return a status code "TransactionId - Unknown"
        ss = self.rss.get(transactionId, None)
        if ss is None:
            raise ApiError('8.10.1', '3.9', 'Unknown')
        ss.euicc_cert = euicc_cert
        ss.eum_cert = eum_cert # TODO: do we need this in the state?

        # Verify that the Root Certificate of the eUICC certificate chain corresponds to the
        # euiccCiPKIdToBeUsed or TODO: euiccCiPKIdToBeUsedV3
        if cert_get_auth_key_id(eum_cert) != ss.ci_cert_id:
            raise ApiError('8.11.1', '3.9', 'Unknown')

        # Verify the validity of the eUICC certificate chain
        cs = CertificateSet(self.ci_get_cert_for_pkid(ss.ci_cert_id))
        cs.add_intermediate_cert(eum_cert)
        # TODO v3: otherCertsInChain
        try:
            cs.verify_cert_chain(euicc_cert)
        except VerifyError:
            raise ApiError('8.1.3', '6.1', 'Verification failed (certificate chain)')
        #   raise ApiError('8.1.3', '6.3', 'Expired')


        # Verify euiccSignature1 over euiccSigned1 using pubkey from euiccCertificate.
        # Otherwise, the SM-DP+ SHALL return a status code "eUICC - Verification failed"
        if not self._ecdsa_verify(euicc_cert, euiccSignature1_bin, euiccSigned1_bin):
            raise ApiError('8.1', '6.1', 'Verification failed (euiccSignature1 over euiccSigned1)')

        # TODO: verify EID of eUICC cert is  within permitted range of EUM cert

        ss.eid = ss.euicc_cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
        print("EID (from eUICC cert): %s" % ss.eid)

        # Verify that the serverChallenge attached to the ongoing RSP session matches the
        # serverChallenge returned by the eUICC. Otherwise, the SM-DP+ SHALL return a status code "eUICC -
        # Verification failed".
        if euiccSigned1['serverChallenge'] != ss.serverChallenge:
            raise ApiError('8.1', '6.1', 'Verification failed (serverChallenge)')

        # If ctxParams1 contains a ctxParamsForCommonAuthentication data object, the SM-DP+ Shall [...]
        # TODO: We really do a very simplistic job here, this needs to be properly implemented later,
        # considering all the various cases, profile state, etc.
        if euiccSigned1['ctxParams1'][0] == 'ctxParamsForCommonAuthentication':
            cpca = euiccSigned1['ctxParams1'][1]
            matchingId = cpca.get('matchingId', None)
            if not matchingId:
                # TODO: check if any pending profile downloads for the EID
                raise ApiError('8.2.6', '3.8', 'Refused')
            if matchingId:
                # look up profile based on matchingID.  We simply check if a given file exists for now..
                path = os.path.join(self.upp_dir, matchingId) + '.der'
                # prevent directory traversal attack
                if os.path.commonprefix((os.path.realpath(path),self.upp_dir)) != self.upp_dir:
                    raise ApiError('8.2.6', '3.8', 'Refused')
                if not os.path.isfile(path) or not os.access(path, os.R_OK):
                    raise ApiError('8.2.6', '3.8', 'Refused')
                ss.matchingId = matchingId
                with open(path, 'rb') as f:
                    pes = saip.ProfileElementSequence.from_der(f.read())
                    iccid_str = b2h(pes.get_pe_for_type('header').decoded['iccid'])
        else:
            # there's currently no other option in the ctxParams1 choice, so this cannot happen
            raise ApiError('1.3.1', '2.2', 'ctxParams1 missing mandatory ctxParamsForCommonAuthentication')

        # FIXME: we actually want to perform the profile binding herr, and read the profile metadat from the profile

        # Put together profileMetadata + _bin
        ss.profileMetadata = ProfileMetadata(iccid_bin=h2b(swap_nibbles(iccid_str)), spn="OsmocomSPN", profile_name=matchingId)
        # enable notifications for all operations
        for event in ['enable', 'disable', 'delete']:
            ss.profileMetadata.add_notification(event, self.server_hostname)
        profileMetadata_bin = ss.profileMetadata.gen_store_metadata_request()

        # Put together smdpSigned2 + _bin
        smdpSigned2 = {
            'transactionId': h2b(ss.transactionId),
            'ccRequiredFlag': False,        # whether the Confirmation Code is required
            #'bppEuiccOtpk': None,           # whether otPK.EUICC.ECKA already used for binding the BPP, tag '5F49'
            }
        smdpSigned2_bin = rsp.asn1.encode('SmdpSigned2', smdpSigned2)

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
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the TransactionID is unknown')

        prepDownloadResp_bin = b64decode(content['prepareDownloadResponse'])
        prepDownloadResp = rsp.asn1.decode('PrepareDownloadResponse', prepDownloadResp_bin)
        print("Rx %s: %s" % prepDownloadResp)

        if prepDownloadResp[0] == 'downloadResponseError':
            r_err = prepDownloadResp[1]
            #r_err['transactionId']
            #r_err['downloadErrorCode']
            raise ValueError("downloadResponseError %s" % r_err)

        r_ok = prepDownloadResp[1]

        # Verify the euiccSignature2 computed over euiccSigned2 and smdpSignature2 using the PK.EUICC.SIG attached to the ongoing RSP session
        euiccSigned2 = r_ok['euiccSigned2']
        euiccSigned2_bin = rsp.extract_euiccSigned2(prepDownloadResp_bin)
        if not self._ecdsa_verify(ss.euicc_cert, r_ok['euiccSignature2'], euiccSigned2_bin + ss.smdpSignature2_do):
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid')

        # not in spec: Verify that signed TransactionID is outer transaction ID
        if h2b(transactionId) != euiccSigned2['transactionId']:
            raise ApiError('8.10.1', '3.9', 'The signed transactionId != outer transactionId')

        # store otPK.EUICC.ECKA in session state
        ss.euicc_otpk = euiccSigned2['euiccOtpk']
        print("euiccOtpk: %s" % (b2h(ss.euicc_otpk)))

        # Generate a one-time ECKA key pair (ot{PK,SK}.DP.ECKA) using the curve indicated by the Key Parameter
        # Reference value of CERT.DPpb.ECDDSA
        print("curve = %s" % self.dp_pb.get_curve())
        ss.smdp_ot = ec.generate_private_key(self.dp_pb.get_curve())
        # extract the public key in (hopefully) the right format for the ES8+ interface
        ss.smdp_otpk = ss.smdp_ot.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        print("smdpOtpk: %s" % b2h(ss.smdp_otpk))
        print("smdpOtsk: %s" % b2h(ss.smdp_ot.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())))

        ss.host_id = b'mahlzeit'

        # Generate Session Keys using the CRT, otPK.eUICC.ECKA and otSK.DP.ECKA according to annex G
        euicc_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ss.smdp_ot.curve, ss.euicc_otpk)
        ss.shared_secret = ss.smdp_ot.exchange(ec.ECDH(), euicc_public_key)
        print("shared_secret: %s" % b2h(ss.shared_secret))

        # TODO: Check if this order requires a Confirmation Code verification

        #  Perform actual protection + binding of profile package (or return  pre-bound one)
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
        print("Rx %s: %s" % pendingNotification)
        if pendingNotification[0] == 'profileInstallationResult':
            profileInstallRes = pendingNotification[1]
            pird = profileInstallRes['profileInstallationResultData']
            transactionId = b2h(pird['transactionId'])
            ss = self.rss.get(transactionId, None)
            if ss is None:
                print("Unable to find session for transactionId")
                return
            profileInstallRes['euiccSignPIR']
            # TODO: use original data, don't re-encode?
            pird_bin = rsp.asn1.encode('ProfileInstallationResultData', pird)
            # verify eUICC signature
            if not self._ecdsa_verify(ss.euicc_cert, profileInstallRes['euiccSignPIR'], pird_bin):
                raise Exception('ECDSA signature verification failed on notification')
            print("Profile Installation Final Result: ", pird['finalResult'])
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
                raise Exception('ECDSA signature verification failed on notification')
            other_notif = otherSignedNotif['tbsOtherNotification']
            pmo = PMO.from_bitstring(other_notif['profileManagementOperation'])
            eid = euicc_cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
            iccid = other_notif.get('iccid', None)
            if iccid:
                iccid = swap_nibbles(b2h(iccid))
            print("handleNotification: EID %s: %s of %s" % (eid, pmo, iccid))
        else:
            raise ValueError(pendingNotification)

    #@app.route('/gsma/rsp3/es9plus/handleDeviceChangeRequest, methods=['POST']')
    #@rsp_api_wrapper
        #"""See ES9+ ConfirmDeviceChange in SGP.22 Section 5.6.6"""
        # TODO: implement this

    @app.route('/gsma/rsp2/es9plus/cancelSession', methods=['POST'])
    @rsp_api_wrapper
    def cancelSession(self, request: IRequest, content: dict) -> dict:
        """See ES9+ CancelSession in SGP.22 Section 5.6.5"""
        print("Rx JSON: %s" % content)
        transactionId = content['transactionId']

        # Verify that the received transactionId is known and relates to an ongoing RSP session
        ss = self.rss.get(transactionId, None)
        if ss is None:
            raise ApiError('8.10.1', '3.9', 'The RSP session identified by the transactionId is unknown')

        cancelSessionResponse_bin = b64decode(content['cancelSessionResponse'])
        cancelSessionResponse = rsp.asn1.decode('CancelSessionResponse', cancelSessionResponse_bin)
        print("Rx %s: %s" % cancelSessionResponse)

        if cancelSessionResponse[0] == 'cancelSessionResponseError':
            # FIXME: print some error
            return
        cancelSessionResponseOk = cancelSessionResponse[1]
        # TODO: use original data, don't re-encode?
        ecsr = cancelSessionResponseOk['euiccCancelSessionSigned']
        ecsr_bin = rsp.asn1.encode('EuiccCancelSessionSigned', ecsr)
        # Verify the eUICC signature (euiccCancelSessionSignature) using the PK.EUICC.SIG attached to the ongoing RSP session
        if not self._ecdsa_verify(ss.euicc_cert, cancelSessionResponseOk['euiccCancelSessionSignature'], ecsr_bin):
            raise ApiError('8.1', '6.1', 'eUICC signature is invalid')

        # Verify that the received smdpOid corresponds to the one in SM-DP+ CERT.DPauth.SIG
        subj_alt_name = self.dp_auth.get_subject_alt_name()
        if x509.ObjectIdentifier(ecsr['smdpOid']) != subj_alt_name.oid:
            raise ApiError('8.8', '3.10', 'The provided SM-DP+ OID is invalid.')

        if ecsr['transactionId'] != h2b(transactionId):
            raise ApiError('8.10.1', '3.9', 'The signed transactionId != outer transactionId')

        # TODO: 1. Notify the Operator using the function "ES2+.HandleNotification" function
        # TODO: 2. Terminate the corresponding pending download process.
        # TODO: 3. If required, execute the SM-DS Event Deletion procedure described in section 3.6.3.

        # delete actual session data
        del self.rss[transactionId]
        return { 'transactionId': transactionId }


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host/IP to bind HTTP to", default="localhost")
    parser.add_argument("-p", "--port", help="TCP port to bind HTTP to", default=8000)
    #parser.add_argument("-v", "--verbose", help="increase output verbosity", action='count', default=0)

    args = parser.parse_args()

    hs = SmDppHttpServer(HOSTNAME, os.path.join(DATA_DIR, 'certs', 'CertificateIssuer'), use_brainpool=False)
    #hs.app.run(endpoint_description="ssl:port=8000:dhParameters=dh_param_2048.pem")
    hs.app.run(args.host, args.port)

if __name__ == "__main__":
    main(sys.argv)
