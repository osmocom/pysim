"""GSMA eSIM RSP ES9+ interface according ot SGP.22 v2.5"""

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
import logging
import time

import pySim.esim.rsp as rsp
from pySim.esim.http_json_api import *

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class param:
    class RspAsn1Par(ApiParamBase64):
        """Generalized RSP ASN.1 parameter: base64-wrapped ASN.1 DER. Derived classes must provide
        the asn1_type class variable to indicate the name of the ASN.1 type to use for encode/decode."""
        asn1_type = None # must be overridden by derived class

        @classmethod
        def _decode(cls, data):
            data = ApiParamBase64.decode(data)
            return rsp.asn1.decode(cls.asn1_type, data)

        @classmethod
        def _encode(cls, data):
            data = rsp.asn1.encode(cls.asn1_type, data)
            return ApiParamBase64.encode(data)

    class EuiccInfo1(RspAsn1Par):
        asn1_type = 'EUICCInfo1'

    class ServerSigned1(RspAsn1Par):
        asn1_type = 'ServerSigned1'

    class PrepareDownloadResponse(RspAsn1Par):
        asn1_type = 'PrepareDownloadResponse'

    class AuthenticateServerResponse(RspAsn1Par):
        asn1_type = 'AuthenticateServerResponse'

    class SmdpSigned2(RspAsn1Par):
        asn1_type = 'SmdpSigned2'

    class StoreMetadataRequest(RspAsn1Par):
        asn1_type = 'StoreMetadataRequest'

    class PendingNotification(RspAsn1Par):
        asn1_type = 'PendingNotification'

    class CancelSessionResponse(RspAsn1Par):
        asn1_type = 'CancelSessionResponse'

    class TransactionId(ApiParamString):
        pass

class Es9PlusApiFunction(JsonHttpApiFunction):
    pass

# ES9+ InitiateAuthentication function (SGP.22 section 6.5.2.6)
class InitiateAuthentication(Es9PlusApiFunction):
    path = '/gsma/rsp2/es9plus/initiateAuthentication'
    extra_http_req_headers = { 'User-Agent': 'gsma-rsp-lpad' }
    input_params = {
        'euiccChallenge': ApiParamBase64,
        'euiccInfo1': param.EuiccInfo1,
        'smdpAddress': SmdpAddress,
      }
    input_mandatory = ['euiccChallenge', 'euiccInfo1', 'smdpAddress']
    output_params = {
        'header': JsonResponseHeader,
        'transactionId': param.TransactionId,
        'serverSigned1': param.ServerSigned1,
        'serverSignature1': ApiParamBase64,
        'euiccCiPKIdToBeUsed': ApiParamBase64,
        'serverCertificate': ApiParamBase64,
      }
    output_mandatory = ['header', 'transactionId', 'serverSigned1', 'serverSignature1',
                        'euiccCiPKIdToBeUsed', 'serverCertificate']

# ES9+ GetBoundProfilePackage function (SGP.22 section 6.5.2.7)
class GetBoundProfilePackage(Es9PlusApiFunction):
    path = '/gsma/rsp2/es9plus/getBoundProfilePackage'
    extra_http_req_headers = { 'User-Agent': 'gsma-rsp-lpad' }
    input_params = {
        'transactionId': param.TransactionId,
        'prepareDownloadResponse': param.PrepareDownloadResponse,
      }
    input_mandatory = ['transactionId', 'prepareDownloadResponse']
    output_params = {
        'header': JsonResponseHeader,
        'transactionId': param.TransactionId,
        'boundProfilePackage': ApiParamBase64,
      }
    output_mandatory = ['header', 'transactionId', 'boundProfilePackage']

# ES9+ AuthenticateClient function (SGP.22 section 6.5.2.8)
class AuthenticateClient(Es9PlusApiFunction):
    path= '/gsma/rsp2/es9plus/authenticateClient'
    extra_http_req_headers = { 'User-Agent': 'gsma-rsp-lpad' }
    input_params = {
        'transactionId': param.TransactionId,
        'authenticateServerResponse': param.AuthenticateServerResponse,
      }
    input_mandatory = ['transactionId', 'authenticateServerResponse']
    output_params = {
        'header': JsonResponseHeader,
        'transactionId': param.TransactionId,
        'profileMetadata': param.StoreMetadataRequest,
        'smdpSigned2': param.SmdpSigned2,
        'smdpSignature2': ApiParamBase64,
        'smdpCertificate': ApiParamBase64,
      }
    output_mandatory = ['header', 'transactionId', 'profileMetadata', 'smdpSigned2',
                        'smdpSignature2', 'smdpCertificate']

# ES9+ HandleNotification function (SGP.22 section 6.5.2.9)
class HandleNotification(Es9PlusApiFunction):
    path = '/gsma/rsp2/es9plus/handleNotification'
    extra_http_req_headers = { 'User-Agent': 'gsma-rsp-lpad' }
    input_params = {
        'pendingNotification': param.PendingNotification,
      }
    input_mandatory = ['pendingNotification']
    expected_http_status = 204

# ES9+ CancelSession function (SGP.22 section 6.5.2.10)
class CancelSession(Es9PlusApiFunction):
    path = '/gsma/rsp2/es9plus/cancelSession'
    extra_http_req_headers = { 'User-Agent': 'gsma-rsp-lpad' }
    input_params = {
        'transactionId': param.TransactionId,
        'cancelSessionResponse': param.CancelSessionResponse,
      }
    input_mandatory = ['transactionId', 'cancelSessionResponse']

class Es9pApiClient:
    def __init__(self, url_prefix:str, server_cert_verify: str = None):
        self.session = requests.Session()
        self.session.verify = False # FIXME HACK
        if server_cert_verify:
            self.session.verify = server_cert_verify

        self.initiateAuthentication = InitiateAuthentication(url_prefix, '', self.session)
        self.authenticateClient = AuthenticateClient(url_prefix, '', self.session)
        self.getBoundProfilePackage = GetBoundProfilePackage(url_prefix, '', self.session)
        self.handleNotification = HandleNotification(url_prefix, '', self.session)
        self.cancelSession = CancelSession(url_prefix, '', self.session)

    def call_initiateAuthentication(self, data: dict) -> dict:
        return self.initiateAuthentication.call(data)

    def call_authenticateClient(self, data: dict) -> dict:
        return self.authenticateClient.call(data)

    def call_getBoundProfilePackage(self, data: dict) -> dict:
        return self.getBoundProfilePackage.call(data)

    def call_handleNotification(self, data: dict) -> dict:
        return self.handleNotification.call(data)

    def call_cancelSession(self, data: dict) -> dict:
        return self.cancelSession.call(data)
