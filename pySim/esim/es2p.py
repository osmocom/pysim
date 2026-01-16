"""GSMA eSIM RSP ES2+ interface according to SGP.22 v2.5"""

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
from klein import Klein
from twisted.internet import defer, protocol, ssl, task, endpoints, reactor
from twisted.internet.posixbase import PosixReactorBase
from pathlib import Path
from twisted.web.server import Site, Request

import logging
from datetime import datetime
import time

from pySim.esim.http_json_api import *

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class param:
    class Iccid(ApiParamString):
        """String representation of 19 or 20 digits, where the 20th digit MAY optionally be the padding
        character F."""
        @classmethod
        def _encode(cls, data):
            data = str(data)
            # SGP.22 version prior to 2.2 do not require support for 19-digit ICCIDs, so let's always
            # encode it with padding F at the end.
            if len(data) == 19:
                data += 'F'
            return data

        @classmethod
        def verify_encoded(cls, data):
            if len(data) not in [19, 20]:
                raise ValueError('ICCID (%s) length (%u) invalid' % (data, len(data)))

        @classmethod
        def _decode(cls, data):
            # strip trailing padding (if it's 20 digits)
            if len(data) == 20 and data[-1] in ['F', 'f']:
                data = data[:-1]
            return data

        @classmethod
        def verify_decoded(cls, data):
            data = str(data)
            if len(data) not in [19, 20]:
                raise ValueError('ICCID (%s) length (%u) invalid' % (data, len(data)))
            if len(data) == 19:
                decimal_part = data
            else:
                decimal_part = data[:-1]
                final_part = data[-1:]
                if final_part not in ['F', 'f'] and not final_part.isdecimal():
                    raise ValueError('ICCID (%s) contains non-decimal characters' % data)
            if not decimal_part.isdecimal():
                raise ValueError('ICCID (%s) contains non-decimal characters' % data)


    class Eid(ApiParamString):
        """String of 32 decimal characters"""
        @classmethod
        def verify_encoded(cls, data):
            if len(data) != 32:
                raise ValueError('EID length invalid: "%s" (%u)' % (data, len(data)))

        @classmethod
        def verify_decoded(cls, data):
            if not data.isdecimal():
                raise ValueError('EID (%s) contains non-decimal characters' % data)

    class ProfileType(ApiParamString):
        pass

    class MatchingId(ApiParamString):
        pass

    class ConfirmationCode(ApiParamString):
        pass

    class SmdsAddress(ApiParamFqdn):
        pass

    class ReleaseFlag(ApiParamBoolean):
        pass

    class FinalProfileStatusIndicator(ApiParamString):
        pass

    class Timestamp(ApiParamString):
        """String format as specified by W3C: YYYY-MM-DDThh:mm:ssTZD"""
        @classmethod
        def _decode(cls, data):
            return datetime.fromisoformat(data)

        @classmethod
        def _encode(cls, data):
            return datetime.isoformat(data)

    class NotificationPointId(ApiParamInteger):
        pass

    class NotificationPointStatus(ApiParam):
        pass

    class ResultData(ApiParamBase64):
        pass

class Es2PlusApiFunction(JsonHttpApiFunction):
    """Base class for representing an ES2+ API Function."""
    pass

# ES2+ DownloadOrder function (SGP.22 section 5.3.1)
class DownloadOrder(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/downloadOrder'
    input_params = {
        'header': JsonRequestHeader,
        'eid': param.Eid,
        'iccid': param.Iccid,
        'profileType': param.ProfileType
      }
    input_mandatory = ['header']
    output_params = {
        'header': JsonResponseHeader,
        'iccid': param.Iccid,
      }
    output_mandatory = ['header', 'iccid']

# ES2+ ConfirmOrder function (SGP.22 section 5.3.2)
class ConfirmOrder(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/confirmOrder'
    input_params = {
        'header': JsonRequestHeader,
        'iccid': param.Iccid,
        'eid': param.Eid,
        'matchingId': param.MatchingId,
        'confirmationCode': param.ConfirmationCode,
        'smdsAddress': param.SmdsAddress,
        'releaseFlag': param.ReleaseFlag,
      }
    input_mandatory = ['header', 'iccid', 'releaseFlag']
    output_params = {
        'header': JsonResponseHeader,
        'eid': param.Eid,
        'matchingId': param.MatchingId,
        'smdpAddress': SmdpAddress,
      }
    output_mandatory = ['header', 'matchingId']

# ES2+ CancelOrder function (SGP.22 section 5.3.3)
class CancelOrder(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/cancelOrder'
    input_params = {
        'header': JsonRequestHeader,
        'iccid': param.Iccid,
        'eid': param.Eid,
        'matchingId': param.MatchingId,
        'finalProfileStatusIndicator': param.FinalProfileStatusIndicator,
      }
    input_mandatory = ['header', 'finalProfileStatusIndicator', 'iccid']
    output_params = {
        'header': JsonResponseHeader,
      }
    output_mandatory = ['header']

# ES2+ ReleaseProfile function (SGP.22 section 5.3.4)
class ReleaseProfile(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/releaseProfile'
    input_params = {
        'header': JsonRequestHeader,
        'iccid': param.Iccid,
      }
    input_mandatory = ['header', 'iccid']
    output_params = {
        'header': JsonResponseHeader,
      }
    output_mandatory = ['header']

# ES2+ HandleDownloadProgress function (SGP.22 section 5.3.5)
class HandleDownloadProgressInfo(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/handleDownloadProgressInfo'
    input_params = {
        'header': JsonRequestHeader,
        'eid': param.Eid,
        'iccid': param.Iccid,
        'profileType': param.ProfileType,
        'timestamp': param.Timestamp,
        'notificationPointId': param.NotificationPointId,
        'notificationPointStatus': param.NotificationPointStatus,
        'resultData': param.ResultData,
    }
    input_mandatory = ['header', 'iccid', 'profileType', 'timestamp', 'notificationPointId', 'notificationPointStatus']
    expected_http_status = 204

class Es2pApiClient:
    """Main class representing a full ES2+ API client. Has one method for each API function."""
    def __init__(self, url_prefix:str, func_req_id:str, server_cert_verify: str = None, client_cert: str = None):
        self.func_id = 0
        self.session = requests.Session()
        if server_cert_verify:
            self.session.verify = server_cert_verify
        if client_cert:
            self.session.cert = client_cert

        self.downloadOrder = JsonHttpApiClient(DownloadOrder(), url_prefix, func_req_id, self.session)
        self.confirmOrder = JsonHttpApiClient(ConfirmOrder(), url_prefix, func_req_id, self.session)
        self.cancelOrder = JsonHttpApiClient(CancelOrder(), url_prefix, func_req_id, self.session)
        self.releaseProfile = JsonHttpApiClient(ReleaseProfile(), url_prefix, func_req_id, self.session)
        self.handleDownloadProgressInfo = JsonHttpApiClient(HandleDownloadProgressInfo(), url_prefix, func_req_id, self.session)

    def _gen_func_id(self) -> str:
        """Generate the next function call id."""
        self.func_id += 1
        return 'FCI-%u-%u' % (time.time(), self.func_id)

    def call_downloadOrder(self, data: dict) -> dict:
        """Perform ES2+ DownloadOrder function (SGP.22 section 5.3.1)."""
        return self.downloadOrder.call(data, self._gen_func_id())

    def call_confirmOrder(self, data: dict) -> dict:
        """Perform ES2+ ConfirmOrder function (SGP.22 section 5.3.2)."""
        return self.confirmOrder.call(data, self._gen_func_id())

    def call_cancelOrder(self, data: dict) -> dict:
        """Perform ES2+ CancelOrder function (SGP.22 section 5.3.3)."""
        return self.cancelOrder.call(data, self._gen_func_id())

    def call_releaseProfile(self, data: dict) -> dict:
        """Perform ES2+ CancelOrder function (SGP.22 section 5.3.4)."""
        return self.releaseProfile.call(data, self._gen_func_id())

    def call_handleDownloadProgressInfo(self, data: dict) -> dict:
        """Perform ES2+ HandleDownloadProgressInfo function (SGP.22 section 5.3.5)."""
        return self.handleDownloadProgressInfo.call(data, self._gen_func_id())

class Es2pApiServerHandler():
    """ES2+ API Server handler class. The API user is expected to override the contained methods as needed."""

    def call_downloadOrder(self, data: dict) -> (dict, str):
        """Perform ES2+ DownloadOrder function (SGP.22 section 5.3.1)."""
        return {}, 'Failed'

    def call_confirmOrder(self, data: dict) -> (dict, str):
        """Perform ES2+ ConfirmOrder function (SGP.22 section 5.3.2)."""
        return {}, 'Failed'

    def call_cancelOrder(self, data: dict) -> (dict, str):
        """Perform ES2+ CancelOrder function (SGP.22 section 5.3.3)."""
        return {}, 'Failed'

    def call_releaseProfile(self, data: dict) -> (dict, str):
        """Perform ES2+ CancelOrder function (SGP.22 section 5.3.4)."""
        return {}, 'Failed'

    def call_handleDownloadProgressInfo(self, data: dict) -> (dict, str):
        """Perform ES2+ HandleDownloadProgressInfo function (SGP.22 section 5.3.5)."""
        return {}, 'Failed'

class Es2pApiServer:
    """Main class representing a full ES2+ API server. Has one method for each API function."""
    app = Klein()

    def __init__(self, port: int, interface: str, handler: Es2pApiServerHandler,
                 server_cert: str = None, client_cert_verify: str = None):
        logger.debug("HTTP SRV: starting ES2+ API server on %s:%s" % (interface, port))

        self.port = port
        self.interface = interface
        self.handler = handler
        if server_cert:
            self.server_cert = ssl.PrivateCertificate.loadPEM(Path(server_cert).read_text())
        else:
            self.server_cert = None
        if client_cert_verify:
            self.client_cert_verify = ssl.Certificate.loadPEM(Path(client_cert_verify).read_text())
        else:
            self.client_cert_verify = None

        self.downloadOrder = JsonHttpApiServer(DownloadOrder())
        self.confirmOrder = JsonHttpApiServer(ConfirmOrder())
        self.cancelOrder = JsonHttpApiServer(CancelOrder())
        self.releaseProfile = JsonHttpApiServer(ReleaseProfile())
        self.handleDownloadProgressInfo = JsonHttpApiServer(HandleDownloadProgressInfo())

        task.react(self.reactor)

    def reactor(self, reactor: PosixReactorBase):
        logger.debug("HTTP SRV: listen on %s:%s" % (self.interface, self.port))
        if self.server_cert:
            if self.client_cert_verify:
                reactor.listenSSL(self.port, Site(self.app.resource()), self.server_cert.options(self.client_cert_verify),
                                  interface=self.interface)
            else:
                reactor.listenSSL(self.port, Site(self.app.resource()), self.server_cert.options(),
                                  interface=self.interface)
        else:
            reactor.listenTCP(self.port, Site(self.app.resource()), interface=self.interface)
        return defer.Deferred()

    @app.route(DownloadOrder.path)
    def call_downloadOrder(self, request: Request) -> dict:
        """Perform ES2+ DownloadOrder function (SGP.22 section 5.3.1)."""
        data, fe_status = self.handler.call_downloadOrder(self.downloadOrder.request(request))
        return self.downloadOrder.response(data, fe_status, request)

    @app.route(ConfirmOrder.path)
    def call_confirmOrder(self, request: Request) -> dict:
        """Perform ES2+ ConfirmOrder function (SGP.22 section 5.3.2)."""
        data, fe_status = self.handler.call_confirmOrder(self.confirmOrder.request(request))
        return self.confirmOrder.response(data, fe_status, request)

    @app.route(CancelOrder.path)
    def call_cancelOrder(self, request: Request) -> dict:
        """Perform ES2+ CancelOrder function (SGP.22 section 5.3.3)."""
        data, fe_status = self.handler.call_cancelOrder(self.cancelOrder.request(request))
        return self.cancelOrder.response(data, fe_status, request)

    @app.route(ReleaseProfile.path)
    def call_releaseProfile(self, request: Request) -> dict:
        """Perform ES2+ CancelOrder function (SGP.22 section 5.3.4)."""
        data, fe_status = self.handler.call_releaseProfile(self.releaseProfile.request(request))
        return self.releaseProfile.response(data, fe_status, request)

    @app.route(HandleDownloadProgressInfo.path)
    def call_handleDownloadProgressInfo(self, request: Request) -> dict:
        """Perform ES2+ HandleDownloadProgressInfo function (SGP.22 section 5.3.5)."""
        data, fe_status = self.handler.call_handleDownloadProgressInfo(self.handleDownloadProgressInfo.request(request))
        return self.handleDownloadProgressInfo.response(data, fe_status, request)
