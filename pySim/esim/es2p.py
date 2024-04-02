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

import abc
import requests
import logging
import json
from datetime import datetime
import time
import base64

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class ApiParam(abc.ABC):
    """A class reprsenting a single parameter in the ES2+ API."""
    @classmethod
    def verify_decoded(cls, data):
        """Verify the decoded reprsentation of a value. Should raise an exception if somthing is odd."""
        pass

    @classmethod
    def verify_encoded(cls, data):
        """Verify the encoded reprsentation of a value. Should raise an exception if somthing is odd."""
        pass

    @classmethod
    def encode(cls, data):
        """[Validate and] Encode the given value."""
        cls.verify_decoded(data)
        encoded = cls._encode(data)
        cls.verify_decoded(encoded)
        return encoded

    @classmethod
    def _encode(cls, data):
        """encoder function, typically [but not always] overridden by derived class."""
        return data

    @classmethod
    def decode(cls, data):
        """[Validate and] Decode the given value."""
        cls.verify_encoded(data)
        decoded = cls._decode(data)
        cls.verify_decoded(decoded)
        return decoded

    @classmethod
    def _decode(cls, data):
        """decoder function, typically [but not always] overridden by derived class."""
        return data

class ApiParamString(ApiParam):
    """Base class representing an API parameter of 'string' type."""
    pass


class ApiParamInteger(ApiParam):
    """Base class representing an API parameter of 'integer' type."""
    @classmethod
    def _decode(cls, data):
        return int(data)

    @classmethod
    def _encode(cls, data):
        return str(data)

    @classmethod
    def verify_decoded(cls, data):
        if not isinstance(data, int):
            raise TypeError('Expected an integer input data type')

    @classmethod
    def verify_encoded(cls, data):
        if isinstance(data, int):
            return
        if not data.isdecimal():
            raise ValueError('integer (%s) contains non-decimal characters' % data)
        assert str(int(data)) == data

class ApiParamBoolean(ApiParam):
    """Base class representing an API parameter of 'boolean' type."""
    @classmethod
    def _encode(cls, data):
        return bool(data)

class ApiParamFqdn(ApiParam):
    """String, as a list of domain labels concatenated using the full stop (dot, period) character as
    separator between labels. Labels are restricted to the Alphanumeric mode character set defined in table 5
    of ISO/IEC 18004"""
    @classmethod
    def verify_encoded(cls, data):
        # FIXME
        pass

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

    class SmdpAddress(ApiParamFqdn):
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
            return datetime.toisoformat(data)

    class NotificationPointId(ApiParamInteger):
        pass

    class NotificationPointStatus(ApiParam):
        pass

    class ResultData(ApiParam):
        @classmethod
        def _decode(cls, data):
            return base64.b64decode(data)

        @classmethod
        def _encode(cls, data):
            return base64.b64encode(data)

    class JsonResponseHeader(ApiParam):
        """SGP.22 section 6.5.1.4."""
        @classmethod
        def verify_decoded(cls, data):
            fe_status = data.get('functionExecutionStatus')
            if not fe_status:
                raise ValueError('Missing mandatory functionExecutionStatus in header')
            status = fe_status.get('status')
            if not status:
                raise ValueError('Missing mandatory status in header functionExecutionStatus')
            if status not in ['Executed-Success', 'Executed-WithWarning', 'Failed', 'Expired']:
                raise ValueError('Unknown/unspecified status "%s"' % status)


class HttpStatusError(Exception):
    pass

class HttpHeaderError(Exception):
    pass

class Es2PlusApiError(Exception):
    """Exception representing an error at the ES2+ API level (status != Executed)."""
    def __init__(self, func_ex_status: dict):
        self.status = func_ex_status['status']
        sec = {
            'subjectCode': None,
            'reasonCode': None,
            'subjectIdentifier': None,
            'message': None,
        }
        actual_sec = func_ex_status.get('statusCodeData', None)
        sec.update(actual_sec)
        self.subject_code = sec['subjectCode']
        self.reason_code = sec['reasonCode']
        self.subject_id = sec['subjectIdentifier']
        self.message = sec['message']

    def __str__(self):
        return f'{self.status}("{self.subject_code}","{self.reason_code}","{self.subject_id}","{self.message}")'

class Es2PlusApiFunction(abc.ABC):
    """Base classs for representing an ES2+ API Function."""
    # the below class variables are expected to be overridden in derived classes

    path = None
    # dictionary of input parameters. key is parameter name, value is ApiParam class
    input_params = {}
    # list of mandatory input parameters
    input_mandatory = []
    # dictionary of output parameters. key is parameter name, value is ApiParam class
    output_params = {}
    # list of mandatory output parameters (for successful response)
    output_mandatory = []
    # expected HTTP status code of the response
    expected_http_status = 200
    # the HTTP method used (GET, OPTIONS, HEAD, POST, PUT, PATCH or DELETE)
    http_method = 'POST'

    def __init__(self, url_prefix: str, func_req_id: str, session):
        self.url_prefix = url_prefix
        self.func_req_id = func_req_id
        self.session = session

    def encode(self, data: dict, func_call_id: str) -> dict:
        """Validate an encode input dict into JSON-serializable dict for request body."""
        output = {
            'header': {
                'functionRequesterIdentifier': self.func_req_id,
                'functionCallIdentifier': func_call_id
            }
        }
        for p in self.input_mandatory:
            if not p in data:
                raise ValueError('Mandatory input parameter %s missing' % p)
        for p, v in data.items():
            p_class = self.input_params.get(p)
            if not p_class:
                logger.warning('Unexpected/unsupported input parameter %s=%s', p, v)
                output[p] = v
            else:
                output[p] = p_class.encode(v)
        return output


    def decode(self, data: dict) -> dict:
        """[further] Decode and validate the JSON-Dict of the respnse body."""
        output = {}
        # let's first do the header, it's special
        if not 'header' in data:
            raise ValueError('Mandatory output parameter "header" missing')
        hdr_class = self.output_params.get('header')
        output['header'] = hdr_class.decode(data['header'])

        if output['header']['functionExecutionStatus']['status'] not in ['Executed-Success','Executed-WithWarning']:
            raise Es2PlusApiError(output['header']['functionExecutionStatus'])
        # we can only expect mandatory parameters to be present in case of successful execution
        for p in self.output_mandatory:
            if p == 'header':
                continue
            if not p in data:
                raise ValueError('Mandatory output parameter "%s" missing' % p)
        for p, v in data.items():
            p_class = self.output_params.get(p)
            if not p_class:
                logger.warning('Unexpected/unsupported output parameter "%s"="%s"', p, v)
                output[p] = v
            else:
                output[p] = p_class.decode(v)
        return output

    def call(self, data: dict, func_call_id:str, timeout=10) -> dict:
        """Make an API call to the ES2+ API endpoint represented by this object.
        Input data is passed in `data` as json-serializable dict.  Output data
        is returned as json-deserialized dict."""
        url = self.url_prefix + self.path
        encoded = json.dumps(self.encode(data, func_call_id))
        headers = {
            'Content-Type': 'application/json',
            'X-Admin-Protocol': 'gsma/rsp/v2.5.0',
        }

        logger.debug("HTTP REQ %s - '%s'" % (url, encoded))
        response = self.session.request(self.http_method, url, data=encoded, headers=headers, timeout=timeout)
        logger.debug("HTTP RSP-STS: [%u] hdr: %s" % (response.status_code, response.headers))
        logger.debug("HTTP RSP: %s" % (response.content))

        if response.status_code != self.expected_http_status:
            raise HttpStatusError(response)
        if not response.headers.get('Content-Type').startswith(headers['Content-Type']):
            raise HttpHeaderError(response)
        if not response.headers.get('X-Admin-Protocol', 'gsma/rsp/v2.unknown').startswith('gsma/rsp/v2.'):
            raise HttpHeaderError(response)

        return self.decode(response.json())


# ES2+ DownloadOrder function (SGP.22 section 5.3.1)
class DownloadOrder(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/downloadOrder'
    input_params = {
        'eid': param.Eid,
        'iccid': param.Iccid,
        'profileType': param.ProfileType
      }
    output_params = {
        'header': param.JsonResponseHeader,
        'iccid': param.Iccid,
      }
    output_mandatory = ['header', 'iccid']

# ES2+ ConfirmOrder function (SGP.22 section 5.3.2)
class ConfirmOrder(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/confirmOrder'
    input_params = {
        'iccid': param.Iccid,
        'eid': param.Eid,
        'matchingId': param.MatchingId,
        'confirmationCode': param.ConfirmationCode,
        'smdsAddress': param.SmdsAddress,
        'releaseFlag': param.ReleaseFlag,
      }
    input_mandatory = ['iccid', 'releaseFlag']
    output_params = {
        'header': param.JsonResponseHeader,
        'eid': param.Eid,
        'matchingId': param.MatchingId,
        'smdpAddress': param.SmdpAddress,
      }
    output_mandatory = ['header', 'matchingId']

# ES2+ CancelOrder function (SGP.22 section 5.3.3)
class CancelOrder(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/cancelOrder'
    input_params = {
        'iccid': param.Iccid,
        'eid': param.Eid,
        'matchingId': param.MatchingId,
        'finalProfileStatusIndicator': param.FinalProfileStatusIndicator,
      }
    input_mandatory = ['finalProfileStatusIndicator', 'iccid']
    output_params = {
        'header': param.JsonResponseHeader,
      }
    output_mandatory = ['header']

# ES2+ ReleaseProfile function (SGP.22 section 5.3.4)
class ReleaseProfile(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/releaseProfile'
    input_params = {
        'iccid': param.Iccid,
      }
    input_mandatory = ['iccid']
    output_params = {
        'header': param.JsonResponseHeader,
      }
    output_mandatory = ['header']

# ES2+ HandleDownloadProgress function (SGP.22 section 5.3.5)
class HandleDownloadProgressInfo(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/handleDownloadProgressInfo'
    input_params = {
        'eid': param.Eid,
        'iccid': param.Iccid,
        'profileType': param.ProfileType,
        'timestamp': param.Timestamp,
        'notificationPointId': param.NotificationPointId,
        'notificationPointStatus': param.NotificationPointStatus,
        'resultData': param.ResultData,
    }
    input_mandatory = ['iccid', 'profileType', 'timestamp', 'notificationPointId', 'notificationPointStatus']
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

        self.downloadOrder = DownloadOrder(url_prefix, func_req_id, self.session)
        self.confirmOrder = ConfirmOrder(url_prefix, func_req_id, self.session)
        self.cancelOrder = CancelOrder(url_prefix, func_req_id, self.session)
        self.releaseProfile = ReleaseProfile(url_prefix, func_req_id, self.session)
        self.handleDownloadProgressInfo = HandleDownloadProgressInfo(url_prefix, func_req_id, self.session)

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
