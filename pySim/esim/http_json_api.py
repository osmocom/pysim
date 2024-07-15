"""GSMA eSIM RSP HTTP/REST/JSON interface according to SGP.22 v2.5"""

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
from typing import Optional
import base64

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class ApiParam(abc.ABC):
    """A class reprsenting a single parameter in the API."""
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

class ApiParamBase64(ApiParam):
    @classmethod
    def _decode(cls, data):
        return base64.b64decode(data)

    @classmethod
    def _encode(cls, data):
        return base64.b64encode(data).decode('ascii')

class SmdpAddress(ApiParamFqdn):
    pass

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

class ApiError(Exception):
    """Exception representing an error at the API level (status != Executed)."""
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

class JsonHttpApiFunction(abc.ABC):
    """Base classs for representing an HTTP[s] API Function."""
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
    extra_http_req_headers = {}

    def __init__(self, url_prefix: str, func_req_id: Optional[str], session: requests.Session):
        self.url_prefix = url_prefix
        self.func_req_id = func_req_id
        self.session = session

    def encode(self, data: dict, func_call_id: Optional[str] = None) -> dict:
        """Validate an encode input dict into JSON-serializable dict for request body."""
        output = {}
        if func_call_id:
            output['header'] = {
                    'functionRequesterIdentifier': self.func_req_id,
                    'functionCallIdentifier': func_call_id
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
        """[further] Decode and validate the JSON-Dict of the response body."""
        output = {}
        if 'header' in self.output_params:
            # let's first do the header, it's special
            if not 'header' in data:
                raise ValueError('Mandatory output parameter "header" missing')
            hdr_class = self.output_params.get('header')
            output['header'] = hdr_class.decode(data['header'])

            if output['header']['functionExecutionStatus']['status'] not in ['Executed-Success','Executed-WithWarning']:
                raise ApiError(output['header']['functionExecutionStatus'])
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

    def call(self, data: dict, func_call_id: Optional[str] = None, timeout=10) -> Optional[dict]:
        """Make an API call to the HTTP API endpoint represented by this object.
        Input data is passed in `data` as json-serializable dict.  Output data
        is returned as json-deserialized dict."""
        url = self.url_prefix + self.path
        encoded = json.dumps(self.encode(data, func_call_id))
        req_headers = {
            'Content-Type': 'application/json',
            'X-Admin-Protocol': 'gsma/rsp/v2.5.0',
        }
        req_headers.update(self.extra_http_req_headers)

        logger.debug("HTTP REQ %s - hdr: %s '%s'" % (url, req_headers, encoded))
        response = self.session.request(self.http_method, url, data=encoded, headers=req_headers, timeout=timeout)
        logger.debug("HTTP RSP-STS: [%u] hdr: %s" % (response.status_code, response.headers))
        logger.debug("HTTP RSP: %s" % (response.content))

        if response.status_code != self.expected_http_status:
            raise HttpStatusError(response)
        if not response.headers.get('Content-Type').startswith(req_headers['Content-Type']):
            raise HttpHeaderError(response)
        if not response.headers.get('X-Admin-Protocol', 'gsma/rsp/v2.unknown').startswith('gsma/rsp/v2.'):
            raise HttpHeaderError(response)

        if response.content:
            return self.decode(response.json())
        return None
