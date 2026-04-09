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
from twisted.web.server import Request


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class ApiParam(abc.ABC):
    """A class representing a single parameter in the API."""
    @classmethod
    def verify_decoded(cls, data):
        """Verify the decoded representation of a value. Should raise an exception if something is odd."""
        pass

    @classmethod
    def verify_encoded(cls, data):
        """Verify the encoded representation of a value. Should raise an exception if something is odd."""
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

class JsonRequestHeader(ApiParam):
    """SGP.22 section 6.5.1.3."""
    @classmethod
    def verify_decoded(cls, data):
        func_req_id = data.get('functionRequesterIdentifier')
        if not func_req_id:
            raise ValueError('Missing mandatory functionRequesterIdentifier in header')
        func_call_id = data.get('functionCallIdentifier')
        if not func_call_id:
            raise ValueError('Missing mandatory functionCallIdentifier in header')

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
        if actual_sec:
            sec.update(actual_sec)
        self.subject_code = sec['subjectCode']
        self.reason_code = sec['reasonCode']
        self.subject_id = sec['subjectIdentifier']
        self.message = sec['message']

    def __str__(self):
        return f'{self.status}("{self.subject_code}","{self.reason_code}","{self.subject_id}","{self.message}")'

class JsonHttpApiFunction(abc.ABC):
    """Base class for representing an HTTP[s] API Function."""
    # The below class variables are used to describe the properties of the API function. Derived classes are expected
    # to orverride those class properties with useful values. The prefixes "input_" and "output_" refer to the API
    # function from an abstract point of view. Seen from the client perspective, "input_" will refer to parameters the
    # client sends to a HTTP server. Seen from the server perspective, "input_" will refer to parameters the server
    # receives from the a requesting client. The same applies vice versa to class variables that have an "output_"
    # prefix.

    # path of the API function (e.g. '/gsma/rsp2/es2plus/confirmOrder')
    path = None

    # dictionary of input parameters. key is parameter name, value is ApiParam class
    input_params = {}

    # list of mandatory input parameters
    input_mandatory = []

    # dictionary of output parameters. key is parameter name, value is ApiParam class
    output_params = {}

    # list of mandatory output parameters (for successful response)
    output_mandatory = []

    # list of mandatory output parameters (for failed response)
    output_mandatory_failed = []

    # expected HTTP status code of the response
    expected_http_status = 200

    # the HTTP method used (GET, OPTIONS, HEAD, POST, PUT, PATCH or DELETE)
    http_method = 'POST'

    # additional custom HTTP headers (client requests)
    extra_http_req_headers = {}

    # additional custom HTTP headers (server responses)
    extra_http_res_headers = {}

    def __new__(cls, *args, role = 'legacy_client', **kwargs):
        """
        Args:
                args: (see JsonHttpApiClient and JsonHttpApiServer)
                role: role ('server' or 'client') in which the JsonHttpApiFunction should be created.
                kwargs: (see JsonHttpApiClient and JsonHttpApiServer)
        """

        # Create a dictionary with the class attributes of this class (the properties listed above and the encode_
        # decode_ methods below). The dictionary will not include any dunder/magic methods
        cls_attr = {attr_name: getattr(cls, attr_name) for attr_name in dir(cls) if not attr_name.startswith('__')}

        # Normal instantiation as JsonHttpApiFunction:
        if len(args) == 0 and len(kwargs) == 0:
            return type(cls.__name__, (abc.ABC,), cls_attr)()

        # Instantiation as as JsonHttpApiFunction with a JsonHttpApiClient or JsonHttpApiServer base
        if role == 'legacy_client':
            # Deprecated: With the advent of the server role (JsonHttpApiServer) the API had to be changed. To maintain
            # compatibility with existing code (out-of-tree) the original behaviour and API interface and behaviour had
            # to be preserved. Already existing JsonHttpApiFunction definitions will still work and the related objects
            # may still be created on the original way: my_api_func = MyApiFunc(url_prefix, func_req_id, self.session)
            logger.warning('implicit role (falling back to legacy JsonHttpApiClient) is deprecated, please specify role explcitly')
            result = type(cls.__name__, (JsonHttpApiClient,), cls_attr)(None, *args, **kwargs)
            result.api_func = result
            result.legacy = True
            return result
        elif role == 'client':
            # Create a JsonHttpApiFunction in client role
            # Example: my_api_func = MyApiFunc(url_prefix, func_req_id, self.session, role='client')
            result = type(cls.__name__, (JsonHttpApiClient,), cls_attr)(None, *args, **kwargs)
            result.api_func = result
            return result
        elif role == 'server':
            # Create a JsonHttpApiFunction in server role
            # Example: my_api_func = MyApiFunc(url_prefix, func_req_id, self.session, role='server')
            result = type(cls.__name__, (JsonHttpApiServer,), cls_attr)(None, *args, **kwargs)
            result.api_func = result
            return result
        else:
            raise ValueError('Invalid role \'%s\' specified' % role)

    def encode_client(self, data: dict) -> dict:
        """Validate an encode input dict into JSON-serializable dict for request body."""
        output = {}
        for p in self.input_mandatory:
            if not p in data:
                raise ValueError('Mandatory input parameter %s missing' % p)
        for p, v in data.items():
            p_class = self.input_params.get(p)
            if not p_class:
                # pySim/esim/http_json_api.py:269:47: E1101: Instance of 'JsonHttpApiFunction' has no 'legacy' member (no-member)
                # pylint: disable=no-member
                if hasattr(self, 'legacy') and self.legacy:
                    output[p] = JsonRequestHeader.encode(v)
                else:
                    logger.warning('Unexpected/unsupported input parameter %s=%s', p, v)
                    output[p] = v
            else:
                output[p] = p_class.encode(v)
        return output

    def decode_client(self, data: dict) -> dict:
        """[further] Decode and validate the JSON-Dict of the response body."""
        output = {}
        output_mandatory = self.output_mandatory

        # In case a provided header (may be optional) indicates that the API function call was unsuccessful, a
        # different set of mandatory parameters applies.
        header = data.get('header')
        if header:
            if data['header']['functionExecutionStatus']['status'] not in ['Executed-Success','Executed-WithWarning']:
                output_mandatory = self.output_mandatory_failed

        for p in output_mandatory:
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

    def encode_server(self, data: dict) -> dict:
        """Validate an encode input dict into JSON-serializable dict for response body."""
        output = {}
        output_mandatory = self.output_mandatory

        # In case a provided header (may be optional) indicates that the API function call was unsuccessful, a
        # different set of mandatory parameters applies.
        header = data.get('header')
        if header:
            if data['header']['functionExecutionStatus']['status'] not in ['Executed-Success','Executed-WithWarning']:
                output_mandatory = self.output_mandatory_failed

        for p in output_mandatory:
            if not p in data:
                raise ValueError('Mandatory output parameter %s missing' % p)
        for p, v in data.items():
            p_class = self.output_params.get(p)
            if not p_class:
                logger.warning('Unexpected/unsupported output parameter %s=%s', p, v)
                output[p] = v
            else:
                output[p] = p_class.encode(v)
        return output

    def decode_server(self, data: dict) -> dict:
        """[further] Decode and validate the JSON-Dict of the request body."""
        output = {}

        for p in self.input_mandatory:
            if not p in data:
                raise ValueError('Mandatory input parameter "%s" missing' % p)
        for p, v in data.items():
            p_class = self.input_params.get(p)
            if not p_class:
                logger.warning('Unexpected/unsupported input parameter "%s"="%s"', p, v)
                output[p] = v
            else:
                output[p] = p_class.decode(v)
        return output

class JsonHttpApiClient():
    def __init__(self, api_func: JsonHttpApiFunction, url_prefix: str, func_req_id: Optional[str],
                 session: requests.Session):
        """
        Args:
                api_func : API function definition (JsonHttpApiFunction)
                url_prefix : prefix to be put in front of the API function path (see JsonHttpApiFunction)
                func_req_id : function requestor id to use for requests
                session : session object (requests)
        """
        self.api_func = api_func
        self.url_prefix = url_prefix
        self.func_req_id = func_req_id
        self.session = session

    def call(self, data: dict, func_call_id: Optional[str] = None, timeout=10) -> Optional[dict]:
        """Make an API call to the HTTP API endpoint represented by this object. Input data is passed in `data` as
        json-serializable dict. Output data is returned as json-deserialized dict."""

        # In case a function caller ID is supplied, use it together with the stored function requestor ID to generate
        # and prepend the header field according to SGP.22, section 6.5.1.1 and 6.5.1.3. (the presence of the header
        # field is checked by the encode_client method)
        if func_call_id:
            data = {'header' : {'functionRequesterIdentifier': self.func_req_id,
                                'functionCallIdentifier': func_call_id}} | data

        # Encode the message (the presence of mandatory fields is checked during encoding)
        encoded = json.dumps(self.api_func.encode_client(data))

        # Apply HTTP request headers according to SGP.22, section 6.5.1
        req_headers = {
            'Content-Type': 'application/json',
            'X-Admin-Protocol': 'gsma/rsp/v2.5.0',
        }
        req_headers.update(self.api_func.extra_http_req_headers)

        # Perform HTTP request
        url = self.url_prefix + self.api_func.path
        logger.debug("HTTP REQ %s - hdr: %s '%s'" % (url, req_headers, encoded))
        response = self.session.request(self.api_func.http_method, url, data=encoded, headers=req_headers, timeout=timeout)
        logger.debug("HTTP RSP-STS: [%u] hdr: %s" % (response.status_code, response.headers))
        logger.debug("HTTP RSP: %s" % (response.content))

        # Check HTTP response status code and make sure that the returned HTTP headers look plausible (according to
        # SGP.22, section 6.5.1)
        if response.status_code != self.api_func.expected_http_status:
            raise HttpStatusError(response)
        if response.content and not response.headers.get('Content-Type').startswith(req_headers['Content-Type']):
            raise HttpHeaderError(response)
        if not response.headers.get('X-Admin-Protocol', 'gsma/rsp/v2.unknown').startswith('gsma/rsp/v2.'):
            raise HttpHeaderError(response)

        # Decode response and return the result back to the caller
        if response.content:
            output = self.api_func.decode_client(response.json())
            # In case the response contains a header, check it to make sure that the API call was executed successfully
            # (the presence of the header field is checked by the decode_client method)
            if 'header' in output:
                if output['header']['functionExecutionStatus']['status'] not in ['Executed-Success','Executed-WithWarning']:
                    raise ApiError(output['header']['functionExecutionStatus'])
            return output
        return None

class JsonHttpApiServer():
    def __init__(self, api_func: JsonHttpApiFunction, call_handler = None):
        """
        Args:
                api_func : API function definition (JsonHttpApiFunction)
                call_handler : handler function to process the request. This function must accept the
                               decoded request as a dictionary. The handler function must return a tuple consisting
                               of the response in the form of a dictionary (may be empty), and a function execution
                               status string ('Executed-Success', 'Executed-WithWarning', 'Failed' or 'Expired')
        """
        self.api_func = api_func
        if call_handler:
            self.call_handler = call_handler
        else:
            self.call_handler = self.default_handler

    def default_handler(self, data: dict) -> (dict, str):
        """default handler, used in case no call handler is provided."""
        logger.error("no handler function for request: %s" % str(data))
        return {}, 'Failed'

    def call(self, request: Request) -> str:
        """ Process an incoming request.
        Args:
                request : request object as received using twisted.web.server
        Returns:
                encoded JSON string (HTTP response code and headers are set by calling the appropriate methods on the
                provided the request object)
        """

        # Make sure the request is done with the correct HTTP method
        if (request.method.decode() != self.api_func.http_method):
            raise ValueError('Wrong HTTP method %s!=%s' % (request.method.decode(), self.api_func.http_method))

        # Decode the request
        decoded_request = self.api_func.decode_server(json.loads(request.content.read()))

        # Run call handler (see above)
        data, fe_status = self.call_handler(decoded_request)

        # In case a function execution status is returned, use it to generate and prepend the header field according to
        # SGP.22, section 6.5.1.2 and 6.5.1.4 (the presence of the header filed is checked by the encode_server method)
        if fe_status:
            data = {'header' : {'functionExecutionStatus': {'status' : fe_status}}} | data

        # Encode the message (the presence of mandatory fields is checked during encoding)
        encoded = json.dumps(self.api_func.encode_server(data))

        # Apply HTTP request headers according to SGP.22, section 6.5.1
        res_headers = {
            'Content-Type': 'application/json',
            'X-Admin-Protocol': 'gsma/rsp/v2.5.0',
        }
        res_headers.update(self.api_func.extra_http_res_headers)
        for header, value in res_headers.items():
            request.setHeader(header, value)
        request.setResponseCode(self.api_func.expected_http_status)

        # Return the encoded result back to the caller for sending (using twisted/klein)
        return encoded

