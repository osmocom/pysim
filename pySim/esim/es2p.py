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
    """Base classs for representing an ES2+ API Function."""
    pass

# ES2+ DownloadOrder function (SGP.22 section 5.3.1)
class DownloadOrder(Es2PlusApiFunction):
    path = '/gsma/rsp2/es2plus/downloadOrder'
    input_params = {
        'eid': param.Eid,
        'iccid': param.Iccid,
        'profileType': param.ProfileType
      }
    output_params = {
        'header': JsonResponseHeader,
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
        'iccid': param.Iccid,
        'eid': param.Eid,
        'matchingId': param.MatchingId,
        'finalProfileStatusIndicator': param.FinalProfileStatusIndicator,
      }
    input_mandatory = ['finalProfileStatusIndicator', 'iccid']
    output_params = {
        'header': JsonResponseHeader,
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
        'header': JsonResponseHeader,
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
