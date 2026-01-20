#!/usr/bin/env python3

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier
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

import sys
import argparse
import logging
import json
import asn1tools
import asn1tools.codecs.ber
import asn1tools.codecs.der
import pySim.esim.rsp as rsp
import pySim.esim.saip as saip
from pySim.esim.es2p import param, Es2pApiServerMno, Es2pApiServerHandlerMno
from osmocom.utils import b2h
from datetime import datetime
from analyze_simaResponse import split_sima_response
from pathlib import Path

logger = logging.getLogger(Path(__file__).stem)

parser = argparse.ArgumentParser(description="""
Utility to receive and log requests against the ES2+ API of an SM-DP+ according to GSMA SGP.22.""")
parser.add_argument("--host", help="Host/IP to bind HTTP(S) to", default="localhost")
parser.add_argument("--port", help="TCP port to bind HTTP(S) to", default=443, type=int)
parser.add_argument('--server-cert', help='X.509 server certificate used to provide the ES2+ HTTPs service')
parser.add_argument('--client-ca-cert', help='X.509 CA certificates to authenticate the requesting client(s)')
parser.add_argument("-v", "--verbose", help="enable debug output", action='store_true', default=False)

def decode_sima_response(sima_response):
    decoded = []
    euicc_response_list = split_sima_response(sima_response)
    for euicc_response in euicc_response_list:
        decoded.append(saip.asn1.decode('EUICCResponse', euicc_response))
    return decoded

def decode_result_data(result_data):
    return rsp.asn1.decode('PendingNotification', result_data)

def decode(data, path="/"):
    if data is None:
        return 'none'
    elif type(data) is datetime:
        return data.isoformat()
    elif type(data) is tuple:
        return {str(data[0]) : decode(data[1], path + str(data[0]) + "/")}
    elif type(data) is list:
        new_data = []
        for item in data:
            new_data.append(decode(item, path))
        return new_data
    elif type(data) is bytes:
        return b2h(data)
    elif type(data) is dict:
        new_data = {}
        for key, item in data.items():
            new_key = str(key)
            if path == '/' and new_key == 'resultData':
                new_item = decode_result_data(item)
            elif (path == '/resultData/profileInstallationResult/profileInstallationResultData/finalResult/successResult/' \
                  or path == '/resultData/profileInstallationResult/profileInstallationResultData/finalResult/errorResult/') \
                  and new_key == 'simaResponse':
                new_item = decode_sima_response(item)
            else:
                new_item = item
            new_data[new_key] = decode(new_item, path + new_key + "/")
        return new_data
    else:
        return data

class Es2pApiServerHandlerForLogging(Es2pApiServerHandlerMno):
    def call_handleDownloadProgressInfo(self, data: dict) -> (dict, str):
        logging.info("ES2+:handleDownloadProgressInfo: %s" % json.dumps(decode(data)))
        return {}, None

if __name__ == "__main__":
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    Es2pApiServerMno(args.port, args.host, Es2pApiServerHandlerForLogging(), args.server_cert, args.client_ca_cert)

