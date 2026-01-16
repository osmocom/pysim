#!/usr/bin/env python3.11

import sys
import argparse

from pySim.esim.http_json_api import *
from pySim.esim.es2p import param, Es2pApiServer, Es2pApiServerHandler

import logging
from pySim.log import PySimLogger

log = PySimLogger.get("main")


parser = argparse.ArgumentParser(description="""
Utility to receive and log requests against the ES2+ API of an SM-DP+ according to GSMA SGP.22.""")
parser.add_argument('--server-cert', help='X.509 server certificate used to provide the ES2+ HTTPs service')
parser.add_argument('--client-ca-cert', help='X.509 CA certificates to authenticate the requesting client(s)')
parser.add_argument("-v", "--verbose", help="dump more raw info", action='store_true', default=False)

class Es2pApiServerHandlerForLogging(Es2pApiServerHandler):

    def call_downloadOrder(self, data: dict) -> (dict, str):
        print("========> Got request: ", data)
        data_res = {'iccid' : '89000000000000000023'}
        fe_status = 'Executed-Success'
        return data_res, fe_status

    def call_releaseProfile(self, data: dict) -> (dict, str):
        print("========> Got request: ", str(data))
        data_res = {}
        fe_status = 'Executed-Success'
        return data_res, fe_status

    def call_handleDownloadProgressInfo(self, data: dict) -> (dict, str):
 #       log.info("Request: %s", str(data))
        return {}, None

if __name__ == "__main__":
    opts = parser.parse_args()


    PySimLogger.setup(print, {logging.WARN: "\033[33m"})
    PySimLogger.set_verbose(True)
    PySimLogger.set_level(logging.DEBUG)

    log.debug("es2p_server started")
#    logging.basicConfig(level=logging.DEBUG if opts.verbose else logging.WARNING)
    Es2pApiServer(8030, "127.0.0.1", Es2pApiServerHandlerForLogging(), opts.server_cert, opts.client_ca_cert)

