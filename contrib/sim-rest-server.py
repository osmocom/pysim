#!/usr/bin/env python3

# RESTful HTTP service for performing authentication against USIM cards
#
# (C) 2021-2022 by Harald Welte <laforge@osmocom.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import sys
import argparse

from klein import Klein

from pySim.transport import ApduTracer
from pySim.transport.pcsc import PcscSimLink
from pySim.commands import SimCardCommands
from pySim.cards import UiccCardBase
from pySim.utils import dec_iccid, dec_imsi
from pySim.ts_51_011 import EF_IMSI
from pySim.ts_102_221 import EF_ICCID
from pySim.exceptions import *

class ApduPrintTracer(ApduTracer):
    def trace_response(self, cmd, sw, resp):
        #print("CMD: %s -> RSP: %s %s" % (cmd, sw, resp))
        pass

def connect_to_card(slot_nr:int):
    tp = PcscSimLink(argparse.Namespace(pcsc_dev=slot_nr), apdu_tracer=ApduPrintTracer())
    tp.connect()

    scc = SimCardCommands(tp)
    card = UiccCardBase(scc)

    # this should be part of UsimCard, but FairewavesSIM breaks with that :/
    scc.cla_byte = "00"
    scc.sel_ctrl = "0004"

    card.read_aids()

    # ensure that MF is selected when we are done.
    card._scc.select_file('3f00')

    return tp, scc, card

class ApiError:
    def __init__(self, msg:str, sw=None):
        self.msg = msg
        self.sw = sw

    def __str__(self):
        d = {'error': {'message':self.msg}}
        if self.sw:
            d['error']['status_word'] = self.sw
        return json.dumps(d)


def set_headers(request):
    request.setHeader('Content-Type', 'application/json')

class SimRestServer:
    app = Klein()

    @app.handle_errors(NoCardError)
    def no_card_error(self, request, failure):
        set_headers(request)
        request.setResponseCode(410)
        return str(ApiError("No SIM card inserted in slot"))

    @app.handle_errors(ReaderError)
    def reader_error(self, request, failure):
        set_headers(request)
        request.setResponseCode(404)
        return str(ApiError("Reader Error: Specified SIM Slot doesn't exist"))

    @app.handle_errors(ProtocolError)
    def protocol_error(self, request, failure):
        set_headers(request)
        request.setResponseCode(500)
        return str(ApiError("Protocol Error: %s" % failure.value))

    @app.handle_errors(SwMatchError)
    def sw_match_error(self, request, failure):
        set_headers(request)
        request.setResponseCode(500)
        sw = failure.value.sw_actual
        if sw == '9862':
            return str(ApiError("Card Authentication Error - Incorrect MAC", sw))
        elif sw == '6982':
            return str(ApiError("Security Status not satisfied - Card PIN enabled?", sw))
        else:
            return str(ApiError("Card Communication Error %s" % failure.value, sw))


    @app.route('/sim-auth-api/v1/slot/<int:slot>')
    def auth(self, request, slot):
        """REST API endpoint for performing authentication against a USIM.
           Expects a JSON body containing RAND and AUTN.
           Returns a JSON body containing RES, CK, IK and Kc."""
        try:
            # there are two hex-string JSON parameters in the body: rand and autn
            content = json.loads(request.content.read())
            rand = content['rand']
            autn = content['autn']
        except:
            set_headers(request)
            request.setResponseCode(400)
            return str(ApiError("Malformed Request"))

        tp, scc, card = connect_to_card(slot)

        card.select_adf_by_aid(adf='usim')
        res, sw = scc.authenticate(rand, autn)

        tp.disconnect()

        set_headers(request)
        return json.dumps(res, indent=4)

    @app.route('/sim-info-api/v1/slot/<int:slot>')
    def info(self, request, slot):
        """REST API endpoint for obtaining information about an USIM.
        Expects empty body in request.
        Returns a JSON body containing ICCID, IMSI."""

        tp, scc, card = connect_to_card(slot)

        ef_iccid = EF_ICCID()
        (iccid, sw) = card._scc.read_binary(ef_iccid.fid)

        card.select_adf_by_aid(adf='usim')
        ef_imsi = EF_IMSI()
        (imsi, sw) = card._scc.read_binary(ef_imsi.fid)

        res = {"imsi": dec_imsi(imsi), "iccid": dec_iccid(iccid) }

        tp.disconnect()

        set_headers(request)
        return json.dumps(res, indent=4)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host/IP to bind HTTP to", default="localhost")
    parser.add_argument("-p", "--port", help="TCP port to bind HTTP to", default=8000)
    #parser.add_argument("-v", "--verbose", help="increase output verbosity", action='count', default=0)

    args = parser.parse_args()

    srr = SimRestServer()
    srr.app.run(args.host, args.port)

if __name__ == "__main__":
    main(sys.argv)
