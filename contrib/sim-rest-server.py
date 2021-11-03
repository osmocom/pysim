#!/usr/bin/env python3

# RESTful HTTP service for performing authentication against USIM cards
#
# (C) 2021 by Harald Welte <laforge@osmocom.org>
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

from klein import run, route

from pySim.transport import ApduTracer
from pySim.transport.pcsc import PcscSimLink
from pySim.commands import SimCardCommands
from pySim.cards import UsimCard
from pySim.exceptions import *

class ApduPrintTracer(ApduTracer):
    def trace_response(self, cmd, sw, resp):
        #print("CMD: %s -> RSP: %s %s" % (cmd, sw, resp))
        pass

def connect_to_card(slot_nr:int):
    tp = PcscSimLink(slot_nr, apdu_tracer=ApduPrintTracer())
    tp.connect()

    scc = SimCardCommands(tp)
    card = UsimCard(scc)

    # this should be part of UsimCard, but FairewavesSIM breaks with that :/
    scc.cla_byte = "00"
    scc.sel_ctrl = "0004"

    card.read_aids()
    card.select_adf_by_aid(adf='usim')

    return tp, scc, card


@route('/sim-auth-api/v1/slot/<int:slot>')
def auth(request, slot):
    """REST API endpoint for performing authentication against a USIM.
       Expects a JSON body containing RAND and AUTN.
       Returns a JSON body containing RES, CK, IK and Kc."""
    try:
        # there are two hex-string JSON parameters in the body: rand and autn
        content = json.loads(request.content.read())
        rand = content['rand']
        autn = content['autn']
    except:
        request.setResponseCode(400)
        return "Malformed Request"

    try:
        tp, scc, card = connect_to_card(slot)
    except ReaderError:
        request.setResponseCode(404)
        return "Specified SIM Slot doesn't exist"
    except ProtocolError:
        request.setResponseCode(500)
        return "Error"
    except NoCardError:
        request.setResponseCode(410)
        return "No SIM card inserted in slot"

    try:
        card.select_adf_by_aid(adf='usim')
        res, sw = scc.authenticate(rand, autn)
    except SwMatchError as e:
        request.setResponseCode(500)
        return "Communication Error %s" % e

    tp.disconnect()

    return json.dumps(res, indent=4)

@route('/sim-info-api/v1/slot/<int:slot>')
def info(request, slot):
    """REST API endpoint for obtaining information about an USIM.
    Expects empty body in request.
    Returns a JSON body containing ICCID, IMSI."""

    try:
        tp, scc, card = connect_to_card(slot)
    except ReaderError:
        request.setResponseCode(404)
        return "Specified SIM Slot doesn't exist"
    except ProtocolError:
        request.setResponseCode(500)
        return "Error"
    except NoCardError:
        request.setResponseCode(410)
        return "No SIM card inserted in slot"

    try:
        card.select_adf_by_aid(adf='usim')
        iccid, sw = card.read_iccid()
        imsi, sw = card.read_imsi()
        res = {"imsi": imsi, "iccid": iccid }
    except SwMatchError as e:
        request.setResponseCode(500)
        return "Communication Error %s" % e

    tp.disconnect()

    return json.dumps(res, indent=4)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host/IP to bind HTTP to", default="localhost")
    parser.add_argument("-p", "--port", help="TCP port to bind HTTP to", default=8000)
    #parser.add_argument("-v", "--verbose", help="increase output verbosity", action='count', default=0)

    args = parser.parse_args()

    run(args.host, args.port)

if __name__ == "__main__":
    main(sys.argv)
