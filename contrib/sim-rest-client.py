#!/usr/bin/env python3
#
# sim-rest-client.py: client program to test the sim-rest-server.py
#
# this will generate authentication tuples just like a HLR / HSS
# and will then send the related challenge to the REST interface
# of sim-rest-server.py
#
# sim-rest-server.py will then contact the SIM card to perform the
# authentication (just like a 3GPP RAN), and return the results via
# the REST to sim-rest-client.py.
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

from typing import Optional, Dict

import sys
import argparse
import secrets
import requests

from CryptoMobile.Milenage import Milenage
from CryptoMobile.utils import xor_buf

def unpack48(x:bytes) -> int:
    """Decode a big-endian 48bit number from binary to integer."""
    return int.from_bytes(x, byteorder='big')

def pack48(x:int) -> bytes:
    """Encode a big-endian 48bit number from integer to binary."""
    return x.to_bytes(48 // 8, byteorder='big')

def milenage_generate(opc:bytes, amf:bytes, k:bytes, sqn:bytes, rand:bytes) -> Dict[str, bytes]:
    """Generate an MILENAGE Authentication Tuple."""
    m = Milenage(None)
    m.set_opc(opc)
    mac_a = m.f1(k, rand, sqn, amf)
    res, ck, ik, ak = m.f2345(k, rand)

    # AUTN = (SQN ^ AK) || AMF || MAC
    sqn_ak = xor_buf(sqn, ak)
    autn = b''.join([sqn_ak, amf, mac_a])

    return {'res': res, 'ck': ck, 'ik': ik, 'autn': autn}

def milenage_auts(opc:bytes, k:bytes, rand:bytes, auts:bytes) -> Optional[bytes]:
    """Validate AUTS. If successful, returns SQN_MS"""
    amf = b'\x00\x00' # TS 33.102 Section 6.3.3
    m = Milenage(None)
    m.set_opc(opc)
    ak = m.f5star(k, rand)

    sqn_ak = auts[:6]
    sqn = xor_buf(sqn_ak, ak[:6])

    mac_s = m.f1star(k, rand, sqn, amf)
    if mac_s == auts[6:14]:
        return sqn
    else:
        return False


def build_url(suffix:str, base_path="/sim-auth-api/v1") -> str:
    """Build an URL from global server_host, server_port, BASE_PATH and suffix."""
    return "http://%s:%u%s%s" % (server_host, server_port, base_path, suffix)


def rest_post(suffix:str, js:Optional[dict] = None):
    """Perform a RESTful POST."""
    url = build_url(suffix)
    if verbose:
        print("POST %s (%s)" % (url, str(js)))
    resp = requests.post(url, json=js)
    if verbose:
        print("-> %s" % (resp))
    if not resp.ok:
        print("POST failed")
    return resp

def rest_get(suffix:str, base_path=None):
    """Perform a RESTful GET."""
    url = build_url(suffix, base_path)
    if verbose:
        print("GET %s" % url)
    resp = requests.get(url)
    if verbose:
        print("-> %s" % (resp))
    if not resp.ok:
        print("GET failed")
    return resp


def main_info(args):
    resp = rest_get('/slot/%u' % args.slot_nr, base_path="/sim-info-api/v1")
    if not resp.ok:
        print("<- ERROR %u: %s" % (resp.status_code, resp.text))
        sys.exit(1)
    resp_json = resp.json()
    print("<- %s" % resp_json)


def main_auth(args):
    #opc = bytes.fromhex('767A662ACF4587EB0C450C6A95540A04')
    #k = bytes.fromhex('876B2D8D403EE96755BEF3E0A1857EBE')
    opc = bytes.fromhex(args.opc)
    k = bytes.fromhex(args.key)
    amf = bytes.fromhex(args.amf)
    sqn = bytes.fromhex(args.sqn)

    for i in range(args.count):
        rand = secrets.token_bytes(16)
        t = milenage_generate(opc=opc, amf=amf, k=k, sqn=sqn, rand=rand)

        req_json = {'rand': rand.hex(), 'autn': t['autn'].hex()}
        print("-> %s" % req_json)
        resp = rest_post('/slot/%u' % args.slot_nr, req_json)
        if not resp.ok:
            print("<- ERROR %u: %s" % (resp.status_code, resp.text))
            break
        resp_json = resp.json()
        print("<- %s" % resp_json)
        if 'synchronisation_failure' in resp_json:
            auts = bytes.fromhex(resp_json['synchronisation_failure']['auts'])
            sqn_ms = milenage_auts(opc, k, rand, auts)
            if sqn_ms is not False:
                print("SQN_MS = %s" % sqn_ms.hex())
                sqn_ms_int = unpack48(sqn_ms)
                # we assume an IND bit-length of 5 here
                sqn = pack48(sqn_ms_int + (1 << 5))
            else:
                raise RuntimeError("AUTS auth failure during re-sync?!?")
        elif 'successful_3g_authentication' in resp_json:
            auth_res = resp_json['successful_3g_authentication']
            assert bytes.fromhex(auth_res['res']) == t['res']
            assert bytes.fromhex(auth_res['ck']) == t['ck']
            assert bytes.fromhex(auth_res['ik']) == t['ik']
            # we assume an IND bit-length of 5 here
            sqn = pack48(unpack48(sqn) + (1 << 5))
        else:
            raise RuntimeError("Auth failure")


def main(argv):
    global server_port, server_host, verbose

    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to connect to", default="localhost")
    parser.add_argument("-p", "--port", help="TCP port to connect to", default=8000)
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action='count', default=0)
    parser.add_argument("-n", "--slot-nr", help="SIM slot number", type=int, default=0)
    subp = parser.add_subparsers()
    subp.required = True

    auth_p = subp.add_parser('auth', help='UMTS AKA Authentication')
    auth_p.add_argument("-c", "--count", help="Auth count", type=int, default=10)
    auth_p.add_argument("-k", "--key", help="Secret key K (hex)", type=str, required=True)
    auth_p.add_argument("-o", "--opc", help="Secret OPc (hex)", type=str, required=True)
    auth_p.add_argument("-a", "--amf", help="AMF Field (hex)", type=str, default="0000")
    auth_p.add_argument("-s", "--sqn", help="SQN Field (hex)", type=str, default="000000000000")
    auth_p.set_defaults(func=main_auth)

    info_p = subp.add_parser('info', help='Information about the Card')
    info_p.set_defaults(func=main_info)

    args = parser.parse_args()
    server_host = args.host
    server_port = args.port
    verbose = args.verbose
    args.func(args)


if __name__ == "__main__":
    main(sys.argv)
