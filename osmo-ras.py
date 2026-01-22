#!/usr/bin/env python3

# Remote Application Server for Remote Application Management over HTTP
# See Amendment B of the GlobalPlatform Card Specification v2.2
#
# (C) 2025 sysmocom s.f.m.c.
# Author: Daniel Willmann <dwillmann@sysmocom.de>
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

from http.server import HTTPServer, SimpleHTTPRequestHandler
from ssl import PROTOCOL_TLS_SERVER, SSLContext, TLSVersion


context = SSLContext(PROTOCOL_TLS_SERVER)
context.maximum_version = TLSVersion.TLSv1_2
CIPHERS_1_0 = "TLS_PSK_WITH_3DES_EDE_CBC_SHA,TLS_PSK_WITH_AES_128_CBC_SHA,TLS_PSK_WITH_NULL_SHA"
CIPHERS_1_2 = "TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA256"
context.set_ciphers(CIPHERS_1_2)

# A table using the identity of the client:
psk_table = { 'ClientId_1': bytes.fromhex('c0ffee'),
              'ClientId_2': bytes.fromhex('facade')
}

def get_psk(ident):
    """ Get the PSK for the client """
    print(f"Get PSK for {ident}")
    return psk_table.get(ident, b'')

context.set_psk_server_callback(get_psk)

server = HTTPServer(("0.0.0.0", 8080), SimpleHTTPRequestHandler)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
