#!/usr/bin/env python3
"""TLS-PSK HTTP Remote Administration Server for SCP81 / RAM over HTTP"""

# (C) 2026 by sysmocom - s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Eric Wild <ewild@sysmocom.de>
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

# The card (specifically a SD supporting SCP81) is the TLS client:
# - it opens a TCP connection to this server,
# - performs a TLS handshake authenticated with a PSK,
# - and then drives the HTTP admin loop of to fetch remote APDU command strings
# - and posts back their responses.
# This program is the server side of that exchange, it:
# - accepts the PSK-TLS connection,
# - hands the card a queue of commands
# - and logs the decoded responses.
#
# The two TS 102 226 annex B figure B.1 administration modes are supported over the
# same session, selected with --mode:
#   ram  GP Amendment B RAM:
#           command is handled by (--targeted-application) a SD
#   rfm  ETSI TS 102 226 RFM/RAM:
#           command is routed to the Receiving/RFM Application specified by
#           --targeted-application, for example UICC-filesystem/USIM-ADF RFM app.
#
# Remote APDU command/response bodies use the Expanded Remote Application
# data format.
#

import ssl
import socket
import logging
import argparse
import threading
from pathlib import Path
from typing import List, Optional, Callable, Dict, Tuple

from osmocom.utils import h2b, b2h

from pySim.ota import encode_expanded_cmd, decode_expanded_resp

logger = logging.getLogger(Path(__file__).stem)

# Amendment B section 3.4
ADMIN_PROTOCOL = 'globalplatform-remote-admin/1.0'
CT_COMMAND = 'application/vnd.globalplatform.card-content-mgt;version=1.0'
CT_RESPONSE = 'application/vnd.globalplatform.card-content-mgt-response;version=1.0'

#  TS 102 226 annex B, figure B.1 RFM/RAM over HTTPS content types
CT_RFM_COMMAND = 'application/vnd.etsi.scp.command-data;version=1.0'
CT_RFM_RESPONSE = 'application/vnd.etsi.scp.response-data;version=1.0'

MODE_CONTENT_TYPE = {
    'ram': CT_COMMAND,          # GP Amendment B RAM: target = a Security Domain
    'rfm': CT_RFM_COMMAND,      # ETSI TS 102 226 RFM/RAM: target = an application
}

# Amendment B Table 3-2. The 3DES and NULL suites are left out and can be enabled with
# --ciphers / --seclevel.
DEFAULT_CIPHERS = ':'.join([
    'PSK-AES128-CBC-SHA256',    # TLS_PSK_WITH_AES_128_CBC_SHA256, TLS 1.2
    'PSK-AES128-CBC-SHA',       # TLS_PSK_WITH_AES_128_CBC_SHA, TLS 1.0/1.1
])

TLS_VERSION_MAP = {
    '1.0': ssl.TLSVersion.TLSv1,
    '1.1': ssl.TLSVersion.TLSv1_1,
    '1.2': ssl.TLSVersion.TLSv1_2,
    '1.3': ssl.TLSVersion.TLSv1_3,
}


def format_aid(aid: str) -> str:
    """AID -> //aid/<RID>/<PIX> for X-Admin-Targeted-Application from Amendment B section 3.4.2
      First 5 bytes RID, the PIX the remainder, string in //aid/ notation is passed through."""
    if aid.startswith('//aid/'):
        return aid
    aid = aid.replace(' ', '').lower()
    if len(aid) < 10:
        raise ValueError('AID %r is shorter than the 5 byte RID' % aid)
    rid, pix = aid[:10], aid[10:]
    return '//aid/%s/%s' % (rid, pix)


def make_ssl_context(psk: bytes, identity: str, *,
                     ciphers: str = DEFAULT_CIPHERS,
                     min_tls: str = '1.2', max_tls: str = '1.3',
                     seclevel: Optional[int] = None,
                     identity_hint: Optional[str] = None,
                     allow_any_identity: bool = False,
                     extra_psks: Optional[Dict[str, bytes]] = None) -> ssl.SSLContext:
    """PSK SSLContext, resolvesg the key from the client psk_identity

    extra_psks can carry additional identity->key mappings.
    allow_any_identity can be used for debugging
    """
    # the PSK callback must return immutable bytes, h2b() gives a bytearray
    psk = bytes(psk)
    keymap: Dict[str, bytes] = {identity: psk}
    if extra_psks:
        keymap.update({k: bytes(v) for k, v in extra_psks.items()})

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = TLS_VERSION_MAP[min_tls]
    ctx.maximum_version = TLS_VERSION_MAP[max_tls]
    cipher_str = ciphers
    if seclevel is not None:
        # @SECLEVEL=0 is to enable NULL/3DES/legacy PSK suites
        cipher_str = '%s:@SECLEVEL=%d' % (ciphers, seclevel)
    if cipher_str:
        ctx.set_ciphers(cipher_str)

    def psk_server_callback(client_identity: Optional[str]) -> bytes:
        if allow_any_identity:
            logger.info('PSK handshake: identity=%r (ACEPTING ANY!)', client_identity)
            return psk
        key = keymap.get(client_identity)
        if key is None:
            logger.warning('PSK handshake: unknown identity %r (known: %r) -> rejecting',
                           client_identity, list(keymap.keys()))
            return b''    # empty PSK aborts handshake
        logger.info('PSK handshake: identity=%r resolved', client_identity)
        return key

    ctx.set_psk_server_callback(psk_server_callback, identity_hint=identity_hint)
    return ctx


class HttpRequest:
    """A parsed HTTP request (request line + headers + body)."""
    __slots__ = ('method', 'uri', 'version', 'headers', 'body')

    def __init__(self, method: str, uri: str, version: str,
                 headers: Dict[str, str], body: bytes):
        self.method = method
        self.uri = uri
        self.version = version
        self.headers = headers      # lower cased field names
        self.body = body

    def get(self, name: str, default=None) -> Optional[str]:
        return self.headers.get(name.lower(), default)


# http.client bound on a single HTTP line.
MAX_LINE = 65536


def _read_line(rfile) -> bytes:
    """readline() with a bound. reaching the bound without a
    terminator means the card is out of sync somehow, not that the line is long."""
    line = rfile.readline(MAX_LINE)
    if line and not line.endswith(b'\n'):
        raise ValueError('HTTP line longer than %u bytes' % MAX_LINE)
    return line


def _read_chunked_body(rfile) -> bytes:
    """Read a Transfer-Encoding: chunked body. Amendment B section 3.4.1 lets
    the card send its response string with either a Content-Length or chunked"""
    out = bytearray()
    while True:
        size_line = _read_line(rfile)
        if not size_line:
            break
        size = int(size_line.split(b';', 1)[0].strip() or b'0', 16)
        if size == 0:
            # consume trailer headers up to the terminating blank line
            while _read_line(rfile) not in (b'\r\n', b'\n', b''):
                pass
            break
        chunk = rfile.read(size)
        if len(chunk) != size:
            raise ValueError('chunked body ended after %u of %u bytes' % (len(chunk), size))
        out += chunk
        _read_line(rfile)   # trailing CRLF after the chunk data
    return bytes(out)


def read_http_request(rfile, send: Optional[Callable[[bytes], None]] = None) -> Optional[HttpRequest]:
    """Read one HTTP request from a buffered binary reader or None when closed"""
    request_line = _read_line(rfile)
    if not request_line:
        return None
    parts = request_line.rstrip(b'\r\n').decode('iso-8859-1').split(' ')
    if len(parts) < 3:
        raise ValueError('Malformed HTTP request line: %r' % request_line)
    method, uri, version = parts[0], parts[1], parts[2]

    headers: Dict[str, str] = {}
    while True:
        line = _read_line(rfile)
        if line in (b'\r\n', b'\n', b''):
            break
        name, _, value = line.rstrip(b'\r\n').decode('iso-8859-1').partition(':')
        headers[name.strip().lower()] = value.strip()

    # Expect: 100-continue waits for the response before it sends the body,
    # and RFC 2616 8.2.3 (Amendment B references RFC 2616 as [HTTP])
    # requires the server to send it. Amendment B 3.4.1 does not mention this
    # header, tho, might be useless.
    if send and '100-continue' in headers.get('expect', '').lower():
        logger.info('-> 100 Continue ')
        send(b'HTTP/1.1 100 Continue\r\n\r\n')

    body = b''
    te = headers.get('transfer-encoding', '').lower()
    if 'chunked' in te:
        body = _read_chunked_body(rfile)
    elif 'content-length' in headers:
        n = int(headers['content-length'])
        if n:
            body = rfile.read(n)
    return HttpRequest(method, uri, version, headers, body)


def build_http_response(status_line: str, headers: List[Tuple[str, str]],
                        body: bytes = b'') -> bytes:
    """Serialise  HTTP response.  status_line 'HTTP/1.1 200 OK'."""
    lines = [status_line]
    lines += ['%s: %s' % (name, value) for name, value in headers]
    head = ('\r\n'.join(lines) + '\r\n\r\n').encode('iso-8859-1')
    return head + body


def format_decoded_response(dec) -> str:
    """hand over the data"""
    bits = ['%u command(s) executed' % dec.number_of_commands]
    for i, c in enumerate(dec.commands):
        data = c.response_data or '-'
        bits.append('  R-APDU[%u]: SW=%s data=%s' % (i, c.status_word, data))
    if dec.get('truncated'):
        bits.append('  TRUNCATED: an R-APDU returned SW 62F1, so the card cut the response data '
                    'short and stopped executing the rest of the script ') # TS 102 226 5.2.1.1
    if dec.bad_format is not None:
        bits.append('  bad-format: %s' % dec.bad_format)
    if dec.immediate_action_response is not None:
        bits.append('  immediate-action-response: %s' % dec.immediate_action_response)
    if dec.script_chaining_response is not None:
        bits.append('  script-chaining-response: %s' % dec.script_chaining_response)
    return '\n'.join(bits)


class AdminSession:

    def __init__(self, command_bodies: List[bytes],
                 next_uri: Optional[str] = None,
                 targeted_application: Optional[str] = None,
                 on_response: Optional[Callable[[object], None]] = None,
                 content_type: str = CT_COMMAND):
        self.pending: List[bytes] = list(command_bodies)
        self.next_uri = next_uri            # None -> echo the request URI
        self.targeted_application = targeted_application
        self.on_response = on_response
        self.content_type = content_type    # Content-Type for the command body
        self.responses: List[object] = []   # decoded Containers, in order

    def record_response(self, dec) -> None:
        self.responses.append(dec)
        if self.on_response:
            self.on_response(dec)


def run_admin_loop(rfile, send: Callable[[bytes], None], session: AdminSession) -> AdminSession:
    """Drive the admin loop for one connection.
    Just keep answering the card POST requests with the next queued command
    (200 OK + Expanded command body) until the queue is empty, end session with 204 No Content."""
    while True:
        req = read_http_request(rfile, send)
        if req is None:
            logger.info('connection closed by card')
            return session

        if req.method != 'POST':
            logger.warning('unexpected method %s %s -> 405', req.method, req.uri)
            send(build_http_response('HTTP/1.1 405 Method Not Allowed',
                                     [('X-Admin-Protocol', ADMIN_PROTOCOL),
                                      ('Connection', 'close')]))
            return session

        proto = req.get('x-admin-protocol')
        if proto and proto != ADMIN_PROTOCOL:
            logger.warning('card X-Admin-Protocol=%r (expected %r)', proto, ADMIN_PROTOCOL)
        status = req.get('x-admin-script-status')
        resume = req.get('x-admin-resume')
        logger.info('POST %s from=%r status=%r resume=%r body=%uB',
                    req.uri, req.get('x-admin-from'), status, resume, len(req.body))

        # section 3.4.1:
        # - body with "X-Admin-Script-Status: ok" carries the previous command
        # response string (Expanded Remote response format);
        # - other status values carry no body ().
        if req.body:
            # Expanded Remote response:
            # - GP Amd B 'card-content-mgt-response'
            # - ETSI 'scp.response-data'
            logger.debug('  response Content-Type=%r raw body (%uB): %s',
                         req.get('content-type'), len(req.body), b2h(req.body))
            if status in (None, 'ok'):
                try:
                    dec = decode_expanded_resp(req.body)
                    session.record_response(dec)
                    logger.info('card response:\n%s', format_decoded_response(dec))
                except Exception as e:
                    logger.error('failed to decode response body %s: %s', b2h(req.body), e)
            else:
                logger.warning('body present with status=%r; ignoring', status) #  section 3.4.1
        elif status and status != 'ok':
            logger.info('card reported script-status=%r (no response body)', status)

        if session.pending:
            body = session.pending.pop(0)
            next_uri = session.next_uri or req.uri
            headers = [('X-Admin-Protocol', ADMIN_PROTOCOL),
                       ('X-Admin-Next-URI', next_uri),
                       ('Content-Type', session.content_type)]
            if session.targeted_application:
                headers.append(('X-Admin-Targeted-Application', session.targeted_application))
            headers.append(('Content-Length', str(len(body))))
            logger.info('-> 200 OK, next command (%uB): %s', len(body), b2h(body))
            send(build_http_response('HTTP/1.1 200 OK', headers, body))
        else:
            # section 3.4.2: No more commands, end session
            # No Content-Type or body for 204
            logger.info('-> 204 No Content, ending administration session')
            send(build_http_response('HTTP/1.1 204 No Content',
                                     [('X-Admin-Protocol', ADMIN_PROTOCOL),
                                      ('Connection', 'close')]))
            return session


class Scp81AdminServer:
    """Threaded TLS-PSK server that runs the Amendment B admin loop against each
    connecting card."""

    def __init__(self, host: str, port: int, ssl_ctx: ssl.SSLContext,
                 command_bodies: List[bytes],
                 next_uri: Optional[str] = None,
                 targeted_application: Optional[str] = None,
                 on_response: Optional[Callable[[object], None]] = None,
                 on_session_end: Optional[Callable[[AdminSession], None]] = None,
                 content_type: str = CT_COMMAND):
        self.host = host
        self.port = port
        self.ssl_ctx = ssl_ctx
        self.command_bodies = command_bodies
        self.next_uri = next_uri
        self.targeted_application = targeted_application
        self.content_type = content_type
        self.on_response = on_response
        self.on_session_end = on_session_end
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()

    def bind(self) -> int:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        return self.port

    def serve_forever(self) -> None:
        if self._sock is None:
            self.bind()
        logger.info('SCP81 admin server listening on %s:%u (%u command(s) queued)',
                    self.host, self.port, len(self.command_bodies))
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def shutdown(self) -> None:
        self._stop.set()
        if self._sock is not None:
            self._sock.close()

    def _handle(self, conn: socket.socket, addr) -> None:
        try:
            tls = self.ssl_ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as e:
            logger.warning('TLS-PSK handshake with %s failed: %s', addr, e)
            try:
                conn.close()
            except OSError:
                pass
            return
        logger.info('TLS-PSK established with %s: %s / %s', addr, tls.version(), tls.cipher())
        session = AdminSession(self.command_bodies, next_uri=self.next_uri,
                               targeted_application=self.targeted_application,
                               on_response=self.on_response,
                               content_type=self.content_type)
        try:
            rfile = tls.makefile('rb')
            run_admin_loop(rfile, tls.sendall, session)
        except (ssl.SSLError, OSError, ValueError) as e:
            logger.warning('session with %s aborted: %s', addr, e)
        finally:
            try:
                tls.close()
            except OSError:
                pass
        logger.info('session with %s ended: %u response(s) collected', addr, len(session.responses))
        if self.on_session_end:
            self.on_session_end(session)


def build_command_bodies(apdus: List[bytes], batch: bool = False,
                         length_coding: str = 'definite') -> List[bytes]:
    """wrpa apdus
    each C-APDU -> one cmd message + one HTTP response per APDU
    batch=True -> all C-APDUs in one Command Scripting template.
    length_coding selects the definite or indefinite Command Scripting template."""
    if not apdus:
        return []
    if batch:
        return [encode_expanded_cmd(apdus, length_coding=length_coding)]
    return [encode_expanded_cmd(a, length_coding=length_coding) for a in apdus]


def main():
    parser = argparse.ArgumentParser(
        description='TLS-PSK HTTP Remote Administration Server for SCP81 / RAM over HTTP')
    parser.add_argument('--host', default='0.0.0.0', help='Host/IP to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8443, help='TCP port to bind to (default: 8443)')
    parser.add_argument('--psk', required=True,
                        help='PSK TLS key, Amendment B key type 85 as hex')
    parser.add_argument('--psk-identity', required=True,
                        help='Expected PSK identity string presented by the card')
    parser.add_argument('--psk-identity-hint', default=None,
                        help='Optional PSK identity hint to send to the card (default: none)')
    parser.add_argument('--allow-any-identity', action='store_true',
                        help='DEBUG: Accept any psk_identity')
    parser.add_argument('--ciphers', default=DEFAULT_CIPHERS,
                        help='OpenSSL cipher string for TLS<=1.2')
    parser.add_argument('--min-tls', default='1.2', choices=sorted(TLS_VERSION_MAP),
                        help='Minimum TLS version (default: 1.2)')
    parser.add_argument('--max-tls', default='1.3', choices=sorted(TLS_VERSION_MAP),
                        help='Maximum TLS version (default: 1.3)')
    parser.add_argument('--seclevel', type=int, default=None,
                        help='OpenSSL @SECLEVEL to force (0 to enable NULL/3DES/legacy PSK)')
    parser.add_argument('--uri', default=None,
                        help='X-Admin-Next-URI to hand the card (default: request URI)')
    parser.add_argument('--mode', choices=sorted(MODE_CONTENT_TYPE), default='ram',
                        help='"ram" = GP Amendment B RAM to a SD (default), '
                             '"rfm" = TS 102 226 RFM/RAM to the --targeted-application.')
    parser.add_argument('--targeted-application', default=None,
                        help='X-Admin-Targeted-Application AID (hex). '
                             'Required by --mode rfm, optional for --mode ram')
    parser.add_argument('--length-coding', choices=('definite', 'indefinite'), default='definite',
                        help='Expanded format length coding "definite" "indefinite"')
    parser.add_argument('--apdu', action='append', default=[], metavar='HEX',
                        help='one of many C-APDU (hex) to send, executed in order')
    parser.add_argument('--apdu-file', default=None,
                        help='File with one C-APDU (hex) per line to push (# comments allowed)')
    parser.add_argument('--batch', action='store_true',
                        help='All C-APDUs in one large command message')
    parser.add_argument('--raw-cmd', action='append', default=[], metavar='HEX',
                        help='Debug, raw command')
    parser.add_argument('-v', '--verbose', action='store_true', help='enable debug output')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    if args.mode == 'rfm' and not args.targeted_application:
        parser.error('--mode rfm requires --targeted-application <RFM Application AID>')
    content_type = MODE_CONTENT_TYPE[args.mode]

    apdus: List[bytes] = [h2b(a) for a in args.apdu]
    if args.apdu_file:
        for line in Path(args.apdu_file).read_text().splitlines():
            line = line.split('#', 1)[0].strip()
            if line:
                apdus.append(h2b(line))
    command_bodies = build_command_bodies(apdus, batch=args.batch,
                                          length_coding=args.length_coding)
    command_bodies += [h2b(r) for r in args.raw_cmd]
    if not command_bodies:
        logger.warning('no C-APDUs: the server will answer the first POST with 204...')

    targeted = format_aid(args.targeted_application) if args.targeted_application else None
    logger.info('mode=%s content-type=%s length-coding=%s targeted-application=%s',
                args.mode, content_type, args.length_coding, targeted or '(none)')

    ssl_ctx = make_ssl_context(h2b(args.psk), args.psk_identity,
                               ciphers=args.ciphers,
                               min_tls=args.min_tls, max_tls=args.max_tls,
                               seclevel=args.seclevel,
                               identity_hint=args.psk_identity_hint,
                               allow_any_identity=args.allow_any_identity)

    server = Scp81AdminServer(args.host, args.port, ssl_ctx, command_bodies,
                              next_uri=args.uri, targeted_application=targeted,
                              content_type=content_type)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info('shutting down')
        server.shutdown()


if __name__ == '__main__':
    main()
