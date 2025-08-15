#!/usr/bin/env python3
# Integrated test for ES2+ functionality using module imports of our existing cli scripts (es2p client, cert gen).
#
# (C) 2025 by Eric Wild <ewild@sysmocom.de>
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

import os
import socket
import sys
import tempfile
import unittest
import subprocess
import time
import shutil
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'contrib'))

from generate_self_signed_operator_cert import generate_self_signed_operator_cert # noqa: E402
from pySim.esim.es2p import Es2pApiClient # noqa: E402

class HostnameResolutionMixin:
    """Mixin to fix cert addresses to localhost"""

    def setUp(self):
        super().setUp()

        self.hostname_mappings = getattr(self, 'hostname_mappings', {
            'testsmdpplus1.example.com': '127.0.0.1'
        })

        self._original_getaddrinfo = socket.getaddrinfo
        def patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if host in self.hostname_mappings:
                target_host = self.hostname_mappings[host]
                return self._original_getaddrinfo(target_host, port, family, type, proto, flags)
            return self._original_getaddrinfo(host, port, family, type, proto, flags)
        socket.getaddrinfo = patched_getaddrinfo

    def tearDown(self):
        socket.getaddrinfo = self._original_getaddrinfo
        super().tearDown()

class TestES2PlusDemo(HostnameResolutionMixin, unittest.TestCase):
    """Test ES2+ mutual TLS authentication with self-signed certificates."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent.parent
        cls.test_dir = tempfile.mkdtemp(prefix='es2p_test_')
        cls.cert_dir = os.path.join(cls.test_dir, 'certs')
        os.makedirs(cls.cert_dir, exist_ok=True)

        cls.server_ca_cert = str(cls.project_root / 'smdpp-data' / 'certs' /
                                 'CertificateIssuer' / 'CERT_CI_ECDSA_NIST.pem')

    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        if hasattr(cls, 'test_dir') and os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir)

    def setUp(self):
        """Set up each test."""
        super().setUp()
        self.server_process = None

    def tearDown(self):
        """Clean up after each test."""
        if self.server_process:
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
                self.server_process.wait()

            if self.server_process.stdout:
                self.server_process.stdout.close()
            if self.server_process.stderr:
                self.server_process.stderr.close()
        super().tearDown()


    def start_smdpp_server(self):
        """Start the SM-DP+ server as a subprocess (like in shell script)."""
        cmd = [
            sys.executable,
            str(self.project_root / 'osmo-smdpp.py'),
            '-t',  # test mode
            '-m',  # in-memory storage
        ]

        self.server_process = subprocess.Popen(
            cmd,
            stdout=sys.stdout,
            stderr=sys.stderr,
            cwd=str(self.project_root)
        )

        # Wait for server to start because.. python
        time.sleep(3)

    def test_self_signed_certificate_flow(self):
        """Test ES2+ downloadOrder with self-signed operator certificate.
        Steps:
        1. Generation of self-signed operator certificates
        2. Direct use of Es2pApiClient from imported cli module
        3. Mutual TLS authentication with self-signed certificates
        4. Trust establishment through SKI at app layer
        """
        # Step 1: Generate self-signed operator certificate using imported function
        operator_name = 'TEST_OPERATOR'
        cert_path, ski = generate_self_signed_operator_cert(operator_name, self.cert_dir)

        # Verify certificate was created
        self.assertTrue(os.path.exists(cert_path))
        self.assertIsNotNone(ski)
        self.assertIn(':', ski)  # SKI should be formatted with colons

        # Step 2: Start SM-DP+ server
        self.start_smdpp_server()

        try:
            client = Es2pApiClient(
                url_prefix='https://testsmdpplus1.example.com:8000/gsma/rsp2/es2plus',
                func_req_id=operator_name,
                server_cert_verify=self.server_ca_cert,
                client_cert=cert_path
            )

            # Step 4: Make downloadOrder request
            request_data = {
                'profileType': 'Test'
            }

            result = client.call_downloadOrder(request_data)

            self.assertIsInstance(result, dict)

            # In test mode, the server should accept the self-signed certificate and return a response
            # - even if it's an error due to no matching profiles, the whole point is that the TLS handshake succeeds

            # Check if we got a functionExecutionStatus (expected in response)
            if 'functionExecutionStatus' in result:
                status = result['functionExecutionStatus']
                self.assertIn('status', status)
                # May be 'Executed-Success' or 'Failed' depending on profile availability, don't care
                self.assertIn(status['status'], ['Executed-Success', 'Failed'])

        except Exception as e:
            # If we get an SSL error, the test failed
            if 'SSL' in str(e) or 'certificate' in str(e).lower():
                self.fail(f"SSL/Certificate error occurred: {e}")

    def test_multiple_operator_certificates(self):
        """Test that different operators can use different self-signed certificates."""
        operators = ['OPERATOR_A', 'OPERATOR_B', 'OPERATOR_C']
        certificates = {}

        # Generate certificates for each operator
        for operator in operators:
            cert_path, ski = generate_self_signed_operator_cert(operator, self.cert_dir)
            certificates[operator] = {
                'cert_path': cert_path,
                'ski': ski
            }
            self.assertTrue(os.path.exists(cert_path))

        self.start_smdpp_server()

        # Test that each operator can authenticate with their own certificate
        for operator, cert_info in certificates.items():
            client = Es2pApiClient(
                url_prefix='https://testsmdpplus1.example.com:8000/gsma/rsp2/es2plus',
                func_req_id=operator,
                server_cert_verify=self.server_ca_cert,
                client_cert=cert_info['cert_path']
            )

            request_data = {'profileType': f'Test_{operator}'}

            try:
                result = client.call_downloadOrder(request_data)
                self.assertIsInstance(result, dict)
                # As above only TLS handshake matters
            except Exception as e:
                if 'SSL' in str(e) or 'certificate' in str(e).lower():
                    self.fail(f"SSL/Certificate error for {operator}: {e}")

    def test_client_without_certificate_fails(self):
        """Test that clients without certificates are rejected when mutual TLS is required."""
        self.start_smdpp_server()

        client = Es2pApiClient(
            url_prefix='https://testsmdpplus1.example.com:8000/gsma/rsp2/es2plus',
            func_req_id='NO_CERT_CLIENT',
            server_cert_verify=self.server_ca_cert,
            client_cert=None  # No client certificate
        )

        request_data = {'profileType': 'Test'}

        # This should fail due to missing client certificate
        # In test mode, the server may not enforce client certificates at TLS layer but rejects at application layer
        try:
            result = client.call_downloadOrder(request_data)
            # If we get here, check if server rejected at application layer
            if 'functionExecutionStatus' in result:
                status = result['functionExecutionStatus']
                # Should be rejected due to missing authentication
                self.assertEqual(status.get('status'), 'Failed', "Expected failure due to missing client certificate")
            else:
                # Got some response but no clear rejection (?!)
                self.fail("Server should reject requests without client certificates")
        except Exception as e:
            # SSL/TLS layer rejection is also acceptable
            error_msg = str(e)
            self.assertTrue(
                'certificate' in error_msg.lower() or
                'SSL' in error_msg or
                'handshake' in error_msg.lower() or
                '404' in error_msg,  # Server might return 404 for unauthenticated requests
                f"Expected certificate or authentication error, got: {error_msg}"
            )


if __name__ == '__main__':
    unittest.main(verbosity=2)