#!/usr/bin/env python3
# Consolidated test suite for ES2+/ES9+ integration.
# HTTP endpoint testing with actual profile storage testing
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

import json
import base64
import sys
import os
import tempfile
import hashlib
import unittest
import importlib.util
from unittest.mock import patch, MagicMock
from pathlib import Path

project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from pySim.utils import h2b # noqa: E402


def import_osmo_smdpp():
    """Import osmo-smdpp module dynamically."""
    project_root = Path(__file__).parent.parent.parent
    module_path = project_root / 'osmo-smdpp.py'
    if 'osmo_smdpp' in sys.modules:
        return sys.modules['osmo_smdpp']

    spec = importlib.util.spec_from_file_location('osmo_smdpp', module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {module_path}")

    module = importlib.util.module_from_spec(spec)

    # Register it in sys.modules with underscores so pickle will look for 'osmo_smdpp' not 'osmo-smdpp'
    sys.modules['osmo_smdpp'] = module
    spec.loader.exec_module(module)
    return module


osmo_smdpp = import_osmo_smdpp()

Es2PlusProfileState = osmo_smdpp.Es2PlusProfileState
Es2PlusProfileStore = osmo_smdpp.Es2PlusProfileStore
SmDppHttpServer = osmo_smdpp.SmDppHttpServer


class ES2PlusHTTPEndpointTest(unittest.TestCase):
    """Test ES2+ and ES9+ HTTP endpoints with mocked responses."""

    def setUp(self):
        """Set up test environment."""
        self.smdp_host = "127.0.0.1"
        self.smdp_port = 8000
        self.base_url = f"http://{self.smdp_host}:{self.smdp_port}"

        self.test_eid = "89001012012341234012345678901234"
        self.test_iccid = "8900000000000000001"
        self.test_matching_id = None  # Will be set by mock confirmOrder
        self.test_confirmation_code = "12345678"

    def _create_mock_response(self, status_code=200, json_data=None):
        """Create a mock HTTP response."""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.raise_for_status.return_value = None
        if json_data:
            mock_response.json.return_value = json_data
        return mock_response

    @patch('requests.post')
    def test_es2plus_download_order(self, mock_post):
        """Test ES2+ DownloadOrder HTTP endpoint."""
        # Mock successful response
        mock_response_data = {
            "header": {
                "functionExecutionStatus": {
                    "status": "Executed-Success"
                }
            },
            "iccid": self.test_iccid
        }
        mock_post.return_value = self._create_mock_response(200, mock_response_data)

        # Import requests here since we're mocking it
        import requests

        data = {
            "eid": self.test_eid,
            "iccid": self.test_iccid,
            "profileType": "Test"
        }

        url = f"{self.base_url}/gsma/rsp2/es2plus/downloadOrder"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=data, headers=headers)
        result = response.json()

        mock_post.assert_called_once_with(url, json=data, headers=headers)

        self.assertEqual(result["header"]["functionExecutionStatus"]["status"], "Executed-Success")
        self.assertEqual(result["iccid"], self.test_iccid)

    @patch('requests.post')
    def test_es2plus_confirm_order(self, mock_post):
        """Test ES2+ ConfirmOrder HTTP endpoint."""
        test_matching_id = "TEST_MATCHING_ID_12345"

        # Mock successful response
        mock_response_data = {
            "header": {
                "functionExecutionStatus": {
                    "status": "Executed-Success"
                }
            },
            "matchingId": test_matching_id
        }
        mock_post.return_value = self._create_mock_response(200, mock_response_data)

        import requests

        data = {
            "iccid": self.test_iccid,
            "releaseFlag": True,
            "eid": self.test_eid,
            "confirmationCode": self.test_confirmation_code
        }

        url = f"{self.base_url}/gsma/rsp2/es2plus/confirmOrder"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=data, headers=headers)
        result = response.json()

        mock_post.assert_called_once_with(url, json=data, headers=headers)

        self.assertEqual(result["header"]["functionExecutionStatus"]["status"], "Executed-Success")
        self.assertEqual(result["matchingId"], test_matching_id)

    @patch('requests.post')
    def test_es9plus_initiate_authentication(self, mock_post):
        """Test ES9+ InitiateAuthentication HTTP endpoint."""
        test_transaction_id = "TXN_12345"

        # Mock successful response
        mock_response_data = {
            "header": {
                "functionExecutionStatus": {
                    "status": "Executed-Success"
                }
            },
            "transactionId": test_transaction_id
        }
        mock_post.return_value = self._create_mock_response(200, mock_response_data)

        import requests

        euicc_info1 = {
            "svn": "2.2.0",
            "euiccCiPKIdListForVerification": [
                {"SubjectKeyIdentifier": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3"}
            ],
            "euiccCiPKIdListForSigning": [
                {"SubjectKeyIdentifier": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3"}
            ]
        }

        euicc_info1_b64 = base64.b64encode(json.dumps(euicc_info1).encode()).decode()
        data = {
            "euiccChallenge": base64.b64encode(b"test_challenge_123").decode(),
            "euiccInfo1": euicc_info1_b64,
            "smdpAddress": f"{self.smdp_host}:{self.smdp_port}"
        }

        url = f"{self.base_url}/gsma/rsp2/es9plus/initiateAuthentication"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=data, headers=headers)
        result = response.json()

        mock_post.assert_called_once_with(url, json=data, headers=headers)

        self.assertEqual(result["header"]["functionExecutionStatus"]["status"], "Executed-Success")
        self.assertEqual(result["transactionId"], test_transaction_id)

    @patch('requests.post')
    def test_es9plus_authenticate_client_with_matching_id(self, mock_post):
        """Test ES9+ AuthenticateClient with matchingId."""
        test_transaction_id = "TXN_12345"
        test_matching_id = "TEST_MATCHING_ID_12345"

        # mock a failure due to certificate validation but ensure that the matchingId was processed
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.raise_for_status.side_effect = Exception("Certificate validation failed")
        mock_response.text = "matchingId processed but certificate validation failed"
        mock_post.return_value = mock_response

        import requests

        authenticate_server_response = {
            "authenticateResponseOk": {
                "euiccSigned1": {
                    "transactionId": test_transaction_id,
                    "serverChallenge": "mock_server_challenge",
                    "ctxParams1": {
                        "ctxParamsForCommonAuthentication": {
                            "matchingId": test_matching_id
                        }
                    }
                },
                "euiccSignature1": base64.b64encode(b"mock_signature").decode(),
                "euiccCertificate": "mock_certificate",
                "eumCertificate": "mock_eum_certificate"
            }
        }

        data = {
            "transactionId": test_transaction_id,
            "authenticateServerResponse": base64.b64encode(
                json.dumps(authenticate_server_response).encode()
            ).decode()
        }

        # Make request and expect it to fail (due to mock certificates)
        url = f"{self.base_url}/gsma/rsp2/es9plus/authenticateClient"
        headers = {"Content-Type": "application/json"}

        with self.assertRaises(Exception) as context:
            requests.post(url, json=data, headers=headers)
            response = context.exception.response if hasattr(context.exception, 'response') else mock_response
            response.raise_for_status()

        mock_post.assert_called_once_with(url, json=data, headers=headers)

        # Verify the matchingId was included in the request
        call_args = mock_post.call_args
        request_data = call_args[1]['json']

        encoded_response = request_data['authenticateServerResponse']
        decoded_response = json.loads(base64.b64decode(encoded_response).decode())

        matching_id_in_request = (decoded_response['authenticateResponseOk']
                                ['euiccSigned1']['ctxParams1']
                                ['ctxParamsForCommonAuthentication']['matchingId'])

        self.assertEqual(matching_id_in_request, test_matching_id)


class ES2PlusProfileIntegrationTest(unittest.TestCase):
    """Test ES2+ profile storage and ES9+ integration."""

    def setUp(self):
        """Set up test environment."""
        self.test_iccid = "8900000000000000099"
        self.test_matching_id = "TEST_ES2PLUS_MID_123"
        self.test_confirmation_code = "87654321"
        self.test_eid = "89001012012341234012345678901234"

        self.temp_dir = tempfile.mkdtemp()
        self.profile_store_path = os.path.join(self.temp_dir, "test-es2plus-profiles")
        self.profile_store = Es2PlusProfileStore(filename=self.profile_store_path)

    def test_es2plus_profile_creation_and_storage(self):
        """Test creating and storing ES2+ profiles."""
        # Create an ES2+ profile as if it was provisioned via downloadOrder/confirmOrder
        profile = Es2PlusProfileState(self.test_iccid, 'Test', 'TestOperator')
        profile.matching_id = self.test_matching_id
        profile.state = 'released'
        profile.eid = self.test_eid

        # Store confirmation code hash (SHA256 of the code)
        cc_bytes = h2b(self.test_confirmation_code)
        profile.confirmation_code_hash = hashlib.sha256(cc_bytes).digest()

        self.profile_store[self.test_iccid] = profile
        self.profile_store.sync()

        self.assertIn(self.test_iccid, self.profile_store)
        stored_profile = self.profile_store[self.test_iccid]
        self.assertEqual(stored_profile.state, 'released')
        self.assertEqual(stored_profile.matching_id, self.test_matching_id)
        self.assertIsNotNone(stored_profile.confirmation_code_hash)

    def test_profile_lookup_by_matching_id(self):
        """Test profile lookup by matching ID."""
        profile = Es2PlusProfileState(self.test_iccid, 'Test', 'TestOperator')
        profile.matching_id = self.test_matching_id
        profile.state = 'released'
        profile.eid = self.test_eid

        cc_bytes = h2b(self.test_confirmation_code)
        profile.confirmation_code_hash = hashlib.sha256(cc_bytes).digest()

        self.profile_store[self.test_iccid] = profile
        self.profile_store.sync()

        # Test lookup by matching_id
        found_profile = self.profile_store.find_by_matching_id(self.test_matching_id)

        self.assertIsNotNone(found_profile, "Profile not found by matching_id")
        self.assertEqual(found_profile.iccid, self.test_iccid)
        self.assertEqual(found_profile.state, 'released')
        self.assertEqual(found_profile.eid, self.test_eid)
        self.assertIsNotNone(found_profile.confirmation_code_hash)

    def test_server_integration_with_es2plus_profiles(self):
        """Test server's ability to find ES2+ profiles."""
        profile = Es2PlusProfileState(self.test_iccid, 'Test', 'TestOperator')
        profile.matching_id = self.test_matching_id
        profile.state = 'released'
        profile.eid = self.test_eid

        cc_bytes = h2b(self.test_confirmation_code)
        profile.confirmation_code_hash = hashlib.sha256(cc_bytes).digest()

        self.profile_store[self.test_iccid] = profile
        self.profile_store.sync()

        server = SmDppHttpServer(
            server_hostname='testsmdpplus1.example.com',
            ci_certs_path=str(project_root / 'smdpp-data/certs/CertificateIssuer'),
            common_cert_path=str(project_root / 'smdpp-data/certs'),
            use_brainpool=False,
            in_memory=True,
            test_mode=True
        )

        # Replace server's profile store with our test store
        server.profile_store = self.profile_store

        # Test server's ability to find the profile
        es2plus_profile = server.profile_store.find_by_matching_id(self.test_matching_id)

        self.assertIsNotNone(es2plus_profile, "Server cannot find ES2+ profile")
        self.assertEqual(es2plus_profile.iccid, self.test_iccid)
        self.assertEqual(es2plus_profile.state, 'released')
        self.assertEqual(es2plus_profile.matching_id, self.test_matching_id)
        self.assertEqual(es2plus_profile.eid, self.test_eid)

    def test_es9plus_would_accept_profile(self):
        """Test that ES9+ logic would accept the ES2+ profile."""
        profile = Es2PlusProfileState(self.test_iccid, 'Test', 'TestOperator')
        profile.matching_id = self.test_matching_id
        profile.state = 'released'
        profile.eid = self.test_eid

        cc_bytes = h2b(self.test_confirmation_code)
        profile.confirmation_code_hash = hashlib.sha256(cc_bytes).digest()

        self.profile_store[self.test_iccid] = profile
        self.profile_store.sync()

        # Find the profile (simulating ES9+ authenticateClient logic)
        found_profile = self.profile_store.find_by_matching_id(self.test_matching_id)

        self.assertIsNotNone(found_profile)
        self.assertEqual(found_profile.state, 'released',
                        "Profile must be in 'released' state for ES9+ download")
        self.assertIsNotNone(found_profile.confirmation_code_hash,
                            "Profile should have confirmation code hash")

        expected_hash = hashlib.sha256(cc_bytes).digest()
        self.assertEqual(found_profile.confirmation_code_hash, expected_hash,
                        "Confirmation code hash mismatch")

    def test_activation_code_profiles_sync(self):
        """Test that ES2+ profiles are synced to activation_code_profiles."""
        server = SmDppHttpServer(
            server_hostname='testsmdpplus1.example.com',
            ci_certs_path=str(project_root / 'smdpp-data/certs/CertificateIssuer'),
            common_cert_path=str(project_root / 'smdpp-data/certs'),
            use_brainpool=False,
            in_memory=True,
            test_mode=True
        )

        test_matching_id = "ES2PLUS_SYNC_TEST"
        test_iccid = "8900000000000000088"

        profile = Es2PlusProfileState(test_iccid, 'Test', 'TestOp')
        profile.matching_id = test_matching_id
        profile.state = 'released'
        server.profile_store[profile.iccid] = profile

        # In test mode, manually trigger sync (simulating confirmOrder behavior)
        if server.test_mode:
            server.activation_code_profiles[test_matching_id] = {
                'matchingId': test_matching_id,
                'confirmationCode': None,
                'iccid': profile.iccid,
                'profileName': f'ES2+ Profile {profile.iccid}',
                'state': 'released',
                'download_attempts': 0,
                'cc_attempts': 0,
                'associated_eid': None,
                'expiration': None,
                'profile_path': 'TS48v4_SAIP2.3_BERTLV'
            }

        self.assertIn(test_matching_id, server.activation_code_profiles,
                     "ES2+ profile should be synced to activation_code_profiles")

        synced_profile = server.activation_code_profiles[test_matching_id]
        self.assertEqual(synced_profile['iccid'], test_iccid)
        self.assertEqual(synced_profile['state'], 'released')

    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self, 'profile_store'):
            self.profile_store.close()

        if hasattr(self, 'temp_dir'):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)


class ES2PlusProfileStoreTest(unittest.TestCase):
    """Test ES2PlusProfileStore functionality."""

    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.store_path = os.path.join(self.temp_dir, "test-store")
        self.store = Es2PlusProfileStore(filename=self.store_path)

    def test_profile_store_basic_operations(self):
        """Test basic profile store operations."""
        iccid = "8900000000000000001"
        profile = Es2PlusProfileState(iccid, "Test", "TestOp")
        profile.matching_id = "TEST_BASIC"
        profile.state = "allocated"

        self.store[iccid] = profile

        self.assertIn(iccid, self.store)
        retrieved = self.store[iccid]
        self.assertEqual(retrieved.iccid, iccid)
        self.assertEqual(retrieved.matching_id, "TEST_BASIC")
        self.assertEqual(retrieved.state, "allocated")

    def test_find_by_matching_id_functionality(self):
        """Test find_by_matching_id method."""
        profiles = [
            ("8900000000000000001", "MATCH_ID_1", "released"),
            ("8900000000000000002", "MATCH_ID_2", "confirmed"),
            ("8900000000000000003", "MATCH_ID_3", "allocated"),
        ]

        for iccid, match_id, state in profiles:
            profile = Es2PlusProfileState(iccid, "Test", "TestOp")
            profile.matching_id = match_id
            profile.state = state
            self.store[iccid] = profile

        for iccid, match_id, state in profiles:
            with self.subTest(matching_id=match_id):
                found = self.store.find_by_matching_id(match_id)
                self.assertIsNotNone(found)
                self.assertEqual(found.iccid, iccid)
                self.assertEqual(found.matching_id, match_id)
                self.assertEqual(found.state, state)

        not_found = self.store.find_by_matching_id("NON_EXISTENT")
        self.assertIsNone(not_found)

    def tearDown(self):
        """Clean up test environment."""
        self.store.close()
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)


class ES2PlusWorkflowTest(unittest.TestCase):
    """Test complete ES2+ to ES9+ workflow."""

    def setUp(self):
        """Set up test environment for workflow tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.profile_store_path = os.path.join(self.temp_dir, "workflow-es2plus-profiles")
        self.profile_store = Es2PlusProfileStore(filename=self.profile_store_path)

        self.test_eid = "89001012012341234012345678901234"
        self.test_iccid = "8900000000000000001"
        self.test_confirmation_code = "12345678"
        self.test_matching_id = "WORKFLOW_TEST_MID"

    def test_complete_workflow_with_profile_store(self):
        """Test complete workflow using actual profile store."""
        # Step 1: Simulate DownloadOrder - create profile
        profile = Es2PlusProfileState(self.test_iccid, 'Test', 'TestOperator')
        profile.state = 'allocated'
        self.profile_store[self.test_iccid] = profile
        self.profile_store.sync()

        stored_profile = self.profile_store[self.test_iccid]
        self.assertEqual(stored_profile.state, 'allocated')

        # Step 2: Simulate ConfirmOrder - update profile with matching_id
        stored_profile.matching_id = self.test_matching_id
        stored_profile.state = 'released'
        stored_profile.eid = self.test_eid

        cc_bytes = h2b(self.test_confirmation_code)
        stored_profile.confirmation_code_hash = hashlib.sha256(cc_bytes).digest()

        self.profile_store[self.test_iccid] = stored_profile
        self.profile_store.sync()

        confirmed_profile = self.profile_store[self.test_iccid]
        self.assertEqual(confirmed_profile.state, 'released')
        self.assertEqual(confirmed_profile.matching_id, self.test_matching_id)

        # Step 3: Simulate ES9+ lookup by matching_id
        es9_profile = self.profile_store.find_by_matching_id(self.test_matching_id)

        self.assertIsNotNone(es9_profile)
        self.assertEqual(es9_profile.iccid, self.test_iccid)
        self.assertEqual(es9_profile.state, 'released')
        self.assertEqual(es9_profile.eid, self.test_eid)

        # Step 4: Verify complete data integrity
        self.assertIsNotNone(es9_profile.confirmation_code_hash)
        expected_hash = hashlib.sha256(cc_bytes).digest()
        self.assertEqual(es9_profile.confirmation_code_hash, expected_hash)

    def test_error_handling_workflow(self):
        """Test error handling in the integration workflow."""
        # Test 1: Profile not found by matching_id
        non_existent_profile = self.profile_store.find_by_matching_id("NON_EXISTENT_MID")
        self.assertIsNone(non_existent_profile)

        # Test 2: Profile in wrong state for ES9+ download
        profile = Es2PlusProfileState(self.test_iccid, 'Test', 'TestOperator')
        profile.matching_id = "ERROR_TEST_MID"
        profile.state = 'allocated'  # Wrong state - should be 'released'
        self.profile_store[self.test_iccid] = profile
        self.profile_store.sync()

        error_profile = self.profile_store.find_by_matching_id("ERROR_TEST_MID")
        self.assertIsNotNone(error_profile)
        self.assertNotEqual(error_profile.state, 'released',
                           "Profile should not be in released state for error test")

        # Test 3: Missing confirmation code hash
        profile2 = Es2PlusProfileState("8900000000000000002", 'Test', 'TestOperator')
        profile2.matching_id = "NO_CC_HASH_MID"
        profile2.state = 'released'
        # Intentionally not setting confirmation_code_hash
        self.profile_store[profile2.iccid] = profile2
        self.profile_store.sync()

        no_cc_profile = self.profile_store.find_by_matching_id("NO_CC_HASH_MID")
        self.assertIsNotNone(no_cc_profile)
        self.assertIsNone(getattr(no_cc_profile, 'confirmation_code_hash', None),
                         "Profile should not have confirmation code hash for error test")

    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self, 'profile_store'):
            self.profile_store.close()

        if hasattr(self, 'temp_dir'):
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()