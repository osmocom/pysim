#!/usr/bin/env python3
# Test script to verify the unified ES2+/ES9+ architecture.
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

import sys
import logging
import unittest
import importlib.util
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

def import_osmo_smdpp():
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

SmDppHttpServer = osmo_smdpp.SmDppHttpServer
Es2PlusProfileState = osmo_smdpp.Es2PlusProfileState


class UnifiedArchitectureTest(unittest.TestCase):
    """Test cases for unified ES2+/ES9+ architecture."""

    def setUp(self):
        """Set up test environment."""
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)

        self.server = SmDppHttpServer(
            server_hostname='test.example.com',
            ci_certs_path=str(project_root / 'smdpp-data/certs/CertificateIssuer'),
            common_cert_path=str(project_root / 'smdpp-data/certs'),
            use_brainpool=False,
            in_memory=True,
            test_mode=True
        )

    def test_server_initialization(self):
        """Test that server initializes correctly in test mode."""
        self.assertIsNotNone(self.server)
        self.assertTrue(self.server.test_mode)
        self.assertIsNotNone(self.server.profile_store)

    def test_static_profiles_loaded(self):
        """Test that static test profiles are loaded."""
        self.assertGreater(len(self.server.activation_code_profiles), 0,
                          "No static test profiles loaded")

    def test_es2plus_profile_creation(self):
        """Test creating and storing ES2+ profiles."""
        test_matching_id = 'TEST123'
        test_iccid = '8900000000000099999F'

        es2_profile = Es2PlusProfileState(test_iccid, 'Test', 'TestOperator')
        es2_profile.matching_id = test_matching_id
        es2_profile.state = 'released'
        self.server.profile_store[test_iccid] = es2_profile

        self.assertIn(test_iccid, self.server.profile_store)
        stored_profile = self.server.profile_store[test_iccid]
        self.assertEqual(stored_profile.matching_id, test_matching_id)
        self.assertEqual(stored_profile.state, 'released')

    def test_es2plus_profile_lookup_by_matching_id(self):
        """Test looking up ES2+ profiles by matching ID."""
        test_matching_id = 'TEST_LOOKUP_001'
        test_iccid = '8900000000000088888F'

        profile = Es2PlusProfileState(test_iccid, 'Test', 'TestOperator')
        profile.matching_id = test_matching_id
        profile.state = 'confirmed'
        self.server.profile_store[test_iccid] = profile

        found_profile = self.server.profile_store.find_by_matching_id(test_matching_id)
        self.assertIsNotNone(found_profile, "Profile not found by matching ID")
        self.assertEqual(found_profile.iccid, test_iccid)
        self.assertEqual(found_profile.matching_id, test_matching_id)

    def test_profile_state_validation(self):
        """Test that profile states are properly validated."""
        # Test valid states
        valid_states = ['released', 'confirmed']
        for state in valid_states:
            with self.subTest(state=state):
                iccid = f'89000000000000{state[:5].upper()}F'
                profile = Es2PlusProfileState(iccid, 'Test', 'TestOp')
                profile.matching_id = f'TEST_{state.upper()}'
                profile.state = state
                self.server.profile_store[iccid] = profile

                found = self.server.profile_store.find_by_matching_id(profile.matching_id)
                self.assertIsNotNone(found)
                self.assertEqual(found.state, state)

        # Test invalid state (should still be stored but not ready for download)
        invalid_state = 'allocated'
        iccid = '8900000000000077777F'
        profile = Es2PlusProfileState(iccid, 'Test', 'TestOp')
        profile.matching_id = 'TEST_INVALID_STATE'
        profile.state = invalid_state
        self.server.profile_store[iccid] = profile

        found = self.server.profile_store.find_by_matching_id('TEST_INVALID_STATE')
        self.assertIsNotNone(found)
        self.assertEqual(found.state, invalid_state)

    def test_es2plus_takes_precedence_over_static(self):
        """Test that ES2+ profiles take precedence over static profiles."""
        # Find a matching ID that exists in static profiles
        if not self.server.activation_code_profiles:
            self.skipTest("No static profiles available for precedence test")

        static_matching_id = next(iter(self.server.activation_code_profiles.keys()))
        static_iccid = self.server.activation_code_profiles[static_matching_id]['iccid']

        # Create ES2+ profile with same matching ID but different ICCID
        es2_iccid = '8900000000000099999F'
        es2_profile = Es2PlusProfileState(es2_iccid, 'Test', 'TestOperator')
        es2_profile.matching_id = static_matching_id
        es2_profile.state = 'released'
        self.server.profile_store[es2_iccid] = es2_profile

        # Verify ES2+ profile is found (takes precedence)
        found_profile = self.server.profile_store.find_by_matching_id(static_matching_id)
        self.assertIsNotNone(found_profile)
        self.assertEqual(found_profile.iccid, es2_iccid,
                        "ES2+ profile should take precedence over static profile")
        self.assertNotEqual(found_profile.iccid, static_iccid,
                           "Should return ES2+ ICCID, not static ICCID")

    def test_multiple_profiles_coexistence(self):
        """Test that multiple ES2+ profiles can coexist with different states."""
        profiles_data = [
            ('8900000000000011111F', 'TEST_MULTI_1', 'released'),
            ('8900000000000022222F', 'TEST_MULTI_2', 'confirmed'),
            ('8900000000000033333F', 'TEST_MULTI_3', 'allocated'),
        ]

        # Create and store multiple profiles
        for iccid, matching_id, state in profiles_data:
            profile = Es2PlusProfileState(iccid, 'Test', 'TestOperator')
            profile.matching_id = matching_id
            profile.state = state
            self.server.profile_store[iccid] = profile

        # Verify all profiles can be found by their matching IDs
        for iccid, matching_id, state in profiles_data:
            with self.subTest(matching_id=matching_id):
                found = self.server.profile_store.find_by_matching_id(matching_id)
                self.assertIsNotNone(found)
                self.assertEqual(found.iccid, iccid)
                self.assertEqual(found.state, state)

    def tearDown(self):
        """Clean up after tests."""
        if hasattr(self, 'server') and self.server:
            # Close profile store if it has a close method
            if hasattr(self.server.profile_store, 'close'):
                self.server.profile_store.close()


if __name__ == '__main__':
    unittest.main()