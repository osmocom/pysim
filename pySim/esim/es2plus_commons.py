#!/usr/bin/env python3
# Common validation and utility functions for ES2+ API endpoints.
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

import shelve
import logging
import time
from typing import Optional, Tuple
from .smdpp_common import ApiError

logger = logging.getLogger(__name__)

class Es2PlusProfileState:
    """Encapsulates the state of an ES2+ profile. Tracks profile lifecycle from available through installed."""
    def __init__(self, iccid: str, profile_type: str = 'Generic', owner: str = 'Unknown'):
        self.iccid = iccid
        self.profile_type = profile_type
        self.owner = owner
        self.state = 'available'  # available, allocated, linked, confirmed, released, downloaded, installed, unavailable
        self.eid: Optional[str] = None
        self.matching_id: Optional[str] = None
        self.confirmation_code_hash: Optional[bytes] = None
        self.sm_ds_address: Optional[str] = None
        self.download_attempts: int = 0
        self.created_timestamp = time.time()
        self.last_modified = time.time()

    def __getstate__(self):
        """Helper for pickling to persistent storage."""
        state = self.__dict__.copy()
        # All current attributes are pickle-able, but let's be prepared
        return state

    def __setstate__(self, state):
        """Helper for unpickling from persistent storage."""
        self.__dict__.update(state)

class Es2PlusProfileStore:
    """Database-backed storage for ES2+ profile states using shelve, similar to RspSessionStore."""

    def __init__(self, filename: Optional[str] = None, in_memory: bool = False):
        self._in_memory = in_memory

        if in_memory:
            self._shelf = shelve.Shelf(dict())
        else:
            if filename is None:
                raise ValueError("filename is required for file-based profile store")
            self._shelf = shelve.open(filename)

    # Dictionary-like interface
    def __getitem__(self, key):
        return self._shelf[key]

    def __setitem__(self, key, value):
        value.last_modified = time.time()
        self._shelf[key] = value

    def __delitem__(self, key):
        del self._shelf[key]

    def __contains__(self, key):
        return key in self._shelf

    def __iter__(self):
        return iter(self._shelf)

    def __len__(self):
        return len(self._shelf)

    # everything else
    def __getattr__(self, name):
        """Delegate attribute access to the underlying shelf object."""
        return getattr(self._shelf, name)

    def close(self):
        """Close the session store."""
        if hasattr(self._shelf, 'close'):
            self._shelf.close()
        if self._in_memory:
            # For in-memory store, clear the reference
            self._shelf = None

    def sync(self):
        """Synchronize the cache with the underlying storage."""
        if hasattr(self._shelf, 'sync'):
            self._shelf.sync()

    def find_by_matching_id(self, matching_id: str) -> Optional[Es2PlusProfileState]:
        """Find a profile by its matching ID."""
        for iccid, profile in self.items():
            if profile.matching_id == matching_id:
                return profile
        return None

    def find_available_by_type(self, profile_type: str, owner: str) -> Optional[Es2PlusProfileState]:
        """Find first available profile of given type for given owner."""
        for iccid, profile in self.items():
            if (profile.state == 'available' and
                profile.profile_type == profile_type and
                profile.owner == owner):
                return profile
        return None

class Es2PlusHelpers:
    """Common validation methods for ES2+ operations."""

    @staticmethod
    def normalize_and_validate_iccid(iccid: str, profile_store) -> Tuple[str, Es2PlusProfileState]:
        """
        Normalize ICCID and retrieve profile with validation.

        Returns:
            Tuple of (normalized_iccid, profile_object)
        Raises:
            ApiError if profile not found
        """
        # Normalize ICCID (remove F padding)
        iccid = iccid.rstrip('F')

        # Retrieve profile
        profile = profile_store.get(iccid)
        if not profile:
            # SGP.22 Table: Profile ICCID - Unknown
            raise ApiError('8.2.1', '3.9', 'Profile unknown', iccid)

        return iccid, profile

    @staticmethod
    def check_authorization(request, profile, iccid: str, test_mode: bool,
                           profile_store) -> str:
        """
        Check authorization and handle ownership assignment.

        Returns:
            authenticated_entity
        Raises:
            ApiError if not authorized
        """
        # Get authenticated entity from client certificate
        authenticated_entity = getattr(request, 'authenticated_entity', None)
        if not authenticated_entity:
            # Should not happen if es2plus_api_wrapper is working correctly but this is python, anything is NaN NaN Nan Batman.
            raise ApiError('8.2.1', '1.2', 'Not authorized - no authenticated entity', iccid)

        # For ES2+, profile ownership is based on the authenticated operator
        # In test mode, we're kinda flexible with ownership
        if test_mode:
            if profile.owner == 'S_MNO' or not profile.owner:
                profile.owner = authenticated_entity
                profile_store[iccid] = profile
                logger.info(f"Test mode: assigned profile {iccid} to {authenticated_entity}")
        else:
            # Less lenient in production, strictly check ownership
            if profile.owner != authenticated_entity:
                # SGP.22 Table: Profile ICCID - Not Allowed (Authorization)
                raise ApiError('8.2.1', '1.2', f'Not authorized - profile owned by {profile.owner}', iccid)

        return authenticated_entity

    @staticmethod
    def validate_eid_association(profile, eid: Optional[str], iccid: str):
        """
        Validate EID association with profile.

        Raises:
            ApiError if EID validation fails
        """
        if profile.eid:
            if not eid:
                # EID should be provided if associated
                raise ApiError('8.1.1', '2.2', 'EID required for this order')
            if eid != profile.eid:
                # SGP.22 Table: Profile ICCID - Invalid Association
                raise ApiError('8.2.1', '3.10', 'Different EID associated', iccid)

    @staticmethod
    def validate_matching_id_association(profile, matching_id: Optional[str]):
        """
        Validate matching ID association with profile.

        Raises:
            ApiError if matching ID validation fails
        """
        if profile.matching_id:
            if matching_id and matching_id != profile.matching_id:
                # SGP.22 Table: Matching ID - Invalid Association
                raise ApiError('8.2.6', '3.10', 'Different matchingID associated')

    @staticmethod
    def handle_sm_ds_event_deletion(profile, sm_ds_events):
        """Handle SM-DS Event Deletion if needed."""
        if profile.sm_ds_address and profile.matching_id:
            # would call ES12.DeleteEvent
            if profile.matching_id in sm_ds_events:
                del sm_ds_events[profile.matching_id]
                logger.info(f"Simulated SM-DS Event Deletion for matchingId: {profile.matching_id}")

    @staticmethod
    def handle_sm_ds_event_registration(profile, sm_ds_events, server_hostname):
        """Handle SM-DS Event Registration if needed."""
        import time

        if (profile.sm_ds_address and
            profile.matching_id and
            profile.matching_id not in sm_ds_events):
            # Simulate ES12.RegisterEvent for now
            sm_ds_events[profile.matching_id] = {
                'eid': profile.eid,
                'smdpAddress': server_hostname,
                'timestamp': time.time()
            }
            logger.info(f"Simulated SM-DS Event Registration for matchingId: {profile.matching_id}")

    @staticmethod
    def reset_profile_to_available(profile):
        """Reset profile to available state, clearing all associations."""
        profile.state = 'available'
        profile.eid = None
        profile.matching_id = None
        profile.confirmation_code_hash = None
        profile.sm_ds_address = None
        profile.download_attempts = 0