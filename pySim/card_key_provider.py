# coding=utf-8
"""Obtaining card parameters (mostly key data) from external source.

This module contains a base class and a concrete implementation of
obtaining card key material (or other card-individual parameters) from
an external data source.

This is used e.g. to keep PIN/PUK data in some file on disk, avoiding
the need of manually entering the related card-individual data on every
operation with pySim-shell.
"""

# (C) 2021-2024 by Sysmocom s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier, Harald Welte
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

from typing import List, Dict, Optional
from Cryptodome.Cipher import AES
from osmocom.utils import h2b, b2h

import abc
import csv

card_key_providers = []  # type: List['CardKeyProvider']

# well-known groups of columns relate to a given functionality.  This avoids having
# to specify the same transport key N number of times, if the same key is used for multiple
# fields of one group, like KIC+KID+KID of one SD.
CRYPT_GROUPS = {
    'UICC_SCP02': ['UICC_SCP02_KIC1', 'UICC_SCP02_KID1', 'UICC_SCP02_KIK1'],
    'UICC_SCP03': ['UICC_SCP03_KIC1', 'UICC_SCP03_KID1', 'UICC_SCP03_KIK1'],
    'SCP03_ISDR': ['SCP03_ENC_ISDR', 'SCP03_MAC_ISDR', 'SCP03_DEK_ISDR'],
    'SCP03_ISDA': ['SCP03_ENC_ISDR', 'SCP03_MAC_ISDA', 'SCP03_DEK_ISDA'],
    'SCP03_ECASD': ['SCP03_ENC_ECASD', 'SCP03_MAC_ECASD', 'SCP03_DEK_ECASD'],
    }

class CardKeyProvider(abc.ABC):
    """Base class, not containing any concrete implementation."""

    VALID_KEY_FIELD_NAMES = ['ICCID', 'EID', 'IMSI' ]

    # check input parameters, but do nothing concrete yet
    def _verify_get_data(self, fields: List[str] = [], key: str = 'ICCID', value: str = "") -> Dict[str, str]:
        """Verify multiple fields for identified card.

        Args:
                fields : list of valid field names such as 'ADM1', 'PIN1', ... which are to be obtained
                key : look-up key to identify card data, such as 'ICCID'
                value : value for look-up key to identify card data
        Returns:
                dictionary of {field, value} strings for each requested field from 'fields'
        """

        if key not in self.VALID_KEY_FIELD_NAMES:
            raise ValueError("Key field name '%s' is not a valid field name, valid field names are: %s" %
                             (key, str(self.VALID_KEY_FIELD_NAMES)))

        return {}

    def get_field(self, field: str, key: str = 'ICCID', value: str = "") -> Optional[str]:
        """get a single field from CSV file using a specified key/value pair"""
        fields = [field]
        result = self.get(fields, key, value)
        return result.get(field)

    @abc.abstractmethod
    def get(self, fields: List[str], key: str, value: str) -> Dict[str, str]:
        """Get multiple card-individual fields for identified card.

        Args:
                fields : list of valid field names such as 'ADM1', 'PIN1', ... which are to be obtained
                key : look-up key to identify card data, such as 'ICCID'
                value : value for look-up key to identify card data
        Returns:
                dictionary of {field, value} strings for each requested field from 'fields'
        """


class CardKeyProviderCsv(CardKeyProvider):
    """Card key provider implementation that allows to query against a specified CSV file.
    Supports column-based encryption as it is generally a bad idea to store cryptographic key material in
    plaintext.  Instead, the key material should be encrypted by a "key-encryption key", occasionally also
    known as "transport key" (see GSMA FS.28)."""
    IV = b'\x23' * 16
    csv_file = None
    filename = None

    def __init__(self, filename: str, transport_keys: dict):
        """
        Args:
                filename : file name (path) of CSV file containing card-individual key/data
                transport_keys : a dict indexed by field name, whose values are hex-encoded AES keys for the
                                 respective field (column) of the CSV.  This is done so that different fields
                                 (columns) can use different transport keys, which is strongly recommended by
                                 GSMA FS.28
        """
        self.csv_file = open(filename, 'r')
        if not self.csv_file:
            raise RuntimeError("Could not open CSV file '%s'" % filename)
        self.filename = filename
        self.transport_keys = self.process_transport_keys(transport_keys)

    @staticmethod
    def process_transport_keys(transport_keys: dict):
        """Apply a single transport key to multiple fields/columns, if the name is a group."""
        new_dict = {}
        for name, key in transport_keys.items():
            if name in CRYPT_GROUPS:
                for field in CRYPT_GROUPS[name]:
                    new_dict[field] = key
            else:
                new_dict[name] = key
        return new_dict

    def _decrypt_field(self, field_name: str, encrypted_val: str) -> str:
        """decrypt a single field, if we have a transport key for the field of that name."""
        if not field_name in self.transport_keys:
            return encrypted_val
        cipher = AES.new(h2b(self.transport_keys[field_name]), AES.MODE_CBC, self.IV)
        return b2h(cipher.decrypt(h2b(encrypted_val)))

    def get(self, fields: List[str], key: str, value: str) -> Dict[str, str]:
        super()._verify_get_data(fields, key, value)

        self.csv_file.seek(0)
        cr = csv.DictReader(self.csv_file)
        if not cr:
            raise RuntimeError(
                "Could not open DictReader for CSV-File '%s'" % self.filename)
        cr.fieldnames = [field.upper() for field in cr.fieldnames]

        rc = {}
        for row in cr:
            if row[key] == value:
                for f in fields:
                    if f in row:
                        rc.update({f: self._decrypt_field(f, row[f])})
                    else:
                        raise RuntimeError("CSV-File '%s' lacks column '%s'" %
                                           (self.filename, f))
        return rc


def card_key_provider_register(provider: CardKeyProvider, provider_list=card_key_providers):
    """Register a new card key provider.

    Args:
            provider : the to-be-registered provider
            provider_list : override the list of providers from the global default
    """
    if not isinstance(provider, CardKeyProvider):
        raise ValueError("provider is not a card data provier")
    provider_list.append(provider)


def card_key_provider_get(fields, key: str, value: str, provider_list=card_key_providers) -> Dict[str, str]:
    """Query all registered card data providers for card-individual [key] data.

    Args:
            fields : list of valid field names such as 'ADM1', 'PIN1', ... which are to be obtained
            key : look-up key to identify card data, such as 'ICCID'
            value : value for look-up key to identify card data
            provider_list : override the list of providers from the global default
    Returns:
            dictionary of {field, value} strings for each requested field from 'fields'
    """
    for p in provider_list:
        if not isinstance(p, CardKeyProvider):
            raise ValueError(
                "provider list contains element which is not a card data provier")
        result = p.get(fields, key, value)
        if result:
            return result
    return {}


def card_key_provider_get_field(field: str, key: str, value: str, provider_list=card_key_providers) -> Optional[str]:
    """Query all registered card data providers for a single field.

    Args:
            field : name valid field such as 'ADM1', 'PIN1', ... which is to be obtained
            key : look-up key to identify card data, such as 'ICCID'
            value : value for look-up key to identify card data
            provider_list : override the list of providers from the global default
    Returns:
            dictionary of {field, value} strings for the requested field
    """
    for p in provider_list:
        if not isinstance(p, CardKeyProvider):
            raise ValueError(
                "provider list contains element which is not a card data provier")
        result = p.get_field(field, key, value)
        if result:
            return result
    return None
