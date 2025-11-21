# coding=utf-8
"""Obtaining card parameters (mostly key data) from external source.

This module contains a base class and a concrete implementation of
obtaining card key material (or other card-individual parameters) from
an external data source.

This is used e.g. to keep PIN/PUK data in some file on disk, avoiding
the need of manually entering the related card-individual data on every
operation with pySim-shell.
"""

# (C) 2021-2025 by Sysmocom s.f.m.c. GmbH
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
from pySim.log import PySimLogger

import abc
import csv
import logging

log = PySimLogger.get("CARDKEY")

card_key_providers = []  # type: List['CardKeyProvider']

class CardKeyFieldCryptor:
    """
    A Card key field encryption class that may be used by Card key provider implementations to add support for
    a column-based encryption to protect sensitive material (cryptographic key material, ADM keys, etc.).
    The sensitive material is encrypted using a "key-encryption key", occasionally also known as "transport key"
    before it is stored into a file or database (see also GSMA FS.28). The "transport key" is then used to decrypt
    the key material on demand.
    """

    # well-known groups of columns relate to a given functionality.  This avoids having
    # to specify the same transport key N number of times, if the same key is used for multiple
    # fields of one group, like KIC+KID+KID of one SD.
    __CRYPT_GROUPS = {
            'UICC_SCP02': ['UICC_SCP02_KIC1', 'UICC_SCP02_KID1', 'UICC_SCP02_KIK1'],
            'UICC_SCP03': ['UICC_SCP03_KIC1', 'UICC_SCP03_KID1', 'UICC_SCP03_KIK1'],
            'SCP03_ISDR': ['SCP03_ENC_ISDR', 'SCP03_MAC_ISDR', 'SCP03_DEK_ISDR'],
            'SCP03_ISDA': ['SCP03_ENC_ISDR', 'SCP03_MAC_ISDA', 'SCP03_DEK_ISDA'],
            'SCP03_ECASD': ['SCP03_ENC_ECASD', 'SCP03_MAC_ECASD', 'SCP03_DEK_ECASD'],
    }

    __IV = b'\x23' * 16

    @staticmethod
    def __dict_keys_to_upper(d: dict) -> dict:
            return {k.upper():v for k,v in d.items()}

    @staticmethod
    def __process_transport_keys(transport_keys: dict, crypt_groups: dict):
        """Apply a single transport key to multiple fields/columns, if the name is a group."""
        new_dict = {}
        for name, key in transport_keys.items():
            if name in crypt_groups:
                for field in crypt_groups[name]:
                    new_dict[field] = key
            else:
                new_dict[name] = key
        return new_dict

    def __init__(self, transport_keys: dict):
        """
        Create new field encryptor/decryptor object and set transport keys, usually one for each column. In some cases
        it is also possible to use a single key for multiple columns (see also __CRYPT_GROUPS)

        Args:
                transport_keys : a dict indexed by field name, whose values are hex-encoded AES keys for the
                                 respective field (column) of the CSV. This is done so that different fields
                                 (columns) can use different transport keys, which is strongly recommended by
                                 GSMA FS.28
        """
        self.transport_keys = self.__process_transport_keys(self.__dict_keys_to_upper(transport_keys),
                                                            self.__CRYPT_GROUPS)
        for name, key in self.transport_keys.items():
                log.debug("Encrypting/decrypting field %s using AES key %s" % (name, key))

    def decrypt_field(self, field_name: str, encrypted_val: str) -> str:
        """
        Decrypt a single field. The decryption is only applied if we have a transport key is known under the provided
        field name, otherwise the field is treated as plaintext and passed through as it is.

        Args:
                field_name : name of the field to decrypt (used to identify which key to use)
                encrypted_val : encrypted field value

        Returns:
                plaintext field value
        """
        if not field_name.upper() in self.transport_keys:
            return encrypted_val
        cipher = AES.new(h2b(self.transport_keys[field_name.upper()]), AES.MODE_CBC, self.__IV)
        return b2h(cipher.decrypt(h2b(encrypted_val)))

    def encrypt_field(self, field_name: str, plaintext_val: str) -> str:
        """
        Encrypt a single field. The encryption is only applied if we have a transport key is known under the provided
        field name, otherwise the field is treated as non sensitive and passed through as it is.

        Args:
                field_name : name of the field to decrypt (used to identify which key to use)
                encrypted_val : encrypted field value

        Returns:
                plaintext field value
        """
        if not field_name.upper() in self.transport_keys:
            return plaintext_val
        cipher = AES.new(h2b(self.transport_keys[field_name.upper()]), AES.MODE_CBC, self.__IV)
        return b2h(cipher.encrypt(h2b(plaintext_val)))

class CardKeyProvider(abc.ABC):
    """Base class, not containing any concrete implementation."""

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
    """Card key provider implementation that allows to query against a specified CSV file."""

    def __init__(self, csv_filename: str, transport_keys: dict):
        """
        Args:
                csv_filename : file name (path) of CSV file containing card-individual key/data
                transport_keys : (see class CardKeyFieldCryptor)
        """
        self.csv_file = open(csv_filename, 'r')
        if not self.csv_file:
            raise RuntimeError("Could not open CSV file '%s'" % csv_filename)
        self.csv_filename = csv_filename
        self.crypt = CardKeyFieldCryptor(transport_keys)

    def get(self, fields: List[str], key: str, value: str) -> Dict[str, str]:
        self.csv_file.seek(0)
        cr = csv.DictReader(self.csv_file)
        if not cr:
            raise RuntimeError("Could not open DictReader for CSV-File '%s'" % self.csv_filename)
        cr.fieldnames = [field.upper() for field in cr.fieldnames]

        rc = {}
        for row in cr:
            if row[key] == value:
                for f in fields:
                    if f in row:
                        rc.update({f: self.crypt.decrypt_field(f, row[f])})
                    else:
                        raise RuntimeError("CSV-File '%s' lacks column '%s'" % (self.csv_filename, f))
        return rc


def card_key_provider_register(provider: CardKeyProvider, provider_list=card_key_providers):
    """Register a new card key provider.

    Args:
            provider : the to-be-registered provider
            provider_list : override the list of providers from the global default
    """
    if not isinstance(provider, CardKeyProvider):
        raise ValueError("provider is not a card data provider")
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
    key = key.upper()
    fields = [f.upper() for f in fields]
    for p in provider_list:
        if not isinstance(p, CardKeyProvider):
            raise ValueError(
                "provider list contains element which is not a card data provider")
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
    key = key.upper()
    field = field.upper()
    for p in provider_list:
        if not isinstance(p, CardKeyProvider):
            raise ValueError(
                "provider list contains element which is not a card data provider")
        result = p.get_field(field, key, value)
        if result:
            return result
    return None
