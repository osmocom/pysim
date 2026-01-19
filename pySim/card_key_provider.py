# coding=utf-8
"""Obtaining card parameters (mostly key data) from external source.

This module contains a base class and a concrete implementation of
obtaining card key material (or other card-individual parameters) from
an external data source.

This is used e.g. to keep PIN/PUK data in some file on disk, avoiding
the need of manually entering the related card-individual data on every
operation with pySim-shell.
"""

# (C) 2021-2025 by sysmocom - s.f.m.c. GmbH
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
import yaml

log = PySimLogger.get(__name__)

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
            'SCP03_ISDA': ['SCP03_ENC_ISDA', 'SCP03_MAC_ISDA', 'SCP03_DEK_ISDA'],
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

    @abc.abstractmethod
    def get(self, fields: List[str], key: str, value: str) -> Dict[str, str]:
        """
        Get multiple card-individual fields for identified card. This method should not fail with an exception in
        case the entry, columns or even the key column itsself is not found.

        Args:
                fields : list of valid field names such as 'ADM1', 'PIN1', ... which are to be obtained
                key : look-up key to identify card data, such as 'ICCID'
                value : value for look-up key to identify card data
        Returns:
                dictionary of {field : value, ...} strings for each requested field from 'fields'. In case nothing is
                fond None shall be returned.
        """

    def __str__(self):
        return type(self).__name__

class CardKeyProviderCsv(CardKeyProvider):
    """Card key provider implementation that allows to query against a specified CSV file."""

    def __init__(self, csv_filename: str, transport_keys: dict):
        """
        Args:
                csv_filename : file name (path) of CSV file containing card-individual key/data
                transport_keys : (see class CardKeyFieldCryptor)
        """
        log.info("Using CSV file as card key data source: %s" % csv_filename)
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

        if key not in cr.fieldnames:
            return None
        return_dict = {}
        for row in cr:
            if row[key] == value:
                for f in fields:
                    if f in row:
                        return_dict.update({f: self.crypt.decrypt_field(f, row[f])})
                    else:
                        raise RuntimeError("CSV-File '%s' lacks column '%s'" % (self.csv_filename, f))
        if return_dict == {}:
            return None
        return return_dict

class CardKeyProviderPgsql(CardKeyProvider):
    """Card key provider implementation that allows to query against a specified PostgreSQL database table."""

    def __init__(self, config_filename: str, transport_keys: dict):
        """
        Args:
                config_filename : file name (path) of CSV file containing card-individual key/data
                transport_keys : (see class CardKeyFieldCryptor)
        """
        import psycopg2
        log.info("Using SQL database as card key data source: %s" % config_filename)
        with open(config_filename, "r") as cfg:
            config = yaml.load(cfg, Loader=yaml.FullLoader)
            log.info("Card key database name: %s" % config.get('db_name'))
            db_users = config.get('db_users')
            user = db_users.get('reader')
            if user is None:
                raise ValueError("user for role 'reader' not set up in config file.")
            self.conn = psycopg2.connect(dbname=config.get('db_name'),
                                         user=user.get('name'),
                                         password=user.get('pass'),
                                         host=config.get('host'))
            self.tables = config.get('table_names')
            log.info("Card key database tables: %s" % str(self.tables))
            self.crypt = CardKeyFieldCryptor(transport_keys)

    def get(self, fields: List[str], key: str, value: str) -> Dict[str, str]:
        import psycopg2
        from psycopg2.sql import Identifier, SQL
        db_result = None
        for t in self.tables:
            self.conn.rollback()
            cur = self.conn.cursor()

            # Make sure that the database table and the key column actually exists. If not, move on to the next table
            cur.execute("SELECT column_name FROM information_schema.columns where table_name = %s;", (t,))
            cols_result = cur.fetchall()
            if cols_result == []:
                log.warning("Card Key database seems to lack table %s, check config file!" % t)
                continue
            if (key.lower(),) not in cols_result:
                continue

            # Query requested columns from database table
            query = SQL("SELECT {}").format(Identifier(fields[0].lower()))
            for f in fields[1:]:
                query += SQL(", {}").format(Identifier(f.lower()))
            query += SQL(" FROM {} WHERE {} = %s LIMIT 1;").format(Identifier(t.lower()),
                                                                  Identifier(key.lower()))
            cur.execute(query, (value,))
            db_result = cur.fetchone()
            cur.close()

            if db_result:
                break

        if db_result is None:
            return None
        result = dict(zip(fields, db_result))

        for k in result.keys():
            result[k] = self.crypt.decrypt_field(k, result.get(k))
        return result


def card_key_provider_register(provider: CardKeyProvider, provider_list=card_key_providers):
    """Register a new card key provider.

    Args:
            provider : the to-be-registered provider
            provider_list : override the list of providers from the global default
    """
    if not isinstance(provider, CardKeyProvider):
        raise ValueError("provider is not a card data provider")
    provider_list.append(provider)


def card_key_provider_get(fields: list[str], key: str, value: str, provider_list=card_key_providers) -> Dict[str, str]:
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
            raise ValueError("Provider list contains element which is not a card data provider")
        log.debug("Searching for card key data (key=%s, value=%s, provider=%s)" % (key, value, str(p)))
        result = p.get(fields, key, value)
        if result:
            log.debug("Found card data: %s" % (str(result)))
            return result

    raise ValueError("Unable to find card key data (key=%s, value=%s, fields=%s)" % (key, value, str(fields)))


def card_key_provider_get_field(field: str, key: str, value: str, provider_list=card_key_providers) -> str:
    """Query all registered card data providers for a single field.

    Args:
            field : name valid field such as 'ADM1', 'PIN1', ... which is to be obtained
            key : look-up key to identify card data, such as 'ICCID'
            value : value for look-up key to identify card data
            provider_list : override the list of providers from the global default
    Returns:
            dictionary of {field, value} strings for the requested field
    """

    fields = [field]
    result = card_key_provider_get(fields, key, value, card_key_providers)
    return result.get(field.upper())
