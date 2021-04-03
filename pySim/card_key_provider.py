# coding=utf-8
"""Abstraction of card related data that can be queried from external source."""

# (C) 2021 by Sysmocom s.f.m.c. GmbH
# All Rights Reserved
#
# Author: Philipp Maier
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

import csv

card_key_providers = [] # type: List[CardData]

class CardKeyProvider(object):

	VALID_FIELD_NAMES = ['ICCID', 'ADM1', 'IMSI', 'PIN1', 'PIN2', 'PUK1', 'PUK2']

	# check input parameters, but do nothing concrete yet
	def get_data(self, fields:List[str]=[], key:str='ICCID', value:str="") -> Dict[str,str]:
		"""abstract implementation of get_data that only verifies the function parameters"""

		for f in fields:
			if (f not in self.VALID_FIELD_NAMES):
				raise ValueError("Requested field name '%s' is not a valid field name, valid field names are: %s" %
						 (f, str(self.VALID_FIELD_NAMES)))

		if (key not in self.VALID_FIELD_NAMES):
			raise ValueError("Key field name '%s' is not a valid field name, valid field names are: %s" %
					 (key, str(self.VALID_FIELD_NAMES)))

		return {}

	def get_field(self, field:str, key:str='ICCID', value:str="") -> Optional[str]:
		"""get a single field from CSV file using a specified key/value pair"""
		fields = [field]
		result = self.get(fields, key, value)
		return result.get(field)

	def get(self, fields:List[str], key:str, value:str) -> Dict[str,str]:
		"""get fields from CSV file using a specified key/value pair"""
		pass

class CardKeyProviderCsv(CardKeyProvider):
	"""card data class that allows the user to query against a specified CSV file"""
	csv_file = None
	filename = None

	def __init__(self, filename:str):
		self.csv_file = open(filename, 'r')
		if not self.csv_file:
			raise RuntimeError("Could not open CSV-File '%s'" % filename)
		self.filename = filename

	def get(self, fields:List[str], key:str, value:str) -> Dict[str,str]:
		"""get fields from CSV file using a specified key/value pair"""
		super().get_data(fields, key, value)

		self.csv_file.seek(0)
		cr = csv.DictReader(self.csv_file)
		if not cr:
			raise RuntimeError("Could not open DictReader for CSV-File '%s'" % self.filename)
		cr.fieldnames = [ field.upper() for field in cr.fieldnames ]

		rc = {}
		for row in cr:
			if row[key] == value:
				for f in fields:
					if f in row:
						rc.update({f : row[f]})
					else:
						raise RuntimeError("CSV-File '%s' lacks column '%s'" %
								   (self.filename, f))
		return rc


def card_key_provider_register(provider:CardKeyProvider, provider_list=card_key_providers):
	"""Register a new card data provider"""
	if not isinstance(provider, CardKeyProvider):
		raise ValueError("provider is not a card data provier")
	provider_list.append(provider)


def card_key_provider_get(fields, key:str, value:str, provider_list=card_key_providers) -> Dict[str,str]:
	"""Query all registered card data providers"""
	for p in provider_list:
		if not isinstance(p, CardKeyProvider):
			raise ValueError("provider list contains provider, which is not a card data provier")
		result = p.get(fields, key, value)
		if result:
			return result
	return {}


def card_key_provider_get_field(field:str, key:str, value:str, provider_list=card_key_providers) -> Optional[str]:
	"""Query all registered card data providers for a single field"""
	for p in provider_list:
		if not isinstance(p, CardKeyProvider):
			raise ValueError("provider list contains provider, which is not a card data provier")
		result = p.get_field(field, key, value)
		if result:
			return result
	return None

