# coding=utf-8
"""Abstraction of card data that can be queried from external source

(C) 2021 by Sysmocom s.f.m.c. GmbH
All Rights Reserved

Author: Philipp Maier

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import csv

card_data_provider = []

class CardData(object):

	VALID_FIELD_NAMES = ['ICCID', 'ADM1', 'IMSI', 'PIN1', 'PIN2', 'PUK1', 'PUK2']

	# check input parameters, but do nothing concrete yet
	def get_data(self, fields=[], key='ICCID', value=""):
		"""abstract implementation of get_data that only verifies the function parameters"""

		for f in fields:
			if (f not in self.VALID_FIELD_NAMES):
				raise ValueError("Requested field name '%s' is not a valid field name, valid field names are: %s" %
						 (f, str(self.VALID_FIELD_NAMES)))

		if (key not in self.VALID_FIELD_NAMES):
			raise ValueError("Key field name '%s' is not a valid field name, valid field names are: %s" %
					 (key, str(self.VALID_FIELD_NAMES)))

		return {}

	def get_field(self, field, key='ICCID', value=""):
		"""get a single field from CSV file using a specified key/value pair"""
		fields = [field]
		result = self.get(fields, key, value)
		return result.get(field)


class CardDataCsv(CardData):
	"""card data class that allows the user to query against a specified CSV file"""
	csv_file = None
	filename = None

	def __init__(self, filename):
		self.csv_file = open(filename, 'r')
		if not self.csv_file:
			raise RuntimeError("Could not open CSV-File '%s'" % filename)
		self.filename = filename

	def get(self, fields, key, value):
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


def card_data_register(provider, provider_list=card_data_provider):
	"""Register a new card data provider"""
	if not isinstance(provider, CardData):
		raise ValueError("provider is not a card data provier")
	provider_list.append(provider)


def card_data_get(fields, key, value, provider_list=card_data_provider):
	"""Query all registered card data providers"""
	for p in provider_list:
		if not isinstance(p, CardData):
			raise ValueError("provider list contains provider, which is not a card data provier")
		result = p.get(fields, key, value)
		if result:
			return result
	return {}


def card_data_get_field(field, key, value, provider_list=card_data_provider):
	"""Query all registered card data providers for a single field"""
	for p in provider_list:
		if not isinstance(p, CardData):
			raise ValueError("provider list contains provider, which is not a card data provier")
		result = p.get_field(field, key, value)
		if result:
			return result
	return None

