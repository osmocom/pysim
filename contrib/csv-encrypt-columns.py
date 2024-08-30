#!/usr/bin/env python3

# Utility program to perform column-based encryption of a CSV file holding SIM/UICC
# related key materials.
#
# (C) 2024 by Harald Welte <laforge@osmocom.org>
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

import sys
import csv
import argparse
from Cryptodome.Cipher import AES
from osmocom.utils import h2b, b2h, Hexstr

from pySim.card_key_provider import CardKeyProviderCsv

def dict_keys_to_upper(d: dict) -> dict:
    return {k.upper():v for k,v in d.items()}

class CsvColumnEncryptor:
    def __init__(self, filename: str, transport_keys: dict):
        self.filename = filename
        self.transport_keys = dict_keys_to_upper(transport_keys)

    def encrypt_col(self, colname:str, value: str) -> Hexstr:
        key = self.transport_keys[colname]
        cipher = AES.new(h2b(key), AES.MODE_CBC, CardKeyProviderCsv.IV)
        return b2h(cipher.encrypt(h2b(value)))

    def encrypt(self) -> None:
        with open(self.filename, 'r') as infile:
            cr = csv.DictReader(infile)
            cr.fieldnames = [field.upper() for field in cr.fieldnames]

            with open(self.filename + '.encr', 'w') as outfile:
                cw = csv.DictWriter(outfile, dialect=csv.unix_dialect, fieldnames=cr.fieldnames)
                cw.writeheader()

                for row in cr:
                    for key_colname in self.transport_keys:
                        if key_colname in row:
                            row[key_colname] = self.encrypt_col(key_colname, row[key_colname])
                    cw.writerow(row)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('CSVFILE', help="CSV file name")
    parser.add_argument('--csv-column-key', action='append', required=True,
                        help='per-CSV-column AES transport key')

    opts = parser.parse_args()

    csv_column_keys = {}
    for par in opts.csv_column_key:
        name, key = par.split(':')
        csv_column_keys[name] = key

    if len(csv_column_keys) == 0:
        print("You must specify at least one key!")
        sys.exit(1)

    csv_column_keys = CardKeyProviderCsv.process_transport_keys(csv_column_keys)
    for name, key in csv_column_keys.items():
        print("Encrypting column %s using AES key %s" % (name, key))

    cce = CsvColumnEncryptor(opts.CSVFILE, csv_column_keys)
    cce.encrypt()
