#!/usr/bin/env python3

# (C) 2025 by sysmocom - s.f.m.c. GmbH
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

import argparse
import logging
import csv
import sys
import os
import yaml
import psycopg2
from psycopg2.sql import Identifier, SQL
from pathlib import Path
from pySim.log import PySimLogger
from packaging import version

log = PySimLogger.get(Path(__file__).stem)

class CardKeyDatabase:
    def __init__(self, config_filename: str, table_name: str, create_table: bool = False, admin: bool = False):
        """
        Initialize database connection and set the table which shall be used as storage for the card key data.
        In case the specified table does not exist yet it can be created using the create_table_type parameter.

        New tables are always minimal tables which follow a pre-defined table scheme. The user may extend the table
        with additional columns using the add_cols() later.

        Args:
                tablename : name of the database table to create.
                create_table_type : type of the table to create ('UICC' or 'EUICC')
        """

        def user_from_config_file(config, role: str) -> tuple[str, str]:
            db_users = config.get('db_users')
            user = db_users.get(role)
            if user is None:
                raise ValueError("user for role '%s' not set up in config file." % role)
            return user.get('name'), user.get('pass')

        self.table = table_name.lower()
        self.cols = None

        # Depending on the table type, the table name must contain either the substring "uicc_keys" or "euicc_keys".
        # This convention will allow us to deduct the table type from the table name.
        if "euicc_keys" not in table_name and "uicc_keys" not in table_name:
            raise ValueError("Table name (%s) should contain the substring \"uicc_keys\" or \"euicc_keys\"" % table_name)

        # Read config file
        log.info("Using config file: %s", config_filename)
        with open(config_filename, "r") as cfg:
            config = yaml.load(cfg, Loader=yaml.FullLoader)
        host = config.get('host')
        log.info("Database host: %s", host)
        db_name = config.get('db_name')
        log.info("Database name: %s", db_name)
        table_names = config.get('table_names')
        username_admin, password_admin = user_from_config_file(config, 'admin')
        username_importer, password_importer = user_from_config_file(config, 'importer')
        username_reader, _ = user_from_config_file(config, 'reader')

        # Switch between admin and importer user
        if admin:
            username, password = username_admin, password_admin
        else:
            username, password = username_importer, password_importer

        # Create database connection
        log.info("Database user: %s", username)
        self.conn = psycopg2.connect(dbname=db_name, user=username, password=password, host=host)
        self.cur = self.conn.cursor()

        # In the context of this tool it is not relevant if the table name is present in the config file. However,
        # pySim-shell.py will require the table name to be configured properly to access the database table.
        if self.table not in table_names:
            log.warning("Specified table name (%s) is not yet present in config file (required for access from pySim-shell.py)",
                        self.table)

        # Create a new minimal database table of the specified table type.
        if create_table:
            if not admin:
                raise ValueError("creation of new table refused, use option --admin and try again.")
            if "euicc_keys" in self.table:
                self.__create_table(username_reader, username_importer, ['EID'])
            elif "uicc_keys" in self.table:
                self.__create_table(username_reader, username_importer, ['ICCID', 'IMSI'])

        # Ensure a table with the specified name exists
        log.info("Database table: %s", self.table)
        if self.get_cols() == []:
            raise ValueError("Table name (%s) does not exist yet" % self.table)
        log.info("Database table columns: %s", str(self.get_cols()))

    def __create_table(self, user_reader:str, user_importer:str, cols:list[str]):
        """
        Initialize a new table. New tables are always minimal tables with one primary key and additional index columns.
        Non index-columns may be added later using method _update_cols().
        """

        # Create table columns with primary key
        query = SQL("CREATE TABLE {} ({} VARCHAR PRIMARY KEY").format(Identifier(self.table),
                                                                      Identifier(cols[0].lower()))
        for c in cols[1:]:
            query += SQL(", {} VARCHAR").format(Identifier(c.lower()))
        query += SQL(");")
        self.cur.execute(query)

        # Create indexes for all other columns
        for c in cols[1:]:
            self.cur.execute(query = SQL("CREATE INDEX {} ON {}({});").format(Identifier(c.lower()),
                                                                              Identifier(self.table),
                                                                              Identifier(c.lower())))

        # Set permissions
        self.cur.execute(SQL("GRANT INSERT ON {} TO {};").format(Identifier(self.table),
                                                                 Identifier(user_importer)))
        self.cur.execute(SQL("GRANT SELECT ON {} TO {};").format(Identifier(self.table),
                                                                 Identifier(user_reader)))

        log.info("New database table created: %s", self.table)

    def get_cols(self) -> list[str]:
        """
        Get a list of all columns available in the current table scheme.

        Returns:
                list with column names (in uppercase) of the database table
        """

        # Return cached col list if present
        if self.cols:
            return self.cols

        # Request a list of current cols from the database
        self.cur.execute("SELECT column_name FROM information_schema.columns where table_name = %s;", (self.table,))

        cols_result = self.cur.fetchall()
        cols = []
        for c in cols_result:
            cols.append(c[0].upper())
        self.cols = cols
        return cols

    def get_missing_cols(self, cols_expected:list[str]) -> list[str]:
        """
        Check if the current table scheme lacks any of the given expected columns.

        Returns:
                list with the missing columns.
        """

        cols_present = self.get_cols()
        return list(set(cols_expected) - set(cols_present))

    def add_cols(self, cols:list[str]):
        """
        Update the current table scheme with additional columns. In case the updated columns are already exist, the
        table schema is not changed.

        Args:
                table : name of the database table to alter
                cols : list with updated colum names to add
        """

        cols_missing = self.get_missing_cols(cols)

        # Depending on the table type (see constructor), we either have a primary key 'ICCID' (for UICC data), or 'EID'
        # (for eUICC data). Both table formats different types of data and have rather differen columns also. Let's
        # prevent the excidentally mixing of both types.
        if 'ICCID' in cols_missing:
            raise ValueError("Table %s stores eUCCC key material, refusing to add UICC specific column 'ICCID'" % self.table)
        if 'EID' in cols_missing:
            raise ValueError("Table %s stores UCCC key material, refusing to add eUICC specific column 'EID'" % self.table)

        # Add the missing columns to the table
        self.cols = None
        for c in cols_missing:
            self.cur.execute(query = SQL("ALTER TABLE {} ADD {} VARCHAR;").format(Identifier(self.table),
                                                                                  Identifier(c.lower())))

    def insert_row(self, row:dict[str, str]):
        """
        Insert a new row into the database table.

        Args:
                row : dictionary with the colum names and their designated values
        """

        # Check if the row is compatible with the current table scheme
        cols_expected = list(row.keys())
        cols_missing = self.get_missing_cols(cols_expected)
        if cols_missing != []:
            raise ValueError("table %s has incompatible format, the row %s contains unknown cols %s" %
                             (self.table, str(row), str(cols_missing)))

        # Insert row into datbase table
        row_keys = list(row.keys())
        row_values = list(row.values())
        query = SQL("INSERT INTO {} ").format(Identifier(self.table))
        query += SQL("({} ").format(Identifier(row_keys[0].lower()))
        for k in row_keys[1:]:
            query += SQL(", {}").format(Identifier(k.lower()))
        query += SQL(") VALUES (%s")
        for v in row_values[1:]:
            query += SQL(", %s")
        query += SQL(");")
        self.cur.execute(query, row_values)

    def commit(self):
        self.conn.commit()
        log.info("Changes to table %s committed!", self.table)

def open_csv(opts: argparse.Namespace):
    log.info("CSV file: %s", opts.csv)
    csv_file = open(opts.csv, 'r')
    cr = csv.DictReader(csv_file)
    if not cr:
        raise RuntimeError("could not open DictReader for CSV-File '%s'" % opts.csv)
    cr.fieldnames = [field.upper() for field in cr.fieldnames]
    log.info("CSV file columns: %s", str(cr.fieldnames))
    return cr

def open_db(cr: csv.DictReader, opts: argparse.Namespace) -> CardKeyDatabase:
    try:
        db = CardKeyDatabase(os.path.expanduser(opts.pgsql), opts.table_name, opts.create_table, opts.admin)

        # Check CSV format against table schema, add missing columns
        cols_missing = db.get_missing_cols(cr.fieldnames)
        if cols_missing != [] and (opts.update_columns or opts.create_table):
            log.info("Adding missing columns: %s", str(cols_missing))
            db.add_cols(cols_missing)
            cols_missing = db.get_missing_cols(cr.fieldnames)

        # Make sure the table schema has no missing columns
        if cols_missing != []:
            log.error("Database table lacks CSV file columns: %s -- import aborted!", cols_missing)
            sys.exit(2)
    except Exception as e:
        log.error(str(e).strip())
        log.error("Database initialization aborted due to error!")
        sys.exit(2)

    return db

def import_from_csv(db: CardKeyDatabase, cr: csv.DictReader):
    count = 0
    for row in cr:
        try:
            db.insert_row(row)
            count+=1
            if count % 100 == 0:
                log.info("CSV file import in progress, %d rows imported...", count)
        except Exception as e:
            log.error(str(e).strip())
            log.error("CSV file import aborted due to error, no datasets committed!")
            sys.exit(2)
    log.info("CSV file import done, %d rows imported", count)

if __name__ == '__main__':
    option_parser = argparse.ArgumentParser(description='CSV importer for pySim-shell\'s PostgreSQL Card Key Provider',
                                            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    option_parser.add_argument("--verbose", help="Enable verbose logging", action='store_true', default=False)
    option_parser.add_argument('--pgsql', metavar='FILE',
                               default="~/.osmocom/pysim/card_data_pgsql.cfg",
                               help='Read card data from PostgreSQL database (config file)')
    option_parser.add_argument('--csv', metavar='FILE', help='input CSV file with card data', required=True)
    option_parser.add_argument("--table-name", help="name of the card key table", type=str, required=True)
    option_parser.add_argument("--update-columns", help="add missing table columns", action='store_true', default=False)
    option_parser.add_argument("--create-table", action='store_true', help="create new card key table", default=False)
    option_parser.add_argument("--admin", action='store_true', help="perform action as admin", default=False)
    opts = option_parser.parse_args()

    PySimLogger.setup(print, {logging.WARN: "\033[33m"})
    if (opts.verbose):
        PySimLogger.set_verbose(True)
        PySimLogger.set_level(logging.DEBUG)

    # Open CSV file
    cr = open_csv(opts)

    # Open database, create initial table, update column scheme
    db = open_db(cr, opts)

    # Progress with import
    if not opts.admin:
        import_from_csv(db, cr)

    # Commit changes to the database
    db.commit()
