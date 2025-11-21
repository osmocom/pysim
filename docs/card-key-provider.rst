Retrieving card-individual keys via CardKeyProvider
===================================================

When working with a batch of cards, or more than one card in general, it
is a lot of effort to manually retrieve the card-specific PIN (like
ADM1) or key material (like SCP02/SCP03 keys).

To increase productivity in that regard, pySim has a concept called the
`CardKeyProvider`.  This is a generic mechanism by which different parts
of the pySim[-shell] code can programmatically request card-specific key material
from some data source (*provider*).

For example, when you want to verify the ADM1 PIN using the `verify_adm`
command without providing an ADM1 value yourself, pySim-shell will
request the ADM1 value for the ICCID of the card via the
CardKeyProvider.

There can in theory be multiple different CardKeyProviders.  You can for
example develop your own CardKeyProvider that queries some kind of
database for the key material, or that uses a key derivation function to
derive card-specific key material from a global master key.

pySim already includes two CardKeyProvider implementations. One to retrieve
key material from a CSV file (`CardKeyProviderCsv`) and a second one that allows
to retrieve the key material from a PostgreSQL database (`CardKeyProviderPgsql`).
Both implementations equally implement a column encryption scheme that allows
to protect sensitive columns using a *transport key*


The CardKeyProviderCsv
----------------------

The `CardKeyProviderCsv` allows you to retrieve card-individual key
material from a CSV (comma separated value) file that is accessible to pySim.

The CSV file must have the expected column names, for example `ICCID`
and `ADM1` in case you would like to use that CSV to obtain the
card-specific ADM1 PIN when using the `verify_adm` command.

You can specify the CSV file to use via the `--csv` command-line option
of pySim-shell.  If you do not specify a CSV file, pySim will attempt to
open a CSV file from the default location at
`~/.osmocom/pysim/card_data.csv`, and use that, if it exists.

The `CardKeyProviderCsv` is suitable to manage small amounts of key material
locally. However, if your card inventory is very large and the key material
must be made available on multiple sites, the `CardKeyProviderPgsql` is the
better option.


The CardKeyProviderPgsql
------------------------

With the `CardKeyProviderPgsql` you can use a PostgreSQL database as storage
medium. The implementation comes with a CSV importer tool that consumes the
same CSV files you would normally use with the `CardKeyProviderCsv`, so you
can just use your existing CSV files and import them into the database.


Requirements
^^^^^^^^^^^^

The `CardKeyProviderPgsql` uses the `Psycopg` PostgreSQL database adapter
(https://www.psycopg.org). `Psycopg` is not part of the default requirements
of pySim-shell and must be installed separately. `Psycopg` is available as
Python package under the name `psycopg2-binary`.


Setting up the database
^^^^^^^^^^^^^^^^^^^^^^^

From the perspective of the database, the `CardKeyProviderPgsql` has only
minimal requirements. You do not have to create any tables in advance. An empty
database and at least one user that may create, alter and insert into tables is
sufficient. However, for increased reliability and as a protection against
incorrect operation, the `CardKeyProviderPgsql` supports a hierarchical model
with three users (or roles):

* **admin**:
  This should be the owner of the database. It is intended to be used for
  administrative tasks like adding new tables or adding new columns to existing
  tables. This user should not be used to insert new data into tables or to access
  data from within pySim-shell using the `CardKeyProviderPgsql`

* **importer**:
  This user is used when feeding new data into an existing table. It should only
  be able to insert new rows into existing tables. It should not be used for
  administrative tasks or to access data from within pySim-shell using the
  `CardKeyProviderPgsql`

* **reader**:
  To access data from within pySim shell using the `CardKeyProviderPgsql` the
  reader user is the correct one to use. This user should have no write access
  to the database or any of the tables.


Creating a config file
^^^^^^^^^^^^^^^^^^^^^^

The default location for the config file is `~/.osmocom/pysim/card_data_pgsql.cfg`
The file uses `yaml` syntax and should look like the example below:

::

   host: "127.0.0.1"
   db_name: "my_database"
   table_names:
   - "uicc_keys"
   - "euicc_keys"
   db_users:
      admin:
         name: "my_admin_user"
         pass: "my_admin_password"
      importer:
         name: "my_importer_user"
         pass: "my_importer_password"
      reader:
         name: "my_reader_user"
         pass: "my_reader_password"

This file is used by pySim-shell and by the importer tool. Both expect the file
in the aforementioned location. In case you want to store the file in a
different location you may use the `--pgsql` commandline option to provide a
custom config file path.

The hostname and the database name for the PostgreSQL database is set with the
`host` and `db_name` fields. The field `db_users` sets the user names and
passwords for each of the aforementioned users (or roles). In case only a single
admin user is used, all three entries may be populated with the same user name
and password (not recommended)

The field `table_names` sets the tables that the `CardKeyProviderPgsql` shall
use to query to locate card key data. You can set up as many tables as you
want, `CardKeyProviderPgsql` will query them in order, one by one until a
matching entry is found.

NOTE: In case you do not want to disclose the admin and the importer credentials
to pySim-shell you may remove those lines. pySim-shell will only require the
`reader` entry under `db_users`.


Using the Importer
^^^^^^^^^^^^^^^^^^

Before data can be imported, you must first create a database table. Tables
are created with the provided importer tool, which can be found under
`contrib/csv-to-pgsql.py`. This tool is used to create the database table and
read the data from the provided CSV file into the database.

As mentioned before, all CSV file formats that work with `CardKeyProviderCsv`
may be used. To demonstrate how the import process works, let's assume you want
to import a CSV file format that looks like the following example. Let's also
assume that you didn't get the Global Platform keys from your card vendor for
this batch of UICC cards, so your CSV file lacks the columns for those fields.

::

   "id","imsi","iccid","acc","pin1","puk1","pin2","puk2","ki","opc","adm1"
   "card1","999700000000001","8900000000000000001","0001","1111","11111111","0101","01010101","11111111111111111111111111111111","11111111111111111111111111111111","11111111"
   "card2","999700000000002","8900000000000000002","0002","2222","22222222","0202","02020202","22222222222222222222222222222222","22222222222222222222222222222222","22222222"
   "card3","999700000000003","8900000000000000003","0003","3333","22222222","0303","03030303","33333333333333333333333333333333","33333333333333333333333333333333","33333333"

Since this is your first import, the database still lacks the table. To
instruct the importer to create a new table, you may use the `--create-table`
option. You also have to pick an appropriate name for the table. Any name may
be chosen as long as it contains the string `uicc_keys` or `euicc_keys`,
depending on the type of data (`UICC` or `eUICC`) you intend to store in the
table. The creation of the table is an administrative task and can only be done
with the `admin` user. The `admin` user is selected using the `--admin` switch.

::

   $ PYTHONPATH=../ ./csv-to-pgsql.py --csv ./csv-to-pgsql_example_01.csv --table-name uicc_keys --create-table --admin
   INFO: CSV file: ./csv-to-pgsql_example_01.csv
   INFO: CSV file columns: ['ID', 'IMSI', 'ICCID', 'ACC', 'PIN1', 'PUK1', 'PIN2', 'PUK2', 'KI', 'OPC', 'ADM1']
   INFO: Using config file: /home/user/.osmocom/pysim/card_data_pgsql.cfg
   INFO: Database host: 127.0.0.1
   INFO: Database name: my_database
   INFO: Database user: my_admin_user
   INFO: New database table created: uicc_keys
   INFO: Database table: uicc_keys
   INFO: Database table columns: ['ICCID', 'IMSI']
   INFO: Adding missing columns: ['PIN2', 'PUK1', 'PUK2', 'ACC', 'ID', 'PIN1', 'ADM1', 'KI', 'OPC']
   INFO: Changes to table uicc_keys committed!

The importer has created a new table with the name `uicc_keys`. The table is
now ready to be filled with data.

::

   $ PYTHONPATH=../ ./csv-to-pgsql.py --csv ./csv-to-pgsql_example_01.csv --table-name uicc_keys
   INFO: CSV file: ./csv-to-pgsql_example_01.csv
   INFO: CSV file columns: ['ID', 'IMSI', 'ICCID', 'ACC', 'PIN1', 'PUK1', 'PIN2', 'PUK2', 'KI', 'OPC', 'ADM1']
   INFO: Using config file: /home/user/.osmocom/pysim/card_data_pgsql.cfg
   INFO: Database host: 127.0.0.1
   INFO: Database name: my_database
   INFO: Database user: my_importer_user
   INFO: Database table: uicc_keys
   INFO: Database table columns: ['ICCID', 'IMSI', 'PIN2', 'PUK1', 'PUK2', 'ACC', 'ID', 'PIN1', 'ADM1', 'KI', 'OPC']
   INFO: CSV file import done, 3 rows imported
   INFO: Changes to table uicc_keys committed!

A quick `SELECT * FROM uicc_keys;` at the PostgreSQL console should now display
the contents of the CSV file you have fed into the importer.

Let's now assume that with your next batch of UICC cards your vendor includes
the Global Platform keys so your CSV format changes. It may now look like this:

::

   "id","imsi","iccid","acc","pin1","puk1","pin2","puk2","ki","opc","adm1","scp02_dek_1","scp02_enc_1","scp02_mac_1"
   "card4","999700000000004","8900000000000000004","0004","4444","44444444","0404","04040404","44444444444444444444444444444444","44444444444444444444444444444444","44444444","44444444444444444444444444444444","44444444444444444444444444444444","44444444444444444444444444444444"
   "card5","999700000000005","8900000000000000005","0005","4444","55555555","0505","05050505","55555555555555555555555555555555","55555555555555555555555555555555","55555555","55555555555555555555555555555555","55555555555555555555555555555555","55555555555555555555555555555555"
   "card6","999700000000006","8900000000000000006","0006","4444","66666666","0606","06060606","66666666666666666666666666666666","66666666666666666666666666666666","66666666","66666666666666666666666666666666","66666666666666666666666666666666","66666666666666666666666666666666"

When importing data from an updated CSV format the database table also has
to be updated. This is done using the `--update-columns` switch. Like when
creating new tables, this operation also requires admin privileges, so the
`--admin` switch is required again.

::

   $ PYTHONPATH=../ ./csv-to-pgsql.py --csv ./csv-to-pgsql_example_02.csv --table-name uicc_keys --update-columns --admin
   INFO: CSV file: ./csv-to-pgsql_example_02.csv
   INFO: CSV file columns: ['ID', 'IMSI', 'ICCID', 'ACC', 'PIN1', 'PUK1', 'PIN2', 'PUK2', 'KI', 'OPC', 'ADM1', 'SCP02_DEK_1', 'SCP02_ENC_1', 'SCP02_MAC_1']
   INFO: Using config file: /home/user/.osmocom/pysim/card_data_pgsql.cfg
   INFO: Database host: 127.0.0.1
   INFO: Database name: my_database
   INFO: Database user: my_admin_user
   INFO: Database table: uicc_keys
   INFO: Database table columns: ['ICCID', 'IMSI', 'PIN2', 'PUK1', 'PUK2', 'ACC', 'ID', 'PIN1', 'ADM1', 'KI', 'OPC']
   INFO: Adding missing columns: ['SCP02_ENC_1', 'SCP02_MAC_1', 'SCP02_DEK_1']
   INFO: Changes to table uicc_keys committed!

When the new table columns are added, the import may be continued like the
first one:

::

   $ PYTHONPATH=../ ./csv-to-pgsql.py --csv ./csv-to-pgsql_example_02.csv --table-name uicc_keys
   INFO: CSV file: ./csv-to-pgsql_example_02.csv
   INFO: CSV file columns: ['ID', 'IMSI', 'ICCID', 'ACC', 'PIN1', 'PUK1', 'PIN2', 'PUK2', 'KI', 'OPC', 'ADM1', 'SCP02_DEK_1', 'SCP02_ENC_1', 'SCP02_MAC_1']
   INFO: Using config file: /home/user/.osmocom/pysim/card_data_pgsql.cfg
   INFO: Database host: 127.0.0.1
   INFO: Database name: my_database
   INFO: Database user: my_importer_user
   INFO: Database table: uicc_keys
   INFO: Database table columns: ['ICCID', 'IMSI', 'PIN2', 'PUK1', 'PUK2', 'ACC', 'ID', 'PIN1', 'ADM1', 'KI', 'OPC', 'SCP02_ENC_1', 'SCP02_MAC_1', 'SCP02_DEK_1']
   INFO: CSV file import done, 3 rows imported
   INFO: Changes to table uicc_keys committed!

On the PostgreSQL console a `SELECT * FROM uicc_keys;` should now show the
imported data with the added columns. All important data should now also be
available from within pySim-shell via the `CardKeyProviderPgsql`.


Column-Level CSV encryption
---------------------------

pySim supports column-level CSV encryption.  This feature will make sure
that your key material is not stored in plaintext in the CSV file (or
database).

The encryption mechanism uses AES in CBC mode.  You can use any key
length permitted by AES (128/192/256 bit).

Following GSMA FS.28, the encryption works on column level.  This means
different columns can be decrypted using different key material.  This
means that leakage of a column encryption key for one column or set of
columns (like a specific security domain) does not compromise various
other keys that might be stored in other columns.

You can specify column-level decryption keys using the
`--csv-column-key` command line argument.  The syntax is
`FIELD:AES_KEY_HEX`, for example:

`pySim-shell.py --csv-column-key SCP03_ENC_ISDR:000102030405060708090a0b0c0d0e0f`

In order to avoid having to repeat the column key for each and every
column of a group of keys within a keyset, there are pre-defined column
group aliases, which will make sure that the specified key will be used
by all columns of the set:

* `UICC_SCP02` is a group alias for `UICC_SCP02_KIC1`, `UICC_SCP02_KID1`, `UICC_SCP02_KIK1`
* `UICC_SCP03` is a group alias for `UICC_SCP03_KIC1`, `UICC_SCP03_KID1`, `UICC_SCP03_KIK1`
* `SCP03_ECASD` is a group alias for `SCP03_ENC_ECASD`, `SCP03_MAC_ECASD`, `SCP03_DEK_ECASD`
* `SCP03_ISDA` is a group alias for `SCP03_ENC_ISDA`, `SCP03_MAC_ISDA`, `SCP03_DEK_ISDA`
* `SCP03_ISDR` is a group alias for `SCP03_ENC_ISDR`, `SCP03_MAC_ISDR`, `SCP03_DEK_ISDR`

NOTE: When using `CardKeyProviderPqsl`, the input CSV files must be encrypted
before import.

Field naming
------------

* For look-up of UICC/SIM/USIM/ISIM or eSIM profile specific key
  material, pySim uses the `ICCID` field as lookup key.

* For look-up of eUICC specific key material (like SCP03 keys for the
  ISD-R, ECASD), pySim uses the `EID` field as lookup key.

As soon as the CardKeyProvider finds a line (row) in your CSV file
(or database) where the ICCID or EID match, it looks for the column containing
the requested data.


ADM PIN
~~~~~~~

The `verify_adm` command will attempt to look up the `ADM1` column
indexed by the ICCID of the SIM/UICC.


SCP02 / SCP03
~~~~~~~~~~~~~

SCP02 and SCP03 each use key triplets consisting if ENC, MAC and DEK
keys.  For more details, see the applicable GlobalPlatform
specifications.

If you do not want to manually enter the key material for each specific
card as arguments to the `establish_scp02` or `establish_scp03`
commands, you can make use of the `--key-provider-suffix` option.  pySim
uses this suffix to compose the column names for the CardKeyProvider as
follows.

* `SCP02_ENC_` + suffix for the SCP02 ciphering key
* `SCP02_MAC_` + suffix for the SCP02 MAC key
* `SCP02_DEK_` + suffix for the SCP02 DEK key
* `SCP03_ENC_` + suffix for the SCP03 ciphering key
* `SCP03_MAC_` + suffix for the SCP03 MAC key
* `SCP03_DEK_` + suffix for the SCP03 DEK key

So for example, if you are using a command like `establish_scp03
--key-provider-suffix ISDR`, then the column names for the key material
look-up are `SCP03_ENC_ISDR`, `SCP03_MAC_ISDR` and `SCP03_DEK_ISDR`,
respectively.

The identifier used for look-up is determined by the definition of the
Security Domain.  For example, the eUICC ISD-R and ECASD will use the EID
of the eUICC.  On the other hand, the ISD-P of an eSIM or the ISD of an
UICC will use the ICCID.
