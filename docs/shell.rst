pySim-shell
===========

pySim-shell is an interactive command line shell for all kind of interactions with SIM cards,
including classic GSM SIM, GSM-R SIM, UICC, USIM, ISIM, HPSIM and recently even eUICC.

If you're familiar with Unix/Linux shells: Think of it like *the bash for SIM cards*.

The pySim-shell interactive shell provides commands for

* navigating the on-card filesystem hierarchy
* authenticating with PINs such as ADM1
* CHV/PIN management (VERIFY, ENABLE, DISABLE, UNBLOCK)
* decoding of SELECT response (file control parameters)
* reading and writing of files and records in raw, hex-encoded binary format
* for most files (where related file-specific encoder/decoder classes have been developed):

 * decoded reading (display file data represented in human and machine readable JSON format)
 * decoded writing (encode from JSON to binary format, then write)

* if your card supports it, and you have the related privileges: resizing, creating, enabling and disabling of
  files
* performing GlobalPlatform operations, including establishment of Secure Channel Protocol (SCP), Installing
  applications, installing key material, etc.
* listing/enabling/disabling/deleting eSIM profiles on Consumer eUICC

By means of using the python ``cmd2`` module, various useful features improve usability:

* history of commands (persistent across restarts)
* output re-direction to files on your computer
* output piping through external tools like ``grep``
* tab completion of commands and SELECT-able files/directories
* interactive help for all commands

A typical interactive pySim workflow would look like this:

* starting the program, specifying which smart card interface to use to talk to the card
* verifying the PIN (if needed) or the ADM1 PIN in case you want to write/modify the card
* selecting on-card application dedicated files like ADF.USIM and navigating the tree of DFs
* reading and potentially modifying file contents, in raw binary (hex) or decoded JSON format

Video Presentation
------------------

There is a `video recording of the presentation back when pySim-shell was originally released
<https://media.ccc.de/v/osmodevcall-20210409-laforge-pysim-shell>`_.  While it is slightly dated, it should
still provide a good introduction.

Running pySim-shell
-------------------

pySim-shell has a variety of command line arguments to control

* which transport to use (how to use a reader to talk to the SIM card)
* whether to automatically verify an ADM pin (and in which format)
* whether to execute a start-up script

.. argparse::
   :module: pySim-shell
   :func: option_parser
   :prog: pySim-shell.py

Usage Examples
--------------
.. toctree::
   :maxdepth: 1
   :caption: Tutorials for pySIM-shell:

   suci-tutorial
   cap-tutorial


Advanced Topics
---------------
.. toctree::
   :maxdepth: 1
   :caption: Advanced pySIM-shell topics

   card-key-provider
   remote-access

cmd2 basics
-----------

As pySim-shell is built upon ``cmd2``, some generic cmd2 commands/features are available.  You may
want to check out the `cmd2 Builtin commands <https://cmd2.readthedocs.io/en/stable/features/builtin_commands.html>`_
to learn about those.


pySim commands
--------------

Commands in this category are pySim specific; they do not have a 1:1 correspondence to ISO 7816
or 3GPP commands. Mostly they will operate either only on local (in-memory) state, or execute
a complex sequence of card-commands.

desc
~~~~
Display human readable file description for the currently selected file.


dir
~~~
.. argparse::
   :module: pySim-shell
   :func: PySimCommands.dir_parser

Example:
::

  pySIM-shell (00:MF)> dir
  MF
  3f00
   ..          ADF.USIM    DF.SYSTEM   EF.DIR      EF.UMPC
   ADF.ARA-M   DF.EIRENE   DF.TELECOM  EF.ICCID    MF
   ADF.ISIM    DF.GSM      EF.ARR      EF.PL
  14 files


export
~~~~~~
.. argparse::
   :module: pySim-shell
   :func: PySimCommands.export_parser

Please note that `export` works relative to the current working
directory, so if you are in `MF`, then the export will contain all known
files on the card.  However, if you are in `ADF.ISIM`, only files below
that ADF will be part of the export.

Furthermore, it is strongly advised to first enter the ADM1 pin
(`verify_adm`) to maximize the chance of having permission to read
all/most files.


Example:
::

  pySIM-shell (00:MF)> export --json > /tmp/export.json
  EXCEPTION of type 'RuntimeError' occurred with message: 'unable to export 50 elementary file(s) and 2 dedicated file(s), also had to stop early due to exception:6e00: ARA-M - Invalid class'
  To enable full traceback, run the following command: 'set debug true'
  pySIM-shell (00:MF)>

The exception above is more or less expected.  It just means that 50 files which are defined (most likely as
optional files in some later 3GPP release) were not found on the card, or were invalidated/disabled when
trying to SELECT them.


fsdump
~~~~~~
.. argparse::
   :module: pySim-shell
   :func: PySimCommands.fsdump_parser

Please note that `fsdump` works relative to the current working
directory, so if you are in `MF`, then the dump will contain all known
files on the card.  However, if you are in `ADF.ISIM`, only files below
that ADF will be part of the dump.

Furthermore, it is strongly advised to first enter the ADM1 pin
(`verify_adm`) to maximize the chance of having permission to read
all/most files.

One use case for this is to systematically analyze the differences between the contents of two
cards.  To do this, you can create fsdumps of the two cards, and then use some general-purpose JSON
diffing tool like `jycm --show` (see https://github.com/eggachecat/jycm).

Example:
::

  pySIM-shell (00:MF)> fsdump > /tmp/fsdump.json
  pySIM-shell (00:MF)>


tree
~~~~
Display a tree of the card filesystem.  It is important to note that this displays a tree
of files that might potentially exist (based on the card profile).  In order to determine if
a given file really exists on a given card, you have to try to select that file.

Example:
::

  pySIM-shell (00:MF)> tree
  EF.DIR                    2f00 Application Directory
  EF.ICCID                  2fe2 ICC Identification
  EF.PL                     2f05 Preferred Languages
  EF.ARR                    2f06 Access Rule Reference
  EF.UMPC                   2f08 UICC Maximum Power Consumption
  DF.TELECOM                7f10 None
    EF.ADN                  6f3a Abbreviated Dialing Numbers
  ...



verify_adm
~~~~~~~~~~

.. argparse::
   :module: pySim-shell
   :func: PySimCommands.verify_adm_parser


Example (successful):
::

  pySIM-shell (00:MF)> verify_adm 11111111
  pySIM-shell (00:MF)>

In the above case, the ADM was successfully verified. Please make always sure to use the correct ADM1 for the
specific card you have inserted! If you present a wrong ADM1 value several times consecutively, your card
ADM1 will likely be permanently locked, meaning you will never be able to reach ADM1 privilege level.
For sysmoUSIM/ISIM products, three consecutive wrong ADM1 values will lock the ADM1.

Example (erroneous):
::

  pySIM-shell (00:MF)> verify_adm 1
  EXCEPTION of type 'RuntimeError' occurred with message: 'Failed to verify chv_no 0x0A with code 0x31FFFFFFFFFFFFFF, 2 tries left.'
  To enable full traceback, run the following command: 'set debug true'

If you frequently work with the same set of cards that you need to modify using their ADM1, you can put a CSV
file with those cards ICCID + ADM1 values into a CSV (comma separated value) file at ``~/.osmocom/pysim/card_data.csv``.  In this case,
you can use the ``verify_adm`` command *without specifying an ADM1 value*.

Example (successful):

::

  pySIM-shell (00:MF)> verify_adm
  found ADM-PIN '11111111' for ICCID '898821190000000512'
  pySIM-shell (00:MF)>

In this case, the CSV file contained a record for the ICCID of the card (11111111) and that value was used to
successfully verify ADM1.


Example (erroneous):
::

  pySIM-shell (00:MF)> verify_adm
  EXCEPTION of type 'ValueError' occurred with message: 'cannot find ADM-PIN for ICCID '898821190000000512''
  To enable full traceback, run the following command: 'set debug true'

In this case there was no record for the ICCID of the card in the CSV file.


reset
~~~~~
Perform card reset and display the card ATR.

Example:
::

  pySIM-shell (00:MF)> reset
  Card ATR: 3b9f96801f878031e073fe211b674a357530350259c4
  pySIM-shell (00:MF)> reset


intro
~~~~~
[Re-]Display the introductory banner

Example:
::

  pySIM-shell (00:MF)> intro
  Welcome to pySim-shell!
  (C) 2021-2023 by Harald Welte, sysmocom - s.f.m.c. GmbH and contributors
  Online manual available at https://downloads.osmocom.org/docs/pysim/master/html/shell.html


equip
~~~~~
Equip pySim-shell with a card; particularly useful if the program was
started before a card was present, or after a card has been replaced by
the user while pySim-shell was kept running.

bulk_script
~~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: PysimApp.bulk_script_parser


echo
~~~~
.. argparse::
   :module: pySim-shell
   :func: PysimApp.echo_parser


apdu
~~~~
.. argparse::
   :module: pySim-shell
   :func: PysimApp.apdu_cmd_parser

Example:

::

  pySIM-shell (00:MF)> apdu 00a40400023f00
  SW: 6700

In the above case the raw APDU hex-string ``00a40400023f00`` was sent to the card, to which it responded with
status word ``6700``.  Keep in mind that pySim-shell has no idea what kind of raw commands you are sending to the
card, and it hence is unable to synchronize its internal state (such as the currently selected file) with the
card.  The use of this command should hence be constrained to commands that do not have any high-level support
in pySim-shell yet.


ISO7816 commands
----------------

This category of commands relates to commands that originate in the ISO 7861-4 specifications,
most of them have a 1:1 resemblance in the specification.

select
~~~~~~

The ``select`` command is used to select a file, either by its FID, AID or by its symbolic name.

Try ``select`` with tab-completion to get a list of all current selectable items:

::

  pySIM-shell (00:MF)> select
  ..                2fe2              a0000000871004    EF.ARR            MF
  2f00              3f00              ADF.ISIM          EF.DIR
  2f05              7f10              ADF.USIM          EF.ICCID
  2f06              7f20              DF.GSM            EF.PL
  2f08              a0000000871002    DF.TELECOM        EF.UMPC

Use ``select`` with a specific FID or name to select the new file.

This will

* output the [JSON decoded, if possible] select response
* change the prompt to the newly selected file
* enable any commands specific to the newly-selected file

::

  pySIM-shell (00:MF)> select ADF.USIM
  {
      "file_descriptor": {
          "file_descriptor_byte": {
              "shareable": true,
              "file_type": "df",
              "structure": "no_info_given"
          }
      },
      "df_name": "A0000000871002FFFFFFFF8907090000",
      "proprietary_info": {
          "uicc_characteristics": "71",
          "available_memory": 101640
      },
      "life_cycle_status_int": "operational_activated",
      "security_attrib_compact": "00",
      "pin_status_template_do": {
          "ps_do": "70",
          "key_reference": 11
      }

  }
  pySIM-shell (00:MF/ADF.USIM)>


status
~~~~~~

The ``status`` command [re-]obtains the File Control Template of the
currently-selected file and print its decoded output.

Example:

::

  pySIM-shell (00:MF/ADF.ISIM)> status
  {
      "file_descriptor": {
          "file_descriptor_byte": {
              "shareable": true,
              "file_type": "df",
              "structure": "no_info_given"
          },
          "record_len": null,
          "num_of_rec": null
      },
      "file_identifier": "ff01",
      "df_name": "a0000000871004ffffffff8907090000",
      "proprietary_information": {
          "uicc_characteristics": "71",
          "available_memory": 101640
      },
      "life_cycle_status_integer": "operational_activated",
      "security_attrib_compact": "00",
      "pin_status_template_do": {
          "ps_do": "70",
          "key_reference": 11
      }
  }


change_chv
~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.change_chv_parser


disable_chv
~~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.disable_chv_parser


enable_chv
~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.enable_chv_parser


unblock_chv
~~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.unblock_chv_parser


verify_chv
~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.verify_chv_parser

deactivate_file
~~~~~~~~~~~~~~~
Deactivate the currently selected file.  A deactivated file can no longer be accessed
for any further operation (such as selecting and subsequently reading or writing).

Any access to a file that is deactivated will trigger the error
*SW 6283 'Selected file invalidated/disabled'*

In order to re-access a deactivated file, you need to activate it again, see the
`activate_file` command below.  Note that for *deactivation* the to-be-deactivated
EF must be selected, but for *activation*, the DF above the to-be-activated
EF must be selected!

This command sends a DEACTIVATE FILE APDU to
the card (used to be called INVALIDATE in TS 11.11 for classic SIM).


activate_file
~~~~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.activate_file_parser

open_channel
~~~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.open_chan_parser

close_channel
~~~~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.close_chan_parser

switch_channel
~~~~~~~~~~~~~~
.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.switch_chan_parser


TS 102 221 commands
-------------------

These are commands as specified in ETSI TS 102 221, the core UICC specification.

suspend_uicc
~~~~~~~~~~~~
This command allows you to perform the SUSPEND UICC command on the card.  This is a relatively
recent power-saving addition to the UICC specifications, allowing for suspend/resume while maintaining
state, as opposed to a full power-off (deactivate) and power-on (activate) of the card.

The pySim command just sends that SUSPEND UICC command and doesn't perform the full related sequence
including the electrical power down.

.. argparse::
   :module: pySim.ts_102_221
   :func: CardProfileUICC.AddlShellCommands.suspend_uicc_parser

resume_uicc
~~~~~~~~~~~
This command allows you to perform the SUSPEND UICC command for the RESUME operation on the card.

Suspend/Resume is a relatively recent power-saving addition to the UICC specifications, allowing for
suspend/resume while maintaining state, as opposed to a full power-off (deactivate) and power-on
(activate) of the card.

The pySim command just sends that SUSPEND UICC (RESUME) command and doesn't perform the full related
sequence including the electrical power down.

.. argparse::
   :module: pySim.ts_102_221
   :func: CardProfileUICC.AddlShellCommands.resume_uicc_parser

terminal_capability
~~~~~~~~~~~~~~~~~~~
This command allows you to perform the TERMINAL CAPABILITY command towards the card.

TS 102 221 specifies the TERMINAL CAPABILITY command using which the
terminal (Software + hardware talking to the card) can expose their
capabilities.  This is also used in the eUICC universe to let the eUICC
know which features are supported.

.. argparse::
   :module: pySim.ts_102_221
   :func: CardProfileUICC.AddlShellCommands.term_cap_parser


Linear Fixed EF commands
------------------------

These commands become enabled only when your currently selected file is of *Linear Fixed EF* type.

read_record
~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: LinFixedEF.ShellCommands.read_rec_parser


read_record_decoded
~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: LinFixedEF.ShellCommands.read_rec_dec_parser

If this command fails, it means that the record is not decodable, and you should use the :ref:`read_record`
command and proceed with manual decoding of the contents.


read_records
~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: LinFixedEF.ShellCommands.read_recs_parser


read_records_decoded
~~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: LinFixedEF.ShellCommands.read_recs_dec_parser

If this command fails, it means that the record[s] are not decodable, and you should use the :ref:`read_records`
command and proceed with manual decoding of the contents.


update_record
~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: LinFixedEF.ShellCommands.upd_rec_parser


update_record_decoded
~~~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: LinFixedEF.ShellCommands.upd_rec_dec_parser

If this command fails, it means that the record is not encodable; please check your input and/or use the raw
:ref:`update_record` command.


edit_record_decoded
~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: LinFixedEF.ShellCommands.edit_rec_dec_parser

This command will read the selected record, decode it to its JSON representation, save
that JSON to a temporary file on your computer, and launch your configured text editor.

You may then perform whatever modifications to the JSON representation, save + leave your
text editor.

Afterwards, the modified JSON will be re-encoded to the binary format, and the result written
back to the record on the SIM card.

This allows for easy interactive modification of records.

If this command fails before the editor is spawned, it means that the current record contents is not decodable,
and you should use the :ref:`update_record_decoded` or :ref:`update_record` command.

If this command fails after making your modificatiosn in the editor, it means that the new file contents is not
encodable; please check your input and/or us the raw :ref:`update_record` comamdn.


decode_hex
~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: LinFixedEF.ShellCommands.dec_hex_parser



Transparent EF commands
-----------------------

These commands become enabled only when your currently selected file is of *Transparent EF* type.


read_binary
~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: TransparentEF.ShellCommands.read_bin_parser


read_binary_decoded
~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: TransparentEF.ShellCommands.read_bin_dec_parser

If this command fails, it means that the file is not decodable, and you should use the :ref:`read_binary`
command and proceed with manual decoding of the contents.

update_binary
~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: TransparentEF.ShellCommands.upd_bin_parser


update_binary_decoded
~~~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: TransparentEF.ShellCommands.upd_bin_dec_parser

In normal operation, update_binary_decoded needs a JSON document representing the entire file contents as
input.  This can be inconvenient if you want to keep 99% of the content but just toggle one specific
parameter.   That's where the JSONpath support comes in handy:  You can specify a JSONpath to an element
inside the document as well as a new value for tat field:

The below example demonstrates this by modifying the ciphering indicator field within EF.AD:

::

  pySIM-shell (00:MF/ADF.USIM/EF.AD)> read_binary_decoded

  {
      "ms_operation_mode": "normal_and_specific_facilities",
      "additional_info": {
          "ciphering_indicator": false,
          "csg_display_control": false,
          "prose_services": false,
          "extended_drx": true
      },
      "rfu": 0,
      "mnc_len": 2,
      "extensions": "ff"
  }
  pySIM-shell (00:MF/ADF.USIM/EF.AD)> update_binary_decoded --json-path additional_info.ciphering_indicator true
  "01000902ff"
  pySIM-shell (00:MF/ADF.USIM/EF.AD)> read_binary_decoded
  {
      "ms_operation_mode": "normal_and_specific_facilities",
      "additional_info": {
          "ciphering_indicator": true,
          "csg_display_control": false,
          "prose_services": false,
          "extended_drx": true
      },
      "rfu": 0,
      "mnc_len": 2,
      "extensions": "ff"
  }

If this command fails, it means that the file is not encodable; please check your input and/or use the raw
:ref:`update_binary` command.


edit_binary_decoded
~~~~~~~~~~~~~~~~~~~
This command will read the selected binary EF, decode it to its JSON representation, save
that JSON to a temporary file on your computer, and launch your configured text editor.

You may then perform whatever modifications to the JSON representation, save + leave your
text editor.

Afterwards, the modified JSON will be re-encoded to the binary format, and the result written
to the SIM card.

This allows for easy interactive modification of file contents.

If this command fails before the editor is spawned, it means that the current file contents is not decodable,
and you should use the :ref:`update_binary_decoded` or :ref:`update_binary` command.

If this command fails after making your modificatiosn in the editor, it means that the new file contents is not
encodable; please check your input and/or us the raw :ref:`update_binary` comamdn.


decode_hex
~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: TransparentEF.ShellCommands.dec_hex_parser



BER-TLV EF commands
-------------------

BER-TLV EFs are files that contain BER-TLV structured data.  Every file can contain any number
of variable-length IEs (DOs).  The tag within a BER-TLV EF must be unique within the file.

The commands below become enabled only when your currently selected file is of *BER-TLV EF* type.

retrieve_tags
~~~~~~~~~~~~~

Retrieve a list of all tags present in the currently selected file.


retrieve_data
~~~~~~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: BerTlvEF.ShellCommands.retrieve_data_parser


set_data
~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: BerTlvEF.ShellCommands.set_data_parser


del_data
~~~~~~~~
.. argparse::
   :module: pySim.filesystem
   :func: BerTlvEF.ShellCommands.del_data_parser



USIM commands
-------------

These commands are available only while ADF.USIM (or ADF.ISIM, respectively) is selected.

authenticate
~~~~~~~~~~~~
.. argparse::
   :module: pySim.ts_31_102
   :func: ADF_USIM.AddlShellCommands.authenticate_parser

terminal_profile
~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.ts_31_102
   :func: ADF_USIM.AddlShellCommands.term_prof_parser

envelope
~~~~~~~~
.. argparse::
   :module: pySim.ts_31_102
   :func: ADF_USIM.AddlShellCommands.envelope_parser

envelope_sms
~~~~~~~~~~~~
.. argparse::
   :module: pySim.ts_31_102
   :func: ADF_USIM.AddlShellCommands.envelope_sms_parser

get_identity
~~~~~~~~~~~~
.. argparse::
   :module: pySim.ts_31_102
   :func: ADF_USIM.AddlShellCommands.get_id_parser


File-specific commands
----------------------

These commands are valid only if the respective file is currently selected.  They perform some
operation that's specific to this file only.

EF.ARR: read_arr_record
~~~~~~~~~~~~~~~~~~~~~~~
Read one EF.ARR record in flattened, human-friendly form.

EF.ARR: read_arr_records
~~~~~~~~~~~~~~~~~~~~~~~~
Read + decode all EF.ARR records in flattened, human-friendly form.

DF.GSM/EF.SST: sst_service_allocate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Mark a given single service as allocated in EF.SST.  Requires service number as argument.

DF.GSM/EF.SST: sst_service_activate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Mark a given single service as activated in EF.SST.  Requires service number as argument.

DF.GSM/EF.SST: sst_service_deallocate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Mark a given single service as deallocated in EF.SST.  Requires service number as argument.

DF.GSM/EF.SST: sst_service_deactivate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Mark a given single service as deactivated in EF.SST.  Requires service number as argument.

ADF.USIM/EF.EST: est_service_enable
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Enables a single service in EF.EST.  Requires service number as argument.

ADF.USIM/EF.EST: est_service_disable
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Disables a single service in EF.EST.  Requires service number as argument.

EF.IMSI: update_imsi_plmn
~~~~~~~~~~~~~~~~~~~~~~~~~
Change the PLMN part (MCC+MNC) of the IMSI.  Requires a single argument consisting of 5/6 digits of
concatenated MCC+MNC.

ADF.USIM/EF.UST: ust_service_activate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Activates a single service in EF.UST.  Requires service number as argument.

ADF.USIM/EF.UST: ust_service_deactivate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deactivates a single service in EF.UST.  Requires service number as argument.

ADF.USIM/EF.UST: ust_service_check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Check consistency between services of this file and files present/activated.
Many services determine if one or multiple files shall be present/activated or if they shall be
absent/deactivated.  This performs a consistency check to ensure that no services are activated
for files that are not - and vice-versa, no files are activated for services that are not.  Error
messages are printed for every inconsistency found.

ADF.ISIM/EF.IST: ist_service_activate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Activates a single service in EF.IST.  Requires service number as argument.

ADF.ISIM/EF.IST: ist_service_deactivate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deactivates a single service in EF.UST.  Requires service number as argument.

ADF.ISIM/EF.IST: ist_service_check
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Check consistency between services of this file and files present/activated.
Many services determine if one or multiple files shall be present/activated or if they shall be
absent/deactivated.  This performs a consistency check to ensure that no services are activated
for files that are not - and vice-versa, no files are activated for services that are not.  Error
messages are printed for every inconsistency found.


UICC Administrative commands
----------------------------

ETSI TS 102 222 specifies a set of *Administrative Commands*, which can
be used by the card issuer / operator to modify the file system structure
(delete files, create files) or even to terminate individual files or the
entire card.

pySim-shell supports those commands, but **use extreme caution**.
Unless you know exactly what you're doing, it's very easy to render your
card unusable.  You've been warned!

delete_file
~~~~~~~~~~~
.. argparse::
   :module: pySim.ts_102_222
   :func: Ts102222Commands.delfile_parser


terminate_df
~~~~~~~~~~~~
.. argparse::
   :module: pySim.ts_102_222
   :func: Ts102222Commands.termdf_parser

terminate_ef
~~~~~~~~~~~~
.. argparse::
   :module: pySim.ts_102_222
   :func: Ts102222Commands.termdf_parser

terminate_card
~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.ts_102_222
   :func: Ts102222Commands.tcard_parser

create_ef
~~~~~~~~~
.. argparse::
   :module: pySim.ts_102_222
   :func: Ts102222Commands.create_parser

create_df
~~~~~~~~~
.. argparse::
   :module: pySim.ts_102_222
   :func: Ts102222Commands.createdf_parser

resize_ef
~~~~~~~~~
.. argparse::
   :module: pySim.ts_102_222
   :func: Ts102222Commands.resize_ef_parser


ARA-M commands
--------------

The ARA-M commands exist to manage the access rules stored in an ARA-M applet on the card.

ARA-M in the context of SIM cards is primarily used to enable Android UICC Carrier Privileges,
please see https://source.android.com/devices/tech/config/uicc for more details on the background.


aram_get_all
~~~~~~~~~~~~

Obtain and decode all access rules from the ARA-M applet on the card.

NOTE: if the total size of the access rules exceeds 255 bytes, this command will fail, as
it doesn't yet implement fragmentation/reassembly on rule retrieval. YMMV

::

  pySIM-shell (00:MF/ADF.ARA-M)> aram_get_all

  [
      {
          "response_all_ref_ar_do": [
              {
                  "ref_ar_do": [
                      {
                          "ref_do": [
                              {
                                  "aid_ref_do": "ffffffffffff"
                              },
                              {
                                  "dev_app_id_ref_do": "e46872f28b350b7e1f140de535c2a8d5804f0be3"
                              }
                          ]
                      },
                      {
                          "ar_do": [
                              {
                                  "apdu_ar_do": {
                                      "generic_access_rule": "always"
                                  }
                              },
                              {
                                  "perm_ar_do": {
                                      "permissions": "0000000000000001"
                                  }
                              }
                          ]
                      }
                  ]
              }
          ]
      }
  ]

aram_get_config
~~~~~~~~~~~~~~~
Perform Config handshake with ARA-M applet: Tell it our version and retrieve its version.

NOTE: Not supported in all ARA-M implementations.


aram_store_ref_ar_do
~~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.ara_m
   :func: ADF_ARAM.AddlShellCommands.store_ref_ar_do_parse

For example, to store an Android UICC carrier privilege rule for the SHA1 hash of the certificate used to sign the CoIMS android app of Supreeth Herle (https://github.com/herlesupreeth/CoIMS_Wiki) you can use the following command:
::

  pySIM-shell (00:MF/ADF.ARA-M)> aram_store_ref_ar_do --aid FFFFFFFFFFFF --device-app-id E46872F28B350B7E1F140DE535C2A8D5804F0BE3 --android-permissions 0000000000000001 --apdu-always


aram_delete_all
~~~~~~~~~~~~~~~
This command will request deletion of all access rules stored within the
ARA-M applet.  Use it with caution, there is no undo.  Any rules later
intended must be manually inserted again using :ref:`aram_store_ref_ar_do`


GlobalPlatform commands
-----------------------

pySim-shell has only the mots rudimentary support for GlobalPlatform at this point. Please use dedicated
projects like GlobalPlatformPro meanwhile.

get_data
~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.get_data_parser

get_status
~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.get_status_parser

set_status
~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.set_status_parser

store_data
~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.store_data_parser

put_key
~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.put_key_parser

delete_key
~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.del_key_parser

load
~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.load_parser

install_cap
~~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.install_cap_parser

install_for_personalization
~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.inst_perso_parser

install_for_install
~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.inst_inst_parser

install_for_load
~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.inst_load_parser

delete_card_content
~~~~~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.del_cc_parser

establish_scp02
~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.est_scp02_parser

establish_scp03
~~~~~~~~~~~~~~~
.. argparse::
   :module: pySim.global_platform
   :func: ADF_SD.AddlShellCommands.est_scp03_parser

release_scp
~~~~~~~~~~~
Release any previously established SCP (Secure Channel Protocol)


eUICC ISD-R commands
--------------------

These commands are to perform a variety of operations against eUICC for GSMA consumer eSIM. They
implement the so-called ES10a, ES10b and ES10c interface.  Basically they perform the tasks that usually would
be done by the LPAd in the UE.

In order to use those commands, you need to go through the specified steps as documented in GSMA SGP.22:

* open a new logical channel (and start to use it)
* select the ISD-R application

Example::

  pySIM-shell (00:MF)> open_channel 2
  pySIM-shell (00:MF)> switch_channel 2
  pySIM-shell (02:MF)> select ADF.ISD-R
  {
      "application_id": "a0000005591010ffffffff8900000100",
      "proprietary_data": {
          "maximum_length_of_data_field_in_command_message": 255
      },
      "isdr_proprietary_application_template": {
          "supported_version_number": "020200"
      }
  }
  pySIM-shell (02:ADF.ISD-R)>

Once you are at this stage, you can issue the various eUICC related commands against the ISD-R application


es10x_store_data
~~~~~~~~~~~~~~~~

.. argparse::
   :module: pySim.euicc
   :func: CardApplicationISDR.AddlShellCommands.es10x_store_data_parser

get_euicc_configured_addresses
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Obtain the configured SM-DP+ and/or SM-DS addresses using the ES10a GetEuiccConfiguredAddresses() function.

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> get_euicc_configured_addresses
  {
      "root_ds_address": "testrootsmds.gsma.com"
  }

set_default_dp_address
~~~~~~~~~~~~~~~~~~~~~~

.. argparse::
   :module: pySim.euicc
   :func: CardApplicationISDR.AddlShellCommands.set_def_dp_addr_parser

get_euicc_challenge
~~~~~~~~~~~~~~~~~~~

Obtain an authentication challenge from the eUICC using the ES10b GetEUICCChallenge() function.

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> get_euicc_challenge
  {
      "euicc_challenge": "3668f20d4e6c8e85609bbca8c14873fd"
  }

get_euicc_info1
~~~~~~~~~~~~~~~

Obtain EUICC Information (1) from the eUICC using the ES10b GetEUICCCInfo() function.

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> get_euicc_info1
  {
      "svn": "2.2.0",
      "euicc_ci_pki_list_for_verification": [
          {
              "subject_key_identifier_seq": {
                  "unknown_ber_tlv_ie_c0": null
              }
          },
          {
              "subject_key_identifier_seq": {
                  "unknown_ber_tlv_ie_f5": {
                      "raw": "72bdf98a95d65cbeb88a38a1c11d800a85c3"
                  }
              }
          }
      ],
      "euicc_ci_pki_list_for_signing": [
          {
              "subject_key_identifier_seq": {
                  "unknown_ber_tlv_ie_c0": null
              }
          },
          {
              "subject_key_identifier_seq": {
                  "unknown_ber_tlv_ie_f5": {
                      "raw": "72bdf98a95d65cbeb88a38a1c11d800a85c3"
                  }
              }
          }
      ]
  }


get_euicc_info2
~~~~~~~~~~~~~~~

Obtain EUICC Information (2) from the eUICC using the ES10b GetEUICCCInfo() function.

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> get_euicc_info2
  {
      "profile_version": "2.1.0",
      "svn": "2.2.0",
      "euicc_firmware_ver": "4.4.0",
      "ext_card_resource": "81010082040006ddc68304000016e0",
      "uicc_capability": "067f36c0",
      "ts102241_version": "9.2.0",
      "global_platform_version": "2.3.0",
      "rsp_capability": "0490",
      "euicc_ci_pki_list_for_verification": [
          {
              "subject_key_identifier_seq": {
                  "unknown_ber_tlv_ie_c0": null
              }
          },
          {
              "subject_key_identifier_seq": {
                  "unknown_ber_tlv_ie_f5": {
                      "raw": "72bdf98a95d65cbeb88a38a1c11d800a85c3"
                  }
              }
          }
      ],
      "euicc_ci_pki_list_for_signing": [
          {
              "subject_key_identifier_seq": {
                  "unknown_ber_tlv_ie_c0": null
              }
          },
          {
              "subject_key_identifier_seq": {
                  "unknown_ber_tlv_ie_f5": {
                      "raw": "72bdf98a95d65cbeb88a38a1c11d800a85c3"
                  }
              }
          }
      ],
      "unknown_ber_tlv_ie_99": {
          "raw": "06c0"
      },
      "pp_version": "0.0.1",
      "ss_acreditation_number": "G&DAccreditationNbr",
      "unknown_ber_tlv_ie_ac": {
          "raw": "801f312e322e3834302e313233343536372f6d79506c6174666f726d4c6162656c812568747470733a2f2f6d79636f6d70616e792e636f6d2f6d79444c4f41526567697374726172"
      }
  }


list_notification
~~~~~~~~~~~~~~~~~

Obtain the list of notifications from the eUICC using the ES10b ListNotification() function.

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> list_notification
  {
      "notification_metadata_list": {
          "notification_metadata": {
              "seq_number": 61,
              "profile_mgmt_operation": {
                  "pmo": {
                      "install": true,
                      "enable": false,
                      "disable": false,
                      "delete": false
                  }
              },
              "notification_address": "testsmdpplus1.example.com",
              "iccid": "89000123456789012358"
          }
      }
  }


remove_notification_from_list
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. argparse::
   :module: pySim.euicc
   :func: CardApplicationISDR.AddlShellCommands.rem_notif_parser

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> remove_notification_from_list 60
  {
      "delete_notification_status": "ok"
  }


get_profiles_info
~~~~~~~~~~~~~~~~~

Obtain information about the profiles present on the eUICC using the ES10c GetProfilesInfo() function.

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> get_profiles_info
  {
      "profile_info_seq": [
          {
              "profile_info": {
                  "iccid": "89000123456789012341",
                  "isdp_aid": "a0000005591010ffffffff8900001100",
                  "profile_state": "disabled",
                  "service_provider_name": "GSMA Test 1A",
                  "profile_name": "GSMA Generic eUICC Test Profile 1A",
                  "profile_class": "operational"
              }
          },
          {
              "profile_info": {
                  "iccid": "89000123456789012358",
                  "isdp_aid": "a0000005591010ffffffff8900001200",
                  "profile_state": "disabled",
                  "service_provider_name": "OsmocomSPN",
                  "profile_name": "OsmocomProfile",
                  "profile_class": "operational"
              }
          }
      ]
  }


enable_profile
~~~~~~~~~~~~~~

.. argparse::
   :module: pySim.euicc
   :func: CardApplicationISDR.AddlShellCommands.en_prof_parser

Example (successful)::

  pySIM-shell (00:MF/ADF.ISD-R)> enable_profile --iccid 89000123456789012358
  {
      "enable_result": "ok"
  }


Example (failed attempt enabling a profile that's already enabled)::

  pySIM-shell (00:MF/ADF.ISD-R)> enable_profile --iccid 89000123456789012358
  {
      "enable_result": "profileNotInDisabledState"
  }

disable_profile
~~~~~~~~~~~~~~~

.. argparse::
   :module: pySim.euicc
   :func: CardApplicationISDR.AddlShellCommands.dis_prof_parser

Example (successful)::

  pySIM-shell (00:MF/ADF.ISD-R)> disable_profile --iccid 89000123456789012358
  {
      "disable_result": "ok"
  }

delete_profile
~~~~~~~~~~~~~~

.. argparse::
   :module: pySim.euicc
   :func: CardApplicationISDR.AddlShellCommands.del_prof_parser

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> delete_profile --iccid 89000123456789012358
  {
      "delete_result": "ok"
  }

euicc_memory_reset
~~~~~~~~~~~~~~~~~~

.. argparse::
   :module: pySim.euicc
   :func: CardApplicationISDR.AddlShellCommands.mem_res_parser


get_eid
~~~~~~~

Obtain the EID of the eUICC using the ES10c GetEID() function.

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> get_eid
  {
      "eid_value": "89049032123451234512345678901235"
  }

set_nickname
~~~~~~~~~~~~

.. argparse::
   :module: pySim.euicc
   :func: CardApplicationISDR.AddlShellCommands.set_nickname_parser

Example::

  pySIM-shell (00:MF/ADF.ISD-R)> set_nickname --profile-nickname asdf 89000123456789012358
  {
      "set_nickname_result": "ok"
  }


get_certs
~~~~~~~~~

Obtain the certificates from an IoT eUICC using the ES10c GetCerts() function.

get_eim_configuration_data
~~~~~~~~~~~~~~~~~~~~~~~~~~

Obtain the eIM configuration data from an IoT eUICC using the ES10b GetEimConfigurationData() function.


cmd2 settable parameters
------------------------

``cmd2`` has the concept of *settable parameters* which act a bit like environment variables in an OS-level
shell: They can be read and set, and they will influence the behavior somehow.

conserve_write
~~~~~~~~~~~~~~

If enabled, pySim will (when asked to write to a card) always first read the respective file/record and
verify if the to-be-written value differs from the current on-card value.  If not, the write will be skipped.
Writes will only be performed if the new value is different from the current on-card value.

If disabled, pySim will always write irrespective of the current/new value.

json_pretty_print
~~~~~~~~~~~~~~~~~

This parameter determines if generated JSON output should (by default) be pretty-printed (multi-line
output with indent level of 4 spaces) or not.

The default value of this parameter is 'true'.

debug
~~~~~

If enabled, full python back-traces will be displayed in case of exceptions

apdu_trace
~~~~~~~~~~

Boolean variable that determines if a hex-dump of the command + response APDU shall be printed.

numeric_path
~~~~~~~~~~~~

Boolean variable that determines if path (e.g. in prompt) is displayed with numeric FIDs or string names.

::

  pySIM-shell (00:MF/EF.ICCID)> set numeric_path True
  numeric_path - was: False
  now: True
  pySIM-shell (00:3f00/2fe2)> set numeric_path False
  numeric_path - was: True
  now: False
  pySIM-shell (00:MF/EF.ICCID)> help set
