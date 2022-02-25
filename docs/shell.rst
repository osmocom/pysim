pySim-shell
===========

pySim-shell is an interactive command line shell for all kind of interactions with SIM cards.

The interactive shell provides command for

* navigating the on-card filesystem hierarchy
* authenticating with PINs such as ADM1
* CHV/PIN management (VERIFY, ENABLE, DISABLE, UNBLOCK)
* decoding of SELECT response (file control parameters)
* reading and writing of files and records in raw, hex-encoded binary format
* for some files where related support has been developed:

 * decoded reading (display file data in JSON format)
 * decoded writing (encode from JSON to binary format, then write)

By means of using the python ``cmd2`` module, various useful features improve usability:

* history of commands (persistent across restarts)
* output re-direction to files on your computer
* output piping through external tools like 'grep'
* tab completion of commands and SELECT-able files/directories
* interactive help for all commands

Running pySim-shell
-------------------

pySim-shell has a variety of command line arguments to control

* which transport to use (how to use a reader to talk to the SIM card)
* whether to automatically verify an ADM pin (and in which format)
* whether to execute a start-up script

.. argparse::
   :module: pySim-shell
   :func: option_parser



cmd2 basics
-----------

FIXME



ISO7816 commands
----------------

This category of commands relates to commands that originate in the ISO 7861-4 specifications,
most of them have a 1:1 resemblance in the specification.

select
~~~~~~

The ``select`` command is used to select a file, either by its FID, AID or by its symbolic name.

Try ``select`` with tab-completion to get a list of all current selectable items:

::

  pySIM-shell (MF)> select
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

  pySIM-shell (MF)> select ADF.USIM
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
      "pin_status_template_do": "90017083010183018183010A83010B"
  }
  pySIM-shell (MF/ADF.USIM)>


status
~~~~~~

The ``status`` command [re-]obtains the File Control Template of the
currently-selected file and print its decoded output.

Example:

::

  pySIM-shell (MF/ADF.ISIM)> status
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
Deactivate the currently selected file.  This used to be called INVALIDATE in TS 11.11.


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


suspend_uicc
~~~~~~~~~~~~
This command allows you to perform the SUSPEND UICC command on the card.  This is a relatively
recent power-saving addition to the UICC specifications, allowing for suspend/resume while maintaining
state, as opposed to a full power-off (deactivate) and power-on (activate) of the card.

The pySim command just sends that SUSPEND UICC command and doesn't perform the full related sequence
including the electrical power down.

.. argparse::
   :module: pySim-shell
   :func: Iso7816Commands.suspend_uicc_parser



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

  pySIM-shell (MF)> dir
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


tree
~~~~
Display a tree of the card filesystem.  It is important to note that this displays a tree
of files that might potentially exist (based on the card profile).  In order to determine if
a given file really exists on a given card, you have to try to select that file.

Example:
::

  pySIM-shell (MF)> tree --help
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
Verify the ADM (Administrator) PIN specified as argument.  This is typically needed in order
to get write/update permissions to most of the files on SIM cards.

Currently only ADM1 is supported.


reset
~~~~~
Perform card reset and display the card ATR.

intro
~~~~~
[Re-]Display the introductory banner


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
   :func: PySimCommands.apdu_cmd_parser



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

Th below example demonstrates this by modifying the ofm field within EF.AD:

::

  pySIM-shell (MF/ADF.USIM/EF.AD)> read_binary_decoded
  {
      "ms_operation_mode": "normal",
      "specific_facilities": {
          "ofm": true
      },
      "len_of_mnc_in_imsi": 2
  }
  pySIM-shell (MF/ADF.USIM/EF.AD)> update_binary_decoded --json-path specific_facilities.ofm false
  pySIM-shell (MF/ADF.USIM/EF.AD)> read_binary_decoded
  {
      "ms_operation_mode": "normal",
      "specific_facilities": {
          "ofm": false
      },
      "len_of_mnc_in_imsi": 2
  }


edit_binary_decoded
~~~~~~~~~~~~~~~~~~~
This command will read the selected binary EF, decode it to its JSON representation, save
that JSON to a temporary file on your computer, and launch your configured text editor.

You may then perform whatever modifications to the JSON representation, save + leave your
text editor.

Afterwards, the modified JSON will be re-encoded to the binary format, and the result written
to the SIM card.

This allows for easy interactive modification of file contents.


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

  pySIM-shell (MF/ADF.ARA-M)> aram_get_all
  [
      {
          "ResponseAllRefArDO": [
              {
                  "RefArDO": [
                      {
                          "RefDO": [
                              {
                                  "AidRefDO": "ffffffffffff"
                              },
                              {
                                  "DevAppIdRefDO": "e46872f28b350b7e1f140de535c2a8d5804f0be3"
                              }
                          ]
                      },
                      {
                          "ArDO": [
                              {
                                  "ApduArDO": {
                                      "generic_access_rule": "always"
                                  }
                              },
                              {
                                  "PermArDO": {
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

  pySIM-shell (MF/ADF.ARA-M)> aram_store_ref_ar_do --aid FFFFFFFFFFFF --device-app-id E46872F28B350B7E1F140DE535C2A8D5804F0BE3 --android-permissions 0000000000000001 --apdu-always


aram_delete_all
~~~~~~~~~~~~~~~
This command will request deletion of all access rules stored within the
ARA-M applet.  Use it with caution, there is no undo.  Any rules later
intended must be manually inserted again using `aram_store_ref_ar_do`



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

  pySIM-shell (MF/EF.ICCID)> set numeric_path True
  numeric_path - was: False
  now: True
  pySIM-shell (3f00/2fe2)> set numeric_path False
  numeric_path - was: True
  now: False
  pySIM-shell (MF/EF.ICCID)> help set
