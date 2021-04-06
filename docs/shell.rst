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
          "shareable": true,
          "file_type": "df",
          "structure": "no_info_given"
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



change_chv
~~~~~~~~~~

This command allows you to change a CHV (PIN).


disable_chv
~~~~~~~~~~~

This command allows you to disable a CHV (PIN).

enable_chv
~~~~~~~~~~

This command allows you to enable a CHV (PIN).


unblock_chv
~~~~~~~~~~~

This command allows you to unblock a CHV (PIN) using the PUK.

verify_chv
~~~~~~~~~~

This command allows you to verify a CHV (PIN), which is how the specifications call
it if you authenticate yourself with the said CHV/PIN.



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

::

  usage: dir [-h] [--fids] [--names] [--apps] [--all]

  Show a listing of files available in currently selected DF or MF

  optional arguments:
    -h, --help  show this help message and exit
    --fids      Show file identifiers
    --names     Show file names
    --apps      Show applications
    --all       Show all selectable identifiers and names


export
~~~~~~

tree
~~~~

verify_adm
~~~~~~~~~~



Linear Fixed EF commands
------------------------

These commands become enabled only when your currently selected file is of *Linear Fixed EF* type.

read_record
~~~~~~~~~~~

read_record_decoded
~~~~~~~~~~~~~~~~~~~

update_record
~~~~~~~~~~~~~

update_record_decoded
~~~~~~~~~~~~~~~~~~~~~



Transparent EF commands
-----------------------

These commands become enabled only when your currently selected file is of *Transparent EF* type.


read_binary
~~~~~~~~~~~

read_binary_decoded
~~~~~~~~~~~~~~~~~~~

update_binary
~~~~~~~~~~~~~

update_binary_decoded
~~~~~~~~~~~~~~~~~~~~~



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
