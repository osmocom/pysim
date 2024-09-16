Legacy tools
============

*legacy tools* are the classic ``pySim-prog`` and ``pySim-read`` programs that
existed long before ``pySim-shell``.

These days, it is highly recommended to use ``pySim-shell`` instead of these
legacy tools.

pySim-prog
----------

``pySim-prog`` was the first part of the pySim software suite. It started as a
tool to write ICCID, IMSI, MSISDN and Ki to very simplistic SIM cards, and was
later extended to a variety of other cards. As the number of features supported
became no longer bearable to express with command-line arguments, `pySim-shell`
was created.

Basic use cases can still use `pySim-prog`.

Program customizable SIMs
~~~~~~~~~~~~~~~~~~~~~~~~~
Two modes are possible:

  - one where the user specifies every parameter manually:

    This is the most common way to use ``pySim-prog``. The user will specify all relevant parameters directly via the
    commandline. A typical commandline would look like this:

    ``pySim-prog.py -p <pcsc_reader> --ki <ki_value> --opc <opc_value> --mcc <mcc_value> --mnc <mnc_value>
    --country <country_code> --imsi <imsi_value> --iccid <iccid_value> --pin-adm <adm_pin>``

    Please note, that this already lengthy commandline still only contains the most common card parameters. For a full
    list of all possible parameters, use the ``--help`` option of ``pySim-prog``. It is also important to mention
    that not all parameters are supported by all card types. In particular, very simple programmable SIM cards will only
    support a very basic set of parameters, such as MCC, MNC, IMSI and KI values.

  - one where the parameters are generated from a minimal set:

    It is also possible to leave the generation of certain parameters to ``pySim-prog``. This is in particular helpful
    when a large number of cards should be initialized with randomly generated key material.

    ``pySim-prog.py -p <pcsc_reader> --mcc <mcc_value> --mnc <mnc_value> --secret <random_secret> --num <card_number> --pin-adm <adm_pin>``

    The parameter ``--secret`` specifies a random seed that is used to generate the card individual parameters. (IMSI).
    The secret should contain enough randomness to avoid conflicts. It is also recommended to store the secret safely,
    in case cards have to be re-generated or the current card batch has to be extended later. For security reasons, the
    key material, which is also card individual, will not be derived from the random seed. Instead a new random set of
    Ki and OPc will be generated during each programming cycle. This means fresh keys are generated, even when the
    ``--num`` remains unchanged.

    The parameter ``--num`` specifies a card individual number. This number will be manged into the random seed so that
    it serves as an identifier for a particular set of randomly generated parameters.

    In the example above the parameters ``--mcc``, and ``--mnc`` are specified as well, since they identify the GSM
    network where the cards should operate in, it is absolutely required to keep them static. ``pySim-prog`` will use
    those parameters to generate a valid IMSI that thas the specified MCC/MNC at the beginning and a random tail.

Specifying the card type:

``pySim-prog`` usually autodetects the card type. In case auto detection does not work, it is possible to specify
the parameter ``--type``. The following card types are supported:

 * Fairwaves-SIM
 * fakemagicsim
 * gialersim
 * grcardsim
 * magicsim
 * OpenCells-SIM
 * supersim
 * sysmoISIM-SJA2
 * sysmoISIM-SJA5
 * sysmosim-gr1
 * sysmoSIM-GR2
 * sysmoUSIM-SJS1
 * Wavemobile-SIM

Specifying the card reader:

It is most common to use ``pySim-prog`` together whith a PCSC reader. The PCSC reader number is specified via the
``--pcsc-device`` or ``-p`` option. However, other reader types (such as serial readers and modems) are supported. Use
the ``--help`` option of ``pySim-prog`` for more information.


Card programming using CSV files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To simplify the card programming process, ``pySim-prog`` also allows to read
the card parameters from a CSV file. When a CSV file is used as input, the
user does not have to craft an individual commandline for each card. Instead
all card related parameters are automatically drawn from the CSV file.

A CSV files may hold rows for multiple (hundreds or even thousands) of
cards. ``pySim-prog`` is able to identify the rows either by ICCID
(recommended as ICCIDs are normally not changed) or IMSI.

The CSV file format is a flexible format with mandatory and optional columns,
here the same rules as for the commandline parameters apply. The column names
match the command line options. The CSV file may also contain columns that are
unknown to pySim-prog, such as inventory numbers, nicknames or parameters that
are unrelated to the card programming process. ``pySim-prog`` will silently
ignore all unknown columns.

A CSV file may contain the following columns:

* name
* iccid (typically used as key)
* mcc
* mnc
* imsi (may be used as key, but not recommended)
* smsp
* ki
* opc
* acc
* pin_adm, adm1 or pin_adm_hex (must be present)
* msisdn
* epdgid
* epdgSelection
* pcscf
* ims_hdomain
* impi
* impu
* opmode
* fplmn

Due to historical reasons, and to maintain the compatibility between multiple different CSV file formats, the ADM pin
may be stored in three different columns. Only one of the three columns must be available.

* adm1: This column contains the ADM pin in numeric ASCII digit format. This format is the most common.
* pin_adm: Same as adm1, only the column name is different
* pin_adm_hex: If the ADM pin consists of raw HEX digits, rather then of numerical ASCII digits, then the ADM pin
  can also be provided as HEX string using this column.

The following example shows a typical minimal example
::

   "imsi","iccid","acc","ki","opc","adm1"
   "999700000053010","8988211000000530108","0001","51ACE8BD6313C230F0BFE1A458928DF0","E5A00E8DE427E21B206526B5D1B902DF","65942330"
   "999700000053011","8988211000000530116","0002","746AAFD7F13CFED3AE626B770E53E860","38F7CE8322D2A7417E0BBD1D7B1190EC","13445792"
   "999700123053012","8988211000000530124","0004","D0DA4B7B150026ADC966DC637B26429C","144FD3AEAC208DFFF4E2140859BAE8EC","53540383"
   "999700000053013","8988211000000530132","0008","52E59240ABAC6F53FF5778715C5CE70E","D9C988550DC70B95F40342298EB84C5E","26151368"
   "999700000053014","8988211000000530140","0010","3B4B83CB9C5F3A0B41EBD17E7D96F324","D61DCC160E3B91F284979552CC5B4D9F","64088605"
   "999700000053015","8988211000000530157","0020","D673DAB320D81039B025263610C2BBB3","4BCE1458936B338067989A06E5327139","94108841"
   "999700000053016","8988211000000530165","0040","89DE5ACB76E06D14B0F5D5CD3594E2B1","411C4B8273FD7607E1885E59F0831906","55184287"
   "999700000053017","8988211000000530173","0080","977852F7CEE83233F02E69E211626DE1","2EC35D48DBF2A99C07D4361F19EF338F","70284674"

::

The following commandline will instruct ``pySim-prog`` to use the provided CSV file as parameter source and the
ICCID (read from the card before programming) as a key to identify the card. To use the IMSI as a key, the parameter
``--read-imsi`` can be used instead of ``--read-iccid``. However, this option is only recommended to be used in very
specific corner cases.

``pySim-prog.py -p <pcsc_reader> --read-csv <path_to_csv_file> --source csv --read-iccid``

It is also possible to pick a row from the CSV file by manually providing an ICCID (option ``--iccid``) or an IMSI
(option ``--imsi``) that is then used as a key to find the matching row in the CSV file.

``pySim-prog.py -p <pcsc_reader> --read-csv <path_to_csv_file> --source csv --iccid <iccid_value>``


Writing CSV files
~~~~~~~~~~~~~~~~~
``pySim-prog`` is also able to generate CSV files that contain a subset of the parameters it has generated or received
from some other source (commandline, CSV-File). The generated file will be header-less and contain the following
columns:

* name
* iccid
* mcc
* mnc
* imsi
* smsp
* ki
* opc

A commandline that makes use of the CSV write feature would look like this:

``pySim-prog.py -p <pcsc_reader> --read-csv <path_to_input_csv_file> --read-iccid --source csv --write-csv <path_to_output_csv_file>``


Batch programming
~~~~~~~~~~~~~~~~~

In case larger card batches need to be programmed, it is possible to use the ``--batch`` parameter to run ``pySim-prog`` in batch mode.

The batch mode will prompt the user to insert a card. Once a card is detected in the reader, the programming is carried out. The user may then remove the card again and the process starts over. This allows for a quick and efficient card programming without permanent commandline interaction.


pySim-read
----------

``pySim-read`` allows to read some of the most important data items from a SIM
card. This means it will only read some files of the card, and will only read
files accessible to a normal user (without any special authentication)

These days, it is recommended to use the ``export`` command of ``pySim-shell``
instead. It performs a much more comprehensive export of all of the [standard]
files that can be found on the card. To get a human-readable decode instead of
the raw hex export, you can use ``export --json``.

Specifically, pySim-read will dump the following:

* MF

 * EF.ICCID

* DF.GSM

 * EF,IMSI
 * EF.GID1
 * EF.GID2
 * EF.SMSP
 * EF.SPN
 * EF.PLMNsel
 * EF.PLMNwAcT
 * EF.OPLMNwAcT
 * EF.HPLMNAcT
 * EF.ACC
 * EF.MSISDN
 * EF.AD
 * EF.SST

* ADF.USIM

 * EF.EHPLMN
 * EF.UST
 * EF.ePDGId
 * EF.ePDGSelection

* ADF.ISIM

 * EF.PCSCF
 * EF.DOMAIN
 * EF.IMPI
 * EF.IMPU
 * EF.UICCIARI
 * EF.IST


pySim-read usage
~~~~~~~~~~~~~~~~

.. argparse::
   :module: pySim-read
   :func: option_parser
   :prog: pySim-read.py
