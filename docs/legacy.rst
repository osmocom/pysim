Legacy tools
============

*legacy tools* are the classic ``pySim-prog`` and ``pySim-read`` programs that
existed long before ``pySim-shell``.

pySim-prog
----------

``pySim-prog`` was the first part of the pySim software suite.  It started as
a tool to write ICCID, IMSI, MSISDN and Ki to very simplistic SIM cards, and
was later extended to a variety of other cards.  As the number of features supported
became no longer bearable to express with command-line arguments, `pySim-shell` was
created.

Basic use cases can still use `pySim-prog`.

Program customizable SIMs
~~~~~~~~~~~~~~~~~~~~~~~~~
Two modes are possible:

  - one where you specify every parameter manually :

``./pySim-prog.py -n 26C3 -c 49 -x 262 -y 42 -i <IMSI> -s <ICCID>``


  - one where they are generated from some minimal set :

``./pySim-prog.py -n 26C3 -c 49 -x 262 -y 42 -z <random_string_of_choice> -j <card_num>``

    With <random_string_of_choice> and <card_num>, the soft will generate
    'predictable' IMSI and ICCID, so make sure you choose them so as not to
    conflict with anyone. (for eg. your name as <random_string_of_choice> and
    0 1 2 ... for <card num>).

  You also need to enter some parameters to select the device :
   -t TYPE : type of card (supersim, magicsim, fakemagicsim or try 'auto')
   -d DEV  : Serial port device (default /dev/ttyUSB0)
   -b BAUD : Baudrate (default 9600)


pySim-read
----------

``pySim-read`` allows you to read some data from a SIM card.  It will only some files
of the card, and will only read files accessible to a normal user (without any special authentication)

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
