pySim-prog - Utility for programmable SIM/USIM-Cards
====================================================

This repository contains a Python-language program that can be used
to program (write) certain fields/parameters on so-called programmable
SIM/USIM cards.

Such SIM/USIM cards are special cards, which - unlike those issued by
regular commercial operators - come with the kind of keys that allow you
to write the files/fields that normally only an operator can program.

This is useful particularly if you are running your own cellular
network, and want to issue your own SIM/USIM cards for that network.


Homepage
--------

The official homepage of the project is
<http://osmocom.org/projects/pysim/wiki>

GIT Repository
--------------

You can clone from the official libosmocore.git repository using

	git clone git://git.osmocom.org/pysim.git

There is a cgit interface at <http://git.osmocom.org/pysim/>


Dependencies
------------

pysim requires:

- pyscard
- serial
- pytlv (for specific card types)

Example for Debian:

	apt-get install python-pyscard python-serial python-pip
	pip install pytlv


Mailing List
------------

There is no separate mailing list for this project.  However,
discussions related to pysim-prog are happening on the
openbsc@lists.osmocom.org mailing list, please see
<https://lists.osmocom.org/mailman/listinfo/openbsc> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We are currently accepting patches by e-mail to the above-mentioned
mailing list.

Usage
-----

 * Program customizable SIMs. Two modes are possible:

  - one where you specify every parameter manually :

./pySim-prog.py -n 26C3 -c 49 -x 262 -y 42 -i <IMSI> -s <ICCID>


  - one where they are generated from some minimal set :

./pySim-prog.py -n 26C3 -c 49 -x 262 -y 42 -z <random_string_of_choice> -j <card_num>

    With <random_string_of_choice> and <card_num>, the soft will generate
    'predictable' IMSI and ICCID, so make sure you choose them so as not to
    conflict with anyone. (for eg. your name as <random_string_of_choice> and
    0 1 2 ... for <card num>).

  You also need to enter some parameters to select the device :
   -t TYPE : type of card (supersim, magicsim, fakemagicsim or try 'auto')
   -d DEV  : Serial port device (default /dev/ttyUSB0)
   -b BAUD : Baudrate (default 9600)

 * Interact with SIMs from a python interactive shell (ipython for eg :)

from pySim.transport.serial import SerialSimLink
from pySim.commands import SimCardCommands

sl = SerialSimLink(device='/dev/ttyUSB0', baudrate=9600)
sc = SimCardCommands(sl)

sl.wait_for_card()

	# Print IMSI
print sc.read_binary(['3f00', '7f20', '6f07'])

	# Run A3/A8
print sc.run_gsm('00112233445566778899aabbccddeeff')
