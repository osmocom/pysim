pySim - Read, Write and Browse Programmable SIM/USIM Cards
====================================================

This repository contains Python programs that can be used
to read, program (write) and browse certain fields/parameters on so-called programmable
SIM/USIM cards.

Such SIM/USIM cards are special cards, which - unlike those issued by
regular commercial operators - come with the kind of keys that allow you
to write the files/fields that normally only an operator can program.

This is useful particularly if you are running your own cellular
network, and want to issue your own SIM/USIM cards for that network.


Homepage and Manual
-------------------

Please visit the [official homepage](https://osmocom.org/projects/pysim/wiki) for usage instructions, manual and examples.

Git Repository
--------------

You can clone from the official Osmocom  git repository using
```
git clone git://git.osmocom.org/pysim.git
```

There is a cgit interface at <https://git.osmocom.org/pysim>


Installation
------------

Please install the following dependencies:

 - pyscard
 - serial
 - pytlv
 - cmd2 >= 1.3.0 but < 2.0.0
 - jsonpath-ng
 - construct
 - bidict
 - gsm0338

Example for Debian:
```
apt-get install python3-pyscard python3-serial python3-pip python3-yaml
pip3 install -r requirements.txt
```

After installing all dependencies, the pySim applications ``pySim-read.py``, ``pySim-prog.py`` and ``pySim-shell.py`` may be started directly from the cloned repository.

### Archlinux Package

Archlinux users may install the package ``python-pysim-git``
[![](https://img.shields.io/aur/version/python-pysim-git)](https://aur.archlinux.org/packages/python-pysim-git)
from the [Arch User Repository (AUR)](https://aur.archlinux.org).
The most convenient way is the use of an [AUR Helper](https://wiki.archlinux.org/index.php/AUR_helpers),
e.g. [yay](https://aur.archlinux.org/packages/yay) or [pacaur](https://aur.archlinux.org/packages/pacaur).
The following example shows the installation with ``yay``.

```sh
# Install
yay -Sy python-pysim-git

# Uninstall
sudo pacman -Rs python-pysim-git
```


Mailing List
------------

There is no separate mailing list for this project. However,
discussions related to pysim-prog are happening on the
<openbsc@lists.osmocom.org> mailing list, please see
<https://lists.osmocom.org/mailman/listinfo/openbsc> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.


Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We are using a gerrit-based patch review process explained at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit>


Usage Examples
--------------

 * Program customizable SIMs. Two modes are possible:

  - one where you specify every parameter manually:
```
./pySim-prog.py -n 26C3 -c 49 -x 262 -y 42 -i <IMSI> -s <ICCID>
```

  - one where they are generated from some minimal set:
```
./pySim-prog.py -n 26C3 -c 49 -x 262 -y 42 -z <random_string_of_choice> -j <card_num>
```

With ``<random_string_of_choice>`` and ``<card_num>``, the soft will generate
'predictable' IMSI and ICCID, so make sure you choose them so as not to
conflict with anyone. (for e.g. your name as ``<random_string_of_choice>`` and
0 1 2 ... for ``<card num>``).

You also need to enter some parameters to select the device:

 -t TYPE : type of card (``supersim``, ``magicsim``, ``fakemagicsim`` or try ``auto``)  
 -d DEV  : Serial port device (default ``/dev/ttyUSB0``)  
 -b BAUD : Baudrate (default 9600)  

 * Interact with SIMs from a python interactive shell (e.g. ipython):

```
from pySim.transport.serial import SerialSimLink
from pySim.commands import SimCardCommands

sl = SerialSimLink(device='/dev/ttyUSB0', baudrate=9600)
sc = SimCardCommands(sl)

sl.wait_for_card()

	# Print IMSI
print(sc.read_binary(['3f00', '7f20', '6f07']))

	# Run A3/A8
print(sc.run_gsm('00112233445566778899aabbccddeeff'))
```
