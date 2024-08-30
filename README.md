pySim - Read, Write and Browse Programmable SIM/USIM/ISIM/HPSIM Cards
=====================================================================

This repository contains a number of Python programs that can be used
to read, program (write) and browse all fields/parameters/files on
SIM/USIM/ISIM/HPSIM cards used in 3GPP cellular networks from 2G to 5G.

Note that the access control configuration of normal production cards
issue by operators will restrict significantly which files a normal
user can read, and particularly write to.

The full functionality of pySim hence can only be used with on so-called
programmable SIM/USIM/ISIM/HPSIM cards.

Such SIM/USIM/ISIM/HPSIM cards are special cards, which - unlike those
issued by regular commercial operators - come with the kind of keys that
allow you to write the files/fields that normally only an operator can
program.

This is useful particularly if you are running your own cellular
network, and want to configure your own SIM/USIM/ISIM/HPSIM cards for
that network.


Homepage
--------

Please visit the [official homepage](https://osmocom.org/projects/pysim/wiki)
for usage instructions, manual and examples.


Documentation
-------------

The pySim user manual can be built from this very source code by means
of sphinx (with sphinxcontrib-napoleon and sphinx-argparse).  See the
Makefile in the 'docs' directory.

A pre-rendered HTML user manual of the current pySim 'git master' is
available from <https://downloads.osmocom.org/docs/latest/pysim/> and
a downloadable PDF version is published at
<https://downloads.osmocom.org/docs/latest/osmopysim-usermanual.pdf>.

A slightly dated video presentation about pySim-shell can be found at
<https://media.ccc.de/v/osmodevcall-20210409-laforge-pysim-shell>.


pySim-shell vs. legacy tools
----------------------------

While you will find a lot of online resources still describing the use of
pySim-prog.py and pySim-read.py, those tools are considered legacy by
now and have by far been superseded by the much more capable
pySim-shell.  We strongly encourage users to adopt pySim-shell, unless
they have very specific requirements like batch programming of large
quantities of cards, which is about the only remaining use case for the
legacy tools.


Git Repository
--------------

You can clone from the official Osmocom  git repository using
```
git clone https://gitea.osmocom.org/sim-card/pysim.git
```

There is a web interface at <https://gitea.osmocom.org/sim-card/pysim>.


Installation
------------

Please install the following dependencies:

 - bidict
 - cmd2 >= 1.5.0
 - colorlog
 - construct >= 2.9.51
 - pyosmocom
 - jsonpath-ng
 - packaging
 - pycryptodomex
 - pyscard
 - pyserial
 - pytlv
 - pyyaml >= 5.1
 - smpp.pdu (from `github.com/hologram-io/smpp.pdu`)
 - termcolor

Example for Debian:
```sh
sudo apt-get install --no-install-recommends \
	pcscd libpcsclite-dev \
	python3 \
	python3-setuptools \
	python3-pycryptodome \
	python3-pyscard \
	python3-pip
pip3 install --user -r requirements.txt
```

After installing all dependencies, the pySim applications ``pySim-read.py``, ``pySim-prog.py`` and ``pySim-shell.py`` may be started directly from the cloned repository.

In addition to the dependencies above ``pySim-trace.py`` requires ``tshark`` and the python package ``pyshark`` to be installed. It is known that the ``tshark`` package
in Debian versions before 11 may not work with pyshark.

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


Forum
-----

We welcome any pySim related discussions in the
[SIM Card Technology](https://discourse.osmocom.org/c/sim-card-technology/)
section of the osmocom discourse (web based Forum).


Mailing List
------------

There is no separate mailing list for this project. However,
discussions related to pySim are happening on the simtrace
<simtrace@lists.osmocom.org> mailing list, please see
<https://lists.osmocom.org/mailman/listinfo/simtrace> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.

Issue Tracker
-------------

We use the [issue tracker of the pysim project on osmocom.org](https://osmocom.org/projects/pysim/issues) for
tracking the state of bug reports and feature requests.  Feel free to submit any issues you may find, or help
us out by resolving existing issues.


Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We are using a gerrit-based patch review process explained at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit>
