pySim library
=============

pySim filesystem abstraction
----------------------------

.. automodule:: pySim.filesystem
   :members:

pySim commands abstraction
--------------------------

.. automodule:: pySim.commands
   :members:

pySim Transport
---------------

The pySim.transport classes implement specific ways how to
communicate with a SIM card.  A "transport" provides ways
to transceive APDUs with the card.

The most commonly used transport uses the PC/SC interface to
utilize a variety of smart card interfaces ("readers").

Transport base class
~~~~~~~~~~~~~~~~~~~~

.. automodule:: pySim.transport
   :members:


calypso / OsmocomBB transport
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This allows the use of the SIM slot of an OsmocomBB compatible phone with the TI Calypso chipset,
using the L1CTL interface to talk to the layer1.bin firmware on the phone.

.. automodule:: pySim.transport.calypso
   :members:


AT-command Modem transport
~~~~~~~~~~~~~~~~~~~~~~~~~~

This transport uses AT commands of a cellular modem in order to get access to the SIM card inserted
in such a modem.

.. automodule:: pySim.transport.modem_atcmd
   :members:


PC/SC transport
~~~~~~~~~~~~~~~

PC/SC is the standard API for accessing smart card interfaces
on all major operating systems, including the MS Windows Family,
OS X as well as Linux / Unix OSs.

.. automodule:: pySim.transport.pcsc
   :members:


Serial/UART transport
~~~~~~~~~~~~~~~~~~~~~

This transport implements interfacing smart cards via
very simplistic UART readers.  These readers basically
wire together the Rx+Tx pins of a RS232 UART, provide
a fixed crystal oscillator for clock, and operate the UART
at 9600 bps.  These readers are sometimes called `Phoenix`.

.. automodule:: pySim.transport.serial
   :members:


pySim utility functions
-----------------------

.. automodule:: pySim.utils
   :members:

pySim exceptions
----------------

.. automodule:: pySim.exceptions
   :members:

pySim card_handler
------------------

.. automodule:: pySim.card_handler
   :members:

pySim card_key_provider
-----------------------

.. automodule:: pySim.card_key_provider
   :members:
