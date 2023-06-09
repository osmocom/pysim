pySim-trace
===========

pySim-trace is a utility for high-level decode of APDU protocol traces such as those obtained with
`Osmocom SIMtrace2 <https://osmocom.org/projects/simtrace2/wiki>`_ or `osmo-qcdiag <https://osmocom.org/projects/osmo-qcdiag/wiki>`_.

pySim-trace leverages the existing knowledge of pySim-shell on anything related to SIM cards,
including the structure/encoding of the various files on SIM/USIM/ISIM/HPSIM cards, and applies this
to decoding protocol traces.  This means that it shows not only the name of the command (like READ
BINARY), but actually understands what the currently selected file is, and how to decode the
contents of that file.

pySim-trace also understands the parameters passed to commands and how to decode them, for example
of the AUTHENTICATE command within the USIM/ISIM/HPSIM application.


Demo
----

To get an idea how pySim-trace usage looks like, you can watch the relevant part of the 11/2022
SIMtrace2 tutorial whose `recording is freely accessible <https://media.ccc.de/v/osmodevcall-20221019-laforge-simtrace2-tutorial#t=2134>`_.


Running pySim-trace
-------------------

Running pySim-trace requires you to specify the *source* of the to-be-decoded APDUs.  There are several
supported options, each with their own respective parameters (like a file name for PCAP decoding).

See the detailed command line reference below for details.

A typical execution of pySim-trace for doing live decodes of *GSMTAP (SIM APDU)* e.g. from SIMtrace2 or
osmo-qcdiag would look like this:

::

  ./pySim-trace.py gsmtap-udp

This binds to the default UDP port 4729 (GSMTAP) on localhost (127.0.0.1), and decodes any APDUs received
there.



pySim-trace command line reference
----------------------------------

.. argparse::
   :module: pySim-trace
   :func: option_parser
   :prog: pySim-trace.py


Constraints
-----------

* In order to properly track the current location in the filesystem tree and other state, it is
  important that the trace you're decoding includes all of the communication with the SIM, ideally
  from the very start (power up).

* pySim-trace currently only supports ETSI UICC (USIM/ISIM/HPSIM) and doesn't yet support legacy GSM
  SIM.  This is not a fundamental technical constraint, it's just simply that nobody got around
  developing and testing that part. Contributions are most welcome.


