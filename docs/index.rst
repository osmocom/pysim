.. pysim documentation master file

Welcome to Osmocom pySim
========================

Introduction
------------

pySim is a python implementation of various software that helps you with
managing subscriber identity cards for cellular networks, so-called SIM
cards.

Many Osmocom (Open Source Mobile Communications) projects relate to operating
private / custom cellular networks, and provisioning SIM cards for said networks
is in many cases a requirement to operate such networks.

To make use of most of pySim's features, you will need a `programmable` SIM card,
i.e. a card where you are the owner/operator and have sufficient credentials (such
as the `ADM PIN`) in order to write to many if not most of the files on the card.

Such cards are, for example, available from sysmocom, a major contributor to pySim.
See https://www.sysmocom.de/products/lab/sysmousim/ for more details.

pySim supports classic GSM SIM cards as well as ETSI UICC with 3GPP USIM and ISIM
applications.  It is easily extensible, so support for additional files, card
applications, etc. can be added easily by any python developer.  We do encourage you
to submit your contributions to help this collaborative development project.

pySim consists of several parts:

* a python :ref:`library<pySim library>` containing plenty of objects and methods that can be used for
  writing custom programs interfacing with SIM cards.
* the [new] :ref:`interactive pySim-shell command line program<pySim-shell>`
* the [new] :ref:`pySim-trace APDU trace decoder<pySim-trace>`
* the [legacy] :ref:`pySim-prog and pySim-read tools<Legacy tools>`

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   shell
   trace
   legacy
   smpp2sim
   library
   library-esim
   osmo-smdpp
   sim-rest
   suci-keytool
   saip-tool


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
