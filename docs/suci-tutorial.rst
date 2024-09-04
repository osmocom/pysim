
Guide: Enabling 5G SUCI
=======================

SUPI/SUCI Concealment is a feature of 5G-Standalone (SA) to encrypt the
IMSI/SUPI with a network operator public key.  3GPP Specifies two different
variants for this:

* SUCI calculation *in the UE*, using key data from the SIM
* SUCI calculation *on the card itself*

pySim supports writing the 5G-specific files for *SUCI calculation in the UE* on USIM cards, assuming
that your cards contain the required files, and you have the privileges/credentials to write to them.
This is the case using sysmocom sysmoISIM-SJA2 or any flavor of sysmoISIM-SJA5.

There is no 3GPP/ETSI standard method for configuring *SUCI calculation on the card*; pySim currently
supports the vendor-specific method for the sysmoISIM-SJA5-S17).

This document describes both methods.


Technical References
~~~~~~~~~~~~~~~~~~~~

This guide covers the basic workflow of provisioning SIM cards with the 5G SUCI feature. For detailed information on the SUCI feature and file contents, the following documents are helpful:

* USIM files and structure: `3GPP TS 31.102 <https://www.etsi.org/deliver/etsi_ts/131100_131199/131102/16.06.00_60/ts_131102v160600p.pdf>`__
* USIM tests (incl. file content examples): `3GPP TS 31.121 <https://www.etsi.org/deliver/etsi_ts/131100_131199/131121/16.01.00_60/ts_131121v160100p.pdf>`__
* Test keys for SUCI calculation: `3GPP TS 33.501 <https://www.etsi.org/deliver/etsi_ts/133500_133599/133501/16.05.00_60/ts_133501v160500p.pdf>`__

For specific information on sysmocom SIM cards, refer to

* the `sysmoISIM-SJA5 User Manual <https://sysmocom.de/manuals/sysmoisim-sja5-manual.pdf>`__ for the curent
  sysmoISIM-SJA5 product
* the `sysmoISIM-SJA2 User Manual <https://sysmocom.de/manuals/sysmousim-manual.pdf>`__ for the older
  sysmoISIM-SJA2 product

--------------


Enabling 5G SUCI *calculated in the UE*
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In short, you can enable *SUCI calculation in the UE* with these steps:

* activate USIM **Service 124**
* make sure USIM **Service 125** is disabled
* store the public keys in **EF.SUCI_Calc_Info**
* set the **Routing Indicator** (required)

If you want to disable the feature, you can just disable USIM Service 124 (and 125) in `EF.UST`.


Admin PIN
---------

The usual way to authenticate yourself to the card as the cellular
operator is to validate the so-called ADM1 (admin) PIN.  This may differ
from card model/vendor to card model/vendor.

Start pySIM-shell and enter the admin PIN for your card. If you bought
the SIM card from your network operator and don’t have the admin PIN,
you cannot change SIM contents!

Launch pySIM:

::

    $ ./pySim-shell.py -p 0

    Using PC/SC reader interface
    Autodetected card type: sysmoISIM-SJA2
    Welcome to pySim-shell!
    pySIM-shell (00:MF)>

Enter the ADM PIN:

::

   pySIM-shell (00:MF)> verify_adm XXXXXXXX

Otherwise, write commands will fail with ``SW Mismatch: Expected 9000 and got 6982.``

Key Provisioning
----------------

::

   pySIM-shell (00:MF)> select MF
   pySIM-shell (00:MF)> select ADF.USIM
   pySIM-shell (00:MF/ADF.USIM)> select DF.5GS
   pySIM-shell (00:MF/ADF.USIM/DF.5GS)> select EF.SUCI_Calc_Info

By default, the file is present but empty:

::

   pySIM-shell (00:MF/ADF.USIM/DF.5GS/EF.SUCI_Calc_Info)> read_binary_decoded
   missing Protection Scheme Identifier List data object tag
   9000: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff -> {}

The following JSON config defines the testfile from 3GPP TS 31.121, Section 4.9.4 with
test keys from 3GPP TS 33.501, Annex C.4. Highest priority (``0``) has a
Profile-B (``identifier: 2``) key in key slot ``1``, which means the key
with ``hnet_pubkey_identifier: 27``.

.. code:: json

   {
        "prot_scheme_id_list": [
           {"priority": 0, "identifier": 2, "key_index": 1},
           {"priority": 1, "identifier": 1, "key_index": 2},
           {"priority": 2, "identifier": 0, "key_index": 0}],
        "hnet_pubkey_list": [
           {"hnet_pubkey_identifier": 27,
            "hnet_pubkey": "0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4"},
           {"hnet_pubkey_identifier": 30,
            "hnet_pubkey": "5A8D38864820197C3394B92613B20B91633CBD897119273BF8E4A6F4EEC0A650"}]
   }

Write the config to file (must be single-line input as for now):

::

   pySIM-shell (00:MF/ADF.USIM/DF.5GS/EF.SUCI_Calc_Info)> update_binary_decoded '{ "prot_scheme_id_list": [ {"priority": 0, "identifier": 2, "key_index": 1}, {"priority": 1, "identifier": 1, "key_index": 2}, {"priority": 2, "identifier": 0, "key_index": 0}], "hnet_pubkey_list": [ {"hnet_pubkey_identifier": 27, "hnet_pubkey": "0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4"}, {"hnet_pubkey_identifier": 30, "hnet_pubkey": "5A8D38864820197C3394B92613B20B91633CBD897119273BF8E4A6F4EEC0A650"}]}'

WARNING: These are TEST KEYS with publicly known/specified private keys, and hence unsafe for live/secure
deployments! For use in production networks, you need to generate your own set[s] of keys.

Routing Indicator
-----------------

The Routing Indicator must be present for the SUCI feature. By default,
the contents of the file is **invalid** (ffffffff):

::

   pySIM-shell (00:MF)> select MF
   pySIM-shell (00:MF)> select ADF.USIM
   pySIM-shell (00:MF/ADF.USIM)> select DF.5GS
   pySIM-shell (00:MF/ADF.USIM/DF.5GS)> select EF.Routing_Indicator
   pySIM-shell (00:MF/ADF.USIM/DF.5GS/EF.Routing_Indicator)> read_binary_decoded
   9000: ffffffff -> {'raw': 'ffffffff'}

The Routing Indicator is a four-byte file but the actual Routing
Indicator goes into bytes 0 and 1 (the other bytes are reserved). To set
the Routing Indicator to 0x71:

::

   pySIM-shell (00:MF/ADF.USIM/DF.5GS/EF.Routing_Indicator)> update_binary 17ffffff

You can also set the routing indicator to **0x0**, which is *valid* and
means “routing indicator not specified”, leaving it to the modem.

USIM Service Table
------------------

First, check out the USIM Service Table (UST):

::

   pySIM-shell (00:MF)> select MF
   pySIM-shell (00:MF)> select ADF.USIM
   pySIM-shell (00:MF/ADF.USIM)> select EF.UST
   pySIM-shell (00:MF/ADF.USIM/EF.UST)> read_binary_decoded
   9000: beff9f9de73e0408400170730000002e00000000 -> [2, 3, 4, 5, 6, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 25, 27, 28, 29, 33, 34, 35, 38, 39, 42, 43, 44, 45, 46, 51, 60, 71, 73, 85, 86, 87, 89, 90, 93, 94, 95, 122, 123, 124, 126]

.. list-table:: From 3GPP TS 31.102
   :widths: 15 40
   :header-rows: 1

   * - Service No.
     - Description
   * - 122
     - 5GS Mobility Management Information
   * - 123
     - 5G Security Parameters
   * - 124
     - Subscription identifier privacy support
   * - 125
     - SUCI calculation by the USIM
   * - 126
     - UAC Access Identities support
   * - 129
     - 5GS Operator PLMN List

If you’d like to enable/disable any UST service:

::

   pySIM-shell (00:MF/ADF.USIM/EF.UST)> ust_service_deactivate 124
   pySIM-shell (00:MF/ADF.USIM/EF.UST)> ust_service_activate 124
   pySIM-shell (00:MF/ADF.USIM/EF.UST)> ust_service_deactivate 125

In this case, UST Service 124 is already enabled and you’re good to go. The
sysmoISIM-SJA2 does not support on-SIM calculation, so service 125 must
be disabled.

USIM Error with 5G and sysmoISIM
--------------------------------

sysmoISIM-SJA2 come 5GS-enabled. By default however, the configuration stored
in the card file-system is **not valid** for 5G networks: Service 124 is enabled,
but EF.SUCI_Calc_Info and EF.Routing_Indicator are empty files (hence
do not contain valid data).

At least for Qualcomm’s X55 modem, this results in an USIM error and the
whole modem shutting 5G down. If you don’t need SUCI concealment but the
smartphone refuses to connect to any 5G network, try to disable the UST
service 124.

sysmoISIM-SJA5 are shipped with a more forgiving default, with valid EF.Routing_Indicator
contents and disabled Service 124


SUCI calculation by the USIM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The SUCI calculation can also be performed by the USIM application on the UICC
directly. The UE then uses the GET IDENTITY command (see also 3GPP TS 31.102,
section 7.5) to retrieve a SUCI value.

The sysmoISIM-SJA5-S17 supports *SUCI calculation by the USIM*. The configuration
is not much different to the above described configuration of *SUCI calculation
in the UE*.

The main difference is how the key provisioning is done. When the SUCI
calculation is done by the USIM, then the key material is not accessed by the
UE. The specification (see also 3GPP TS 31.102, section 7.5.1.1), also does not
specify any file or file format to store the key material. This means the exact
way to perform the key provisioning is an implementation detail of the USIM
card application.

In the case of sysmoISIM-SJA5-S17, the key material for *SUCI calculation by the USIM* is stored in
`ADF.USIM/DF.SAIP/EF.SUCI_Calc_Info` (**not** in `ADF.USIM/DF.5GS/EF.SUCI_Calc_Info`!).

::

   pySIM-shell (00:MF)> select MF
   pySIM-shell (00:MF)> select ADF.USIM
   pySIM-shell (00:MF/ADF.USIM)> select DF.SAIP
   pySIM-shell (00:MF/ADF.USIM/DF.SAIP)> select EF.SUCI_Calc_Info

The file format is exactly the same as specified in 3GPP TS 31.102, section
4.4.11.8. This means the above described key provisioning procedure can be
applied without any changes, except that the file location is different.

To signal to the UE that the USIM is setup up for SUCI calculation, service
125 must be enabled in addition to service 124 (see also 3GPP TS 31.102,
section 5.3.48)

::

   pySIM-shell (00:MF/ADF.USIM/EF.UST)> ust_service_activate 124
   pySIM-shell (00:MF/ADF.USIM/EF.UST)> ust_service_activate 125

To verify that the SUCI calculation works as expected, it is possible to issue
a GET IDENTITY command using pySim-shell:

::

   select ADF.USIM
   get_identity

The USIM should then return a SUCI TLV Data object that looks like this:

::

   SUCI TLV Data Object: 0199f90717ff021b027a2c58ce1c6b89df088a9eb4d242596dd75746bb5f3503d2cf58a7461e4fd106e205c86f76544e9d732226a4e1
