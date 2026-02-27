smpp-ota-tool
=============

The `smpp-ota-tool` allows users to send OTA SMS messages containing APDU scripts (RFM, RAM) via an SMPP server. The
intended audience are developers who want to test/evaluate the OTA SMS interface of a SIM/UICC/eUICC. `smpp-ota-tool`
is intended to be used as a companion tool for :ref:`pySim-smpp2sim`, however it should be usable on any other SMPP
server (such as a production SMSC of a live cellular network) as well.

From the technical perspective `smpp-ota-tool` takes the role of an SMPP ESME. It takes care of the encoding, encryption
and checksumming (signing) of the RFM/RAM OTA SMS and eventually submits it to the SMPP server. The program then waits
for a response. The response is automatically parsed and printed on stdout. This makes the program also suitable to be
called from shell scripts.

.. note:: In the following we will we will refer to `SIM` as one of the following: `SIM`, `USIM`, `ISIM`, `UICC`,
	  `eUICC`, `eSIM`.

Applying OTA keys
~~~~~~~~~~~~~~~~~

Depending on the `SIM` type you will receive one or more sets of keys which you can use to communicate with the `SIM`
through a secure channel protocol. When using the OTA SMS method, the SCP80 protocol is used and it therefore crucial
to use a keyset that is actually suitable for SCP80.

A keyset usually consists of three keys:

#. KIC: the key used for ciphering (encryption/decryption)
#. KID: the key used to compute a cryptographic checksum (signing)
#. KIK: the key used to encrypt/decrypt key material (key rotation, adding of new keys)

From the transport security perspective, only KIC and KID are relevant. The KIK (also referenced as "Data Encryption
Key", DEK) is only used when keys are rotated or new keys are added (see also ETSI TS 102 226, section 8.2.1.5).

When the keyset is programmed into the security domain of the `SIM`, it is tied to a specific cryptographic algorithm
(3DES, AES128 or AES256) and a so called Key Version Number (KVN). The term "Key Version Number" is misleading, since
it is actually not a version number. It is a unique identifier of a certain keyset which also identifies for which
secure channel protocol the keyset may be used. Keysets with a KVN from 1-15 (``0x01``-``0x0F``) are suitable for SCP80.
This means that it is not only important to know just the KIC/KID/KIK keys. Also the related algorithms and the KVN
numbers must be known.

.. note:: SCP80 keysets typically start counting from 1 upwards. Typical configurations use a set of 3 keysets with
	  KVN numbers 1-3.

Addressing an Application
~~~~~~~~~~~~~~~~~~~~~~~~~

When communicating with a specific application on a `SIM` via SCP80, it is important to address that application with
the correct parameters. The following two parameters must be known in advance:

#. TAR: The Toolkit Application Reference (TAR) number is a three byte value that uniquely addresses an application
   on the `SIM`. The exact values may vary (see also ETSI TS 101 220, Table D.1).
#. MSL: The Minimum Security Level (MSL) is a bit-field that dictates which of the security measures encoded in the
   SPI are mandatory (see also ETSI TS 102 225, section 5.1.1).

A practical example
~~~~~~~~~~~~~~~~~~~

.. note:: This tutorial assumes that pySim-smpp2sim is running on the local machine with its default parameters.
	  See also :ref:`pySim-smpp2sim`.

Let's assume that an OTA SMS shall be sent to the SIM RFM application of an sysmoISIM-SJA2. What we want to do is to
select DF.GSM and to get the select response back.

We have received the following key material from the `SIM` vendor:

::

   KIC1: F09C43EE1A0391665CC9F05AF4E0BD10
   KID1: 01981F4A20999F62AF99988007BAF6CA
   KIK1: 8F8AEE5CDCC5D361368BC45673D99195
   KIC2: 01022916E945B656FDE03F806A105FA2
   KID2: D326CB69F160333CC5BD1495D448EFD6
   KIK2: 08037E0590DFE049D4975FFB8652F625
   KIC3: 2B22824D0D27A3A1CEEC512B312082B4
   KID3: F1697766925A11F4458295590137B672
   KIK3: C7EE69B2C5A1C8E160DD36A38EB517B3

Those are three keysets. The enumeration is directly equal to the KVN used. All three keysets are 3DES keys, which
means triple_des_cbc2 is the correct algorithm to use.

.. note:: The key set configuration can be confirmed by retrieving the key configuration using
	  `get_data key_information` from within an SCP02 session on ADF.ISD.

In this example we intend to address the SIM RFM application on the `SIM`. Which according to the manual has TAR ``B00010``
and MSL ``0x06``. When we hold ``0x06`` = ``0b00000110`` against the SPI coding chart (see also ETSI TS 102 225,
section 5.1.1). We can deduct that Ciphering and Cryptographic Checksum are mandatory.

.. note:: The MSL (see also ETSI TS 102 226, section 6.1) is assigned to an application by the `SIM` issuer. It is a
	  custom decision and may vary with different `SIM` types/profiles. In the case of sysmoISIM-SJS1/SJA2/SJA5 the
	  counter requirement has been waived to simplify lab/research type use. In productive environments, `SIM`
	  applications should ideally use an MSL that makes the counter mandatory.

In order to select DF.GSM (``0x7F20``) and to retrieve the select response, two APDUs are needed. The first APDU is the
select command ``A0A40000027F20`` and the second is the related get-response command ``A0C0000016``. Those APDUs will be
concatenated and are sent in a single message. The message containing the concatenated APDUs works as a script that
is received by the SIM RFM application and then executed. This method poses some limitations that have to be taken into
account when making requests like this (see also ETSI TS 102 226, section 5).

With this information we may now construct a commandline for `smpp-ota-tool.py`. We will pass the KVN as kid_idx and
kic_idx (see also ETSI TS 102 225, Table 2, fields `KIc` and `KID`). Both index values should refer to the same
keyset/KVN as keysets should not be mixed. (`smpp-ota-tool` still provides separate parameters anyway to allow testing
with invalid keyset combinations)

::

   $ PYTHONPATH=./ ./contrib/smpp-ota-tool.py --kic F09C43EE1A0391665CC9F05AF4E0BD10 --kid 01981F4A20999F62AF99988107BAF6CA --kid_idx 1 --kic_idx 1 --algo-crypt triple_des_cbc2 --algo-auth triple_des_cbc2 --tar B00010 --apdu A0A40000027F20 --apdu A0C0000016
   2026-02-26 17:13:56 INFO Connecting to localhost:2775...
   2026-02-26 17:13:56 INFO C-APDU sending: a0a40000027f20a0c0000016...
   2026-02-26 17:13:56 INFO SMS-TPDU sending: 02700000281506191515b00010da1d6cbbd0d11ce4330d844c7408340943e843f67a6d7b0674730881605fd62d...
   2026-02-26 17:13:56 INFO SMS-TPDU sent, waiting for response...
   2026-02-26 17:13:56 INFO SMS-TPDU received: 027100002c12b000107ddf58d1780f771638b3975759f4296cf5c31efc87a16a1b61921426baa16da1b5ba1a9951d59a39
   2026-02-26 17:13:56 INFO SMS-TPDU decoded: (Container(rpl=44, rhl=18, tar=b'\xb0\x00\x10', cntr=b'\x00\x00\x00\x00\x00', pcntr=0, response_status=uEnumIntegerString.new(0, 'por_ok'), cc_rc=b'\x8f\xea\xf5.\xf4\x0e\xc2\x14', secured_data=b'\x02\x90\x00\x00\x00\xff\xff\x7f \x02\x00\x00\x00\x00\x00\t\xb1\x065\x04\x00\x83\x8a\x83\x8a'), Container(number_of_commands=2, last_status_word=u'9000', last_response_data=u'0000ffff7f2002000000000009b106350400838a838a'))
   2026-02-26 17:13:56 INFO R-APDU received: 0000ffff7f2002000000000009b106350400838a838a 9000
   0000ffff7f2002000000000009b106350400838a838a 9000
   2026-02-26 17:13:56 INFO Disconnecting...

The result we see is the select response of DF.GSM and a status word indicating that the last command has been
processed normally.

As we can see, this mechanism now allows us to perform small administrative tasks remotely. We can read the contents of
files remotely or make changes to files. Depending on the changes we make, there may be security issues arising from
replay attacks. With the commandline above, the communication is encrypted and protected by a cryptographic checksum,
so an adversary can neither read, nor alter the message. However, an adversary could still replay an intercepted
message and the `SIM` would happily execute the contained APDUs again.

To prevent this, we may include a replay protection counter within the message. In this case, the MSL indicates that a
replay protection counter is not required. However, to extended the security of our messages, we may chose to use a
counter anyway. In the following example, we will encode a counter value of 100. We will instruct the `SIM` to make sure
that the value we send is higher than the counter value that is currently stored in the `SIM`.

To add a replay connection counter we add the commandline arguments `--cntr-req` to set the counter requirement and
`--cntr` to pass the counter value.

::

   $ PYTHONPATH=./ ./contrib/smpp-ota-tool.py --kic F09C43EE1A0391665CC9F05AF4E0BD10 --kid 01981F4A20999F62AF99988107BAF6CA --kid_idx 1 --kic_idx 1 --algo-crypt triple_des_cbc2 --algo-auth triple_des_cbc2 --tar B00010 --apdu A0A40000027F20 --apdu A0C0000016 --cntr-req counter_must_be_higher --cntr 100
   2026-02-26 17:16:39 INFO Connecting to localhost:2775...
   2026-02-26 17:16:39 INFO C-APDU sending: a0a40000027f20a0c0000016...
   2026-02-26 17:16:39 INFO SMS-TPDU sending: 02700000281516191515b000103a4f599e94f2b5dcfbbda984761b7977df6514c57a580fb4844787c436d2eade...
   2026-02-26 17:16:39 INFO SMS-TPDU sent, waiting for response...
   2026-02-26 17:16:39 INFO SMS-TPDU received: 027100002c12b0001049fb0315f6c6401b553867f412cefaf9355b38271178edb342a3bc9cc7e670cdc1f45eea6ffcbb39
   2026-02-26 17:16:39 INFO SMS-TPDU decoded: (Container(rpl=44, rhl=18, tar=b'\xb0\x00\x10', cntr=b'\x00\x00\x00\x00d', pcntr=0, response_status=uEnumIntegerString.new(0, 'por_ok'), cc_rc=b'\xa9/\xc7\xc9\x00"\xab5', secured_data=b'\x02\x90\x00\x00\x00\xff\xff\x7f \x02\x00\x00\x00\x00\x00\t\xb1\x065\x04\x00\x83\x8a\x83\x8a'), Container(number_of_commands=2, last_status_word=u'9000', last_response_data=u'0000ffff7f2002000000000009b106350400838a838a'))
   2026-02-26 17:16:39 INFO R-APDU received: 0000ffff7f2002000000000009b106350400838a838a 9000
   0000ffff7f2002000000000009b106350400838a838a 9000
   2026-02-26 17:16:39 INFO Disconnecting...

The `SIM` has accepted the message. The message got processed and the `SIM` has set its internal to 100. As an experiment,
we may try to re-use the counter value:

::

   $ PYTHONPATH=./ ./contrib/smpp-ota-tool.py --kic F09C43EE1A0391665CC9F05AF4E0BD10 --kid 01981F4A20999F62AF99988107BAF6CA --kid_idx 1 --kic_idx 1 --algo-crypt triple_des_cbc2 --algo-auth triple_des_cbc2 --tar B00010 --apdu A0A40000027F20 --apdu A0C0000016 --cntr-req counter_must_be_higher --cntr 100
   2026-02-26 17:16:43 INFO Connecting to localhost:2775...
   2026-02-26 17:16:43 INFO C-APDU sending: a0a40000027f20a0c0000016...
   2026-02-26 17:16:43 INFO SMS-TPDU sending: 02700000281516191515b000103a4f599e94f2b5dcfbbda984761b7977df6514c57a580fb4844787c436d2eade...
   2026-02-26 17:16:43 INFO SMS-TPDU sent, waiting for response...
   2026-02-26 17:16:43 INFO SMS-TPDU received: 027100000b0ab0001000000000000006
   2026-02-26 17:16:43 INFO SMS-TPDU decoded: (Container(rpl=11, rhl=10, tar=b'\xb0\x00\x10', cntr=b'\x00\x00\x00\x00\x00', pcntr=0, response_status=uEnumIntegerString.new(6, 'undefined_security_error'), cc_rc=b'', secured_data=b''), None)
   Traceback (most recent call last):
   File "/home/user/work/git_master/pysim/./contrib/smpp-ota-tool.py", line 238, in <module>
    resp, sw = smpp_handler.transceive_apdu(apdu, opts.src_addr, opts.dest_addr, opts.timeout)
               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   File "/home/user/work/git_master/pysim/./contrib/smpp-ota-tool.py", line 162, in transceive_apdu
     raise ValueError("Response does not contain any last_response_data, no R-APDU received!")
   ValueError: Response does not contain any last_response_data, no R-APDU received!
   2026-02-26 17:16:43 INFO Disconnecting...

As we can see, the `SIM` has rejected the message with an `undefined_security_error`. The replay-protection-counter
ensures that a message can only be sent once.

.. note:: The replay-protection-counter is implemented as a 5 byte integer value (see also ETSI TS 102 225, Table 3).
	  When the counter has reached its maximum, it will not overflow nor can it be reset.

smpp-ota-tool syntax
~~~~~~~~~~~~~~~~~~~~

.. argparse::
   :module: contrib.smpp-ota-tool
   :func: option_parser
   :prog: contrib/smpp-ota-tool.py
