Guide: Managing GP Keys
=======================

Most of today's smartcards follow the GlobalPlatform Card Specification and the included Security Domain model.
UICCs and eUCCCs are no exception here.

The Security Domain acts as an on-card representative of a card authority or administrator. It is used to perform tasks
like the installation of applications or the provisioning and rotation of secure channel keys. It also acts as a secure
key storage and offers all kinds of cryptographic services to applications that are installed under a specific
Security Domain (see also GlobalPlatform Card Specification, section 7).

In this tutorial, we will show how to work with the key material (keysets) stored inside a Security Domain and how to
rotate (replace) existing keys. We will also show how to provision new keys.

.. warning:: Making changes to keysets requires extreme caution as misconfigured keysets may lock you out permanently.
	     It's also strongly recommended to maintain at least one backup keyset that you can use as fallback in case
	     the primary keyset becomes unusable for some reason.


Selecting a Security Domain
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A typical smartcard, such as an UICC will have one primary Security Domain, called the Issuer Security Domain (ISD).
When working with those cards, the ISD will show up in the UICC filesystem tree as `ADF.ISD` and can be selected like
any other file.

::

   pySIM-shell (00:MF)> select ADF.ISD
   {
      "application_id": "a000000003000000",
      "proprietary_data": {
         "maximum_length_of_data_field_in_command_message": 255
      }
   }

When working with eUICCs, multiple Security Domains are involved. The model is fundamentally different from the classic
model with one primary Security Domain (ISD). In the case of eUICCs, an ISD-R (Issuer Security Domain - Root) and an
ISD-P (Issuer Security Domain - Profile) exist (see also: GSMA SGP.02, section 2.2.1).

The ISD-P is established by the ISD-R during the profile installation and serves as a secure container for an eSIM
profile. Within the ISD-P the eSIM profile establishes a dedicated Security Domain called `MNO-SD` (see also GSMA
SGP.02, section 2.2.4). This `MNO-SD` is comparable to the Issuer Security Domain (ISD) we find on UICCs. The AID of
`MNO-SD` is either the default AID for the Issuer Security Domain (see also GlobalPlatform, section H.1.3) or a
different value specified by the provider of the eSIM profile.

Since the AID of the `MNO-SD` is not a fixed value, it is not known by `pySim-shell`. This means there will be no
`ADF.ISD` file shown in the file system, but we can simply select the `ADF.ISD-R` first and then select the `MNO-SD`
using a raw APDU. In the following example we assume that the default AID (``a000000151000000``) is used  The APDU
would look like this: ``00a4040408`` + ``a000000151000000`` + ``00``

::

   pySIM-shell (00:MF)> select ADF.ISD-R
   {
       "application_id": "a0000005591010ffffffff8900000100",
       "proprietary_data": {
           "maximum_length_of_data_field_in_command_message": 255
       },
       "isdr_proprietary_application_template": {
           "supported_version_number": "020300"
       }
   }
   pySIM-shell (00:MF/ADF.ISD-R)> apdu 00a4040408a00000015100000000
   SW: 9000, RESP: 6f108408a000000151000000a5049f6501ff

After that, the prompt will still show the `ADF.ISD-R`, but we are actually in `ADF.ISD` and the standard GlobalPlatform
operations like `establish_scpXX`, `get_data`, and `put_key` should work. By doing this, we simply have tricked
`pySim-shell` into making the GlobalPlatform related commands available for some other Security Domain we are not
interested in. With the raw APDU we then have swapped out the Security Domain under the hood. The same workaround can
be applied to any Security Domain, provided that the AID is known to the user.


Establishing a secure channel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before we can make changes to the keysets in the currently selected Security Domain we must first establish a secure
channel with that Security Domain. In the following examples we will use `SCP02` (see also GlobalPlatform Card
Specification, section E.1.1) and `SCP03` (see also GlobalPlatform Card Specification – Amendment D) to establish the
secure channel. `SCP02` is slightly older than `SCP03`. The main difference between the two is that `SCP02` uses 3DES
while `SCP03` is based on AES.

.. warning:: Secure channel protocols like `SCP02` and `SCP03` may manage an error counter to count failed login
	     attempts. This means attempting to establish a secure channel with a wrong keyset multiple times may lock
	     you out permanently. Double check the applied keyset before attempting to establish a secure channel.

.. warning:: The key values used in the following examples are random key values used for illustration purposes only.
	     Each UICC or eSIM profile is shipped with individual keys, which means that the keys used below will not
	     work with your UICC or eSIM profile. You must replace the key values with the values you have received
	     from your UICC vendor or eSIM profile provider.


Example: `SCP02`
----------------

In the following example, we assume that we want to establish a secure channel with the ISD of a `sysmoUSIM-SJA5` UICC.
Along with the card we have received the following keyset:

+---------+----------------------------------+
| Keyname | Keyvalue                         |
+=========+==================================+
| ENC/KIC | F09C43EE1A0391665CC9F05AF4E0BD10 |
+---------+----------------------------------+
| MAC/KID | 01981F4A20999F62AF99988007BAF6CA |
+---------+----------------------------------+
| DEK/KIK | 8F8AEE5CDCC5D361368BC45673D99195 |
+---------+----------------------------------+

This keyset is tied to the key version number KVN 122 and is configured as a DES keyset. We can use this keyset to
establish a secure channel using the SCP02 Secure Channel Protocol.

::

    pySIM-shell (00:MF/ADF.ISD)> establish_scp02 --key-enc F09C43EE1A0391665CC9F05AF4E0BD10 --key-mac 01981F4A20999F62AF99988007BAF6CA --key-dek 8F8AEE5CDCC5D361368BC45673D99195  --key-ver 112 --security-level 3
    Successfully established a SCP02[03] secure channel


Example: `SCP03`
----------------

The establishment of a secure channel via SCP03 works just the same. In the following example we will establish a
secure channel to the `MNO-SD` of an eSIM profile. The SCP03 keyset we use is tied to KVN 48 and looks like this:

+---------+------------------------------------------------------------------+
| Keyname | Keyvalue                                                         |
+=========+==================================================================+
| ENC/KIC | 63af517c29ad6ac6fcadfe6ac8a3c8a041d8141c7eb845ef1cba6112a325e430 |
+---------+------------------------------------------------------------------+
| MAC/KID | 54b9ad6713ae922f54014ed762132e7b59bdcd2a2a6beba98fb9afe6b4df27e1 |
+---------+------------------------------------------------------------------+
| DEK/KIK | cbb933ba2389da93c86c112739cd96389139f16c6f80f7d16bf3593e407ca893 |
+---------+------------------------------------------------------------------+

We assume that the `MNO-SD` is already selected (see above). We may now establish the SCP03 secure channel:

::

   pySIM-shell (00:MF/ADF.ISD-R)> establish_scp03 --key-enc 63af517c29ad6ac6fcadfe6ac8a3c8a041d8141c7eb845ef1cba6112a325e430 --key-mac 54b9ad6713ae922f54014ed762132e7b59bdcd2a2a6beba98fb9afe6b4df27e1 --key-dek cbb933ba2389da93c86c112739cd96389139f16c6f80f7d16bf3593e407ca893 --key-ver 48 --security-level 3
   Successfully established a SCP03[03] secure channel



Understanding Keysets
~~~~~~~~~~~~~~~~~~~~~

Before making any changes to keysets, it is recommended to check the status of the currently installed keysets. To do
so, we use the `get_data` command to retrieve the `key_information`. This command does not require the establishment of
a secure channel. We also cannot read back the key values themselves, but we get a summary of the installed keys
together with their KVN numbers, IDs, algorithm and key length values.

Example: `key_information` from a `sysmoISIM-SJA5`:

::

    pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> get_data key_information
    {
        "key_information": [
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 112,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 112,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 3,
                    "key_version_number": 112,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 1,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 1,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 3,
                    "key_version_number": 1,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 2,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 2,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 3,
                    "key_version_number": 2,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 47,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 47,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 3,
                    "key_version_number": 47,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            }
        ]
    }

Example: `key_information` from a `sysmoEUICC1-C2T`:

::

    pySIM-shell (SCP03[03]:00:MF/ADF.ISD-R)> get_data key_information
    {
        "key_information": [
            {
                "key_information_data": {
                    "key_identifier": 3,
                    "key_version_number": 50,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 32
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 50,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 32
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 50,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 32
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 64,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 64,
                    "key_types": [
                        {
                            "type": "tls_psk",
                            "length": 16
                        }
                    ]
                }
            }
        ]
    }

The output from those two examples above may seem lengthy, but in order to move on and to provision own keys
successfully, it is important to understand each aspect of it.

Key Version Number (KVN)
------------------------

Each key is associated with a Key Version Number (KVN). Multiple keys that share the same KVN belong to the same
keyset. In the first example above we can see that four keysets with KVN numbers 112, 1, 2 and 47 are provisioned.
In the second example we see two keysets. One with KVN 50 and one with KVN 64.

The term "Key Version Number" is misleading as this number is not really a version number. It's actually a unique
identifier for a specific keyset that also defines with which Secure Channel Protocol a key can be used. This means
that the KVN is not just an arbitrary number. The following (incomplete) table gives a hint which KVN numbers may be
used with which Secure Channel Protocol.

+-----------+-------------------------------------------------------+
| KVN range | Secure Channel Protocol                               |
+===========+=======================================================+
| 1-15      | reserved for `SCP80` (OTA SMS)                        |
+-----------+-------------------------------------------------------+
| 17        | reserved for DAP specified in ETSI TS 102 226         |
+-----------+-------------------------------------------------------+
| 32-47     | reserved for `SCP02`                                  |
+-----------+-------------------------------------------------------+
| 48-63     | reserved for `SCP03`                                  |
+-----------+-------------------------------------------------------+
| 64-79     | reserved for `SCP81` (GSMA SGP.02, section 2.2.5.1)   |
+-----------+-------------------------------------------------------+
| 112       | Token key (RSA public or DES, also used with `SCP02`) |
+-----------+-------------------------------------------------------+
| 113       | Receipt key (DES)                                     |
+-----------+-------------------------------------------------------+
| 115       | DAP verifiation key (RS public or DES)                |
+-----------+-------------------------------------------------------+
| 116       | reserved for CASD                                     |
+-----------+-------------------------------------------------------+
| 117       | 16-byte DES key for Ciphered Load File Data Block     |
+-----------+-------------------------------------------------------+
| 255       | reserved for ISD with SCP02 without SCP80 support     |
+-----------+-------------------------------------------------------+

With that we can now understand that in the first example, the first and the last keyset is intended to be used with
`SCP02` and that the second and the third keyset is intended to be used with `SCP80` (OTA SMS). In the second example we
can see that the first keyset is intended to be used with `SCP03`, wheres the second should be usable with `SCP81`.


Key Identifier
--------------

Each keyset consists of a number of keys, where each key has a different Key Identifier. The Key Identifier is usually
an incrementing number that starts counting at 1. The Key Identifier is used to distinguish the keys within the keyset.
The exact number of keys and their attributes depends on the secure channel protocol for which the keyset is intended
for. Each secure channel protocol may have its specific requirements on how many keys of which which type, length or
Key Identifier have to be present.

However, almost all of the classic secure channel protocols (including  `SCP02`, `SCP03` and `SCP81`) make use of the
following three-key scheme:

+----------------+---------+---------------------------------------+
| Key Identifier | Keyname | Purpose                               |
+================+=========+=======================================+
| 1              | ENC/KIC | encryption/decryption                 |
+----------------+---------+---------------------------------------+
| 2              | MAC/KID | cryptographic checksumming/signing    |
+----------------+---------+---------------------------------------+
| 3              | DEK/KIK | encryption/decryption of key material |
+----------------+---------+---------------------------------------+

In this case, all three keys share the same length and are used with the same algorithm. The key length is often used
to implicitly select sub-types of an algorithm. (e.g. a 16 byte key of type `aes` is associated with `AES128`, where a 32
byte key would be associated with `AES256`).

The second example shows that different schemes are possible. The `SCP80` keyset from the second example uses a scheme
that works with two keys:

+----------------+---------+---------------------------------------+
| Key Identifier | Keyname | Purpose                               |
+================+=========+=======================================+
| 1              | TLS-PSK | pre-shared key used for TLS           |
+----------------+---------+---------------------------------------+
| 2              | DEK/KIK | encryption/decryption of key material |
+----------------+---------+---------------------------------------+

It should also be noted that the order in which keysets and keys appear is an implementation detail of the UICC/eUICC
O/S. The order has no influence on how a keyset is interpreted. Only the Key Version Number (KVN) and the Key Identifier
matter.


Rotating a keyset
~~~~~~~~~~~~~~~~~

Rotating keys is one of the most basic tasks one might want to perform on an UICC/eUICC before using it productively. In
the following example we will illustrate how key rotation can be done. When rotating keys, only the key itself may
change. For example it is not possible to change the key length or the algorithm used (see also GlobalPlatform Card
Specification, section 11.8.2.3.3). Any key of the current Security Domain can be rotated, this also includes the key
that was used to establish the secure channel.

In the following example we assume that the Security Domain is selected and a secure channel is already established. We
intend to rotate the keyset with KVN 112. Since this keyset uses triple DES keys with a key length of 16, we must
replace it with a keyset with keys of the same nature.

The new keyset shall look like this:

+----------------+---------+----------------------------------+
| Key Identifier | Keyname | Keyvalue                         |
+================+=========+==================================+
| 1              | ENC/KIC | 542C37A6043679F2F9F71116418B1CD5 |
+----------------+---------+----------------------------------+
| 2              | MAC/KID | 34F11BAC8E5390B57F4E601372339E3C |
+----------------+---------+----------------------------------+
| 3              | DEK/KIK | 5524F4BECFE96FB63FC29D6BAAC6058B |
+----------------+---------+----------------------------------+

When passing the keys to the `put_key` commandline, we set the Key Identifier of the first key using the `--key-id`
parameter. This Key Identifier will be valid for the first key (KIC) we pass. For all consecutive keys, the Key
Identifier will be incremented automatically (see also GlobalPlatform Card Specification, section 11.8.2.2). To Ensure
that the new KIC, KID and KIK keys get the correct Key Identifiers, it is crucial to maintain order when passing the
keys in the `--key-data` arguments. It is also important that each `--key-data` argument is preceded by a `--key-type`
argument that sets the algorithm correctly (`des` in this case).

Finally we have to target the keyset we want to rotate by its KVN. The `--old-key-version-nr` argument is set to 112
as this is identifies the keyset we want to rotate. The `--key-version-nr` is also set to 112 as we do not want to the
KVN to be changed in this example. Changing the KVN while rotating a keyset is possible. In case the KVN has to change
for some reason, the new KVN must be selected carefully to keep the key usable with the associated Secure Channel
Protocol.

The commandline that matches the keyset we had laid out above looks like this:
::

   pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> put_key --key-id 1 --key-type des --key-data 542C37A6043679F2F9F71116418B1CD5 --key-type des --key-data 34F11BAC8E5390B57F4E601372339E3C --key-type des --key-data 5524F4BECFE96FB63FC29D6BAAC6058B --old-key-version-nr 112 --key-version-nr 112

After executing this put_key commandline, the keyset identified by KVN 122 is equipped with new keys. We can use
`get_data key_information` to inspect the currently installed keysets. The output should appear unchanged as
we only swapped out the keys. All other parameters, identifiers etc. should remain constant.

.. warning:: It is technically possible to rotate a keyset in a `non atomic` way using one `put_key` commandline for
	     each key. However, in case the targeted keyset is the one used to establish the current secure channel,
	     this method should not be used since, depending on the UICC/eUICC model, half-written key material may
	     interrupt the current secure channel.


Removing a keyset
~~~~~~~~~~~~~~~~~

In some cases it is necessary to remove a keyset entirely. This can be done with the `delete_key` command. Here it is
important to understand that `delete_key` only removes one specific key from a specific keyset. This means that you
need to run a separate `delete_key` command for each key inside a keyset.

In the following example we assume that the Security Domain is selected and a secure channel is already established. We
intend to remove the keyset with KVN 112. This keyset consists of three keys.

::

   pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> delete_key --key-ver 112 --key-id 1
   pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> delete_key --key-ver 112 --key-id 2
   pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> delete_key --key-ver 112 --key-id 3

To verify that the keyset has been deleted properly, we can use the `get_data key_information` command to inspect the
current status of the installed keysets. We should see that the key with KVN 112 is no longer present.


Adding a keyset
~~~~~~~~~~~~~~~

In the following we will discuss how to add an entirely new keyset. The procedure is almost identical with the key
rotation procedure we have already discussed and it is assumed that all details about the key rotation are understood.
In this section we will go into more detail and and illustrate how to provision new 3DES, `AES128` and `AES256` keysets.

It is important to keep in mind that storage space on smartcard is a precious resource. In many cases the amount of
keysets that a Security Domain can store is limited. In some situations you may be forced to sacrifice one of your
existing keysets in favor of a new keyset.

The main difference between key rotation and the adding of new keys is that we do not simply replace an existing key.
Instead an entirely new key is programmed into the Security Domain. Therefore the `put_key` commandline will have no
`--old-key-version-nr` parameter. From the commandline perspective, this is already the only visible difference from a
commandline that simply rotates a keyset. Since we are writing an entirely new keyset, we are free to chose the
algorithm and the key length within the parameter range permitted by the targeted secure channel protocol. Otherwise
the same rules apply.

For reference, it should be mentioned that it is also possible to add or rotate keyset using multiple `put_key`
commandlines. In this case one `put_key` commandline for each key is used. Each commandline will specify `--key-id` and
`--key-version-nr` and one `--key-type` and `--key-data` tuple. However, when rotating or adding a keyset step-by-step,
the whole process happens in a `non-atomic` way, which is less reliable. Therefore we will favor the `atomic method`

In the following examples we assume that the Security Domain is selected and a secure channel is already established.


Example: `3DES` key for `SCP02`
-------------------------------

Let's assume we want to provision a new 3DES keyset that we can use for SCP02. The keyset shall look like this:

+----------------+---------+----------------------------------+
| Key Identifier | Keyname | Keyvalue                         |
+================+=========+==================================+
| 1              | ENC/KIC | 542C37A6043679F2F9F71116418B1CD5 |
+----------------+---------+----------------------------------+
| 2              | MAC/KID | 34F11BAC8E5390B57F4E601372339E3C |
+----------------+---------+----------------------------------+
| 3              | DEK/KIK | 5524F4BECFE96FB63FC29D6BAAC6058B |
+----------------+---------+----------------------------------+

The keyset shall be a associated with the KVN 46. We have made sure before that KVN 46 is still unused and that this
KVN number is actually suitable for SCP02 keys. As we are using 3DES, it is obvious that we have to pass 3 keys with 16
byte length.

To program the key, we may use the following commandline. As we can see, this commandline is almost the exact same as
the one from the key rotation example where we were rotating a 3DES key. The only difference is that we didn't specify
an old KVN number and that we have chosen a different KVN.

::

   pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> put_key --key-id 1 --key-type des --key-data 542C37A6043679F2F9F71116418B1CD5 --key-type des --key-data 34F11BAC8E5390B57F4E601372339E3C --key-type des --key-data 5524F4BECFE96FB63FC29D6BAAC6058B --key-version-nr 46

In case of success, the keyset should appear in the `key_information` among the other keysets that are already present.

::

    pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> get_data key_information
    {
        "key_information": [
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 46,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 46,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 3,
                    "key_version_number": 46,
                    "key_types": [
                        {
                            "type": "des",
                            "length": 16
                        }
                    ]
                }
            },
            ...
        ]
    }


Example: `AES128` key for `SCP80`
---------------------------------

In this example we intend to provision a new `AES128` keyset that we can use with SCP80 (OTA SMS). The keyset shall look
like this:

+----------------+---------+----------------------------------+
| Key Identifier | Keyname | Keyvalue                         |
+================+=========+==================================+
| 1              | ENC/KIC | 542C37A6043679F2F9F71116418B1CD5 |
+----------------+---------+----------------------------------+
| 2              | MAC/KID | 34F11BAC8E5390B57F4E601372339E3C |
+----------------+---------+----------------------------------+
| 3              | DEK/KIK | 5524F4BECFE96FB63FC29D6BAAC6058B |
+----------------+---------+----------------------------------+

In addition to that, we want to associate this key with KVN 3. We have inspected the currently installed keysets before
and made sure that KVN 3 is still unused. We are also aware that for SCP80 we may only use KVN values from 1 to 15.

For `AES128`, we specify the algorithm using the `--key-type aes` parameter. The selection between `AES128` and `AES256` is
done implicitly using the key length. Since we want to use `AES128` in this case, all three keys have a length of 16 byte.

::

   pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> put_key --key-id 1 --key-type aes --key-data 542C37A6043679F2F9F71116418B1CD5 --key-type aes --key-data 34F11BAC8E5390B57F4E601372339E3C --key-type aes --key-data 5524F4BECFE96FB63FC29D6BAAC6058B --key-version-nr 3

In case of success, the keyset should appear in the `key_information` among the other keysets that are already present.

::

    pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> get_data key_information
    {
        "key_information": [
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 3,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 3,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 3,
                    "key_version_number": 3,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 16
                        }
                    ]
                }
            },
            ...
        ]
    }


Example: `AES256` key for `SCP03`
---------------------------------

Let's assume we want to provision a new `AES256` keyset that we can use for SCP03. The keyset shall look like this:

+----------------+---------+------------------------------------------------------------------+
| Key Identifier | Keyname | Keyvalue                                                         |
+================+=========+==================================================================+
| 1              | ENC/KIC | 542C37A6043679F2F9F71116418B1CD5542C37A6043679F2F9F71116418B1CD5 |
+----------------+---------+------------------------------------------------------------------+
| 2              | MAC/KID | 34F11BAC8E5390B57F4E601372339E3C34F11BAC8E5390B57F4E601372339E3C |
+----------------+---------+------------------------------------------------------------------+
| 3              | DEK/KIK | 5524F4BECFE96FB63FC29D6BAAC6058B5524F4BECFE96FB63FC29D6BAAC6058B |
+----------------+---------+------------------------------------------------------------------+

In addition to that, we assume that we want to associate this key with KVN 51. This KVN number falls in the range of
48 - 63 and is therefore suitable for a key that shall be usable with SCP03. We also made sure before that KVN 51 is
still unused.

With that we can go ahead and make up the following commandline:
::

   pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> put_key --key-id 1 --key-type aes --key-data 542C37A6043679F2F9F71116418B1CD5542C37A6043679F2F9F71116418B1CD5 --key-type aes --key-data 34F11BAC8E5390B57F4E601372339E3C34F11BAC8E5390B57F4E601372339E3C --key-type aes --key-data 5524F4BECFE96FB63FC29D6BAAC6058B5524F4BECFE96FB63FC29D6BAAC6058B --key-version-nr 51

In case of success, we should see the keyset in the `key_information`

::

    pySIM-shell (SCP02[03]:00:MF/ADF.ISD)> get_data key_information
    {
        "key_information": [
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 51,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 32
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 51,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 32
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 3,
                    "key_version_number": 51,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 32
                        }
                    ]
                }
            },
            ...
        ]
    }


Example: `AES128` key for `SCP81`
---------------------------------

In this example we will show how to provision a new `AES128` keyset for `SCP81`. We will provision this keyset under
KVN 64. The keyset we intend to apply shall look like this:

+----------------+---------+----------------------------------+
| Key Identifier | Keyname | Keyvalue                         |
+================+=========+==================================+
| 1              | TLS-PSK | 000102030405060708090a0b0c0d0e0f |
+----------------+---------+----------------------------------+
| 2              | DEK/KIK | 000102030405060708090a0b0c0d0e0f |
+----------------+---------+----------------------------------+

With that we can put together the following command line:

::

    put_key --key-id 1 --key-type tls_psk --key-data 000102030405060708090a0b0c0d0e0f --key-type aes --key-data 000102030405060708090a0b0c0d0e0f --key-version-nr 64

In case of success, the keyset should appear in the `key_information` as follows:

::

    pySIM-shell (SCP03[03]:00:MF/ADF.ISD-R)> get_data key_information
    {
        "key_information": [
            ...,
            {
                "key_information_data": {
                    "key_identifier": 2,
                    "key_version_number": 64,
                    "key_types": [
                        {
                            "type": "aes",
                            "length": 16
                        }
                    ]
                }
            },
            {
                "key_information_data": {
                    "key_identifier": 1,
                    "key_version_number": 64,
                    "key_types": [
                        {
                            "type": "tls_psk",
                            "length": 16
                        }
                    ]
                }
            }
        ]
    }
