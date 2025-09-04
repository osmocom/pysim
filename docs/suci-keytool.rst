suci-keytool
============

Subscriber concealment is an important feature of the 5G SA architecture: It avoids the many privacy
issues associated with having a permanent identifier (SUPI, traditionally the IMSI) transmitted in plain text
over the air interface.  Using SUCI solves this issue not just for the air interface; it even ensures the SUPI/IMSI
is not known to the visited network (VPLMN) at all.

In principle, the SUCI mechanism works by encrypting the SUPI by asymmetric (public key) cryptography:
Only the HPLMN is in possession of the private key and hence can decrypt the SUCI to the SUPI, while
each subscriber has the public key in order to encrypt their SUPI into the SUCI.  In reality, the
details are more complex, as there are ephemeral keys and cryptographic MAC involved.

In any case, in order to operate a SUCI-enabled 5G SA network, you will have to

#. generate a ECC key pair of public + private key
#. deploy the public key on your USIMs
#. deploy the private key on your 5GC, specifically the UDM function

pysim contains (in its `contrib` directory) a small utility program that can make it easy to generate
such keys: `suci-keytool.py`

Generating keys
~~~~~~~~~~~~~~~

Example: Generating a *secp256r1* ECC public key pair and storing it to `/tmp/suci.key`:
::

        $ ./contrib/suci-keytool.py --key-file /tmp/suci.key generate-key --curve secp256r1

Dumping public keys
~~~~~~~~~~~~~~~~~~~

In order to store the key to SIM cards as part of `ADF.USIM/DF.5GS/EF.SUCI_Calc_Info`, you will need
a hexadecimal representation of the public key.  You can achieve that using the `dump-pub-key` operation
of suci-keytool:

Example: Dumping the public key part from a previously generated key file:
::

        $ ./contrib/suci-keytool.py --key-file /tmp/suci.key dump-pub-key
        0473152f32523725f5175d255da2bd909de97b1d06449a9277bc629fe42112f8643e6b69aa6dce6c86714ccbe6f2e0f4f4898d102e2b3f0c18ce26626f052539bb

If you want the point-compressed representation, you can use the `--compressed` option:
::

        $ ./contrib/suci-keytool.py --key-file /tmp/suci.key dump-pub-key --compressed
        0373152f32523725f5175d255da2bd909de97b1d06449a9277bc629fe42112f864



suci-keytool syntax
~~~~~~~~~~~~~~~~~~~

.. argparse::
   :module: contrib.suci-keytool
   :func: arg_parser
   :prog: contrib/suci-keytool.py
